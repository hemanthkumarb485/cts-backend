"""
canonical.py — ONE unified Pydantic schema for all 4 scanners.
Web findings (ZAP/Nuclei) and Network findings (Nmap/OpenVAS) share this schema.
Fields irrelevant to a scanner are set to None.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from enum import Enum
import hashlib


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class SourceTool(str, Enum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    OPENVAS = "openvas"
    NMAP = "nmap"


class SourceFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"
    XML = "xml"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    NORMAL_TEXT = "normal_text"  # nmap -oN
    GREPABLE = "grepable"        # nmap -oG


class NormalizedSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class FindingStatus(str, Enum):
    ACTIVE = "active"
    NEEDS_REVIEW = "needs_review"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"
    CORROBORATED = "corroborated"


class PriorityTier(str, Enum):
    P0 = "P0"        # Critical
    P1 = "P1"        # High
    P2 = "P2"        # Medium
    P3 = "P3"        # Low
    UNSCORED = "UNSCORED"  # No CVE — Nmap open ports etc.


class AssetCriticality(str, Enum):
    PRODUCTION = "production"    # multiplier 1.2
    STAGING = "staging"          # multiplier 1.0
    DEVELOPMENT = "development"  # multiplier 0.8
    UNKNOWN = "unknown"          # multiplier 1.0


class DataCompleteness(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    NO_CVE = "no_cve"
    NO_ENRICHMENT = "no_enrichment"


# ─────────────────────────────────────────────
# SUB-SCHEMAS
# ─────────────────────────────────────────────

class AssetSchema(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    url: Optional[str] = None
    path: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.UNKNOWN


class CVSSSchema(BaseModel):
    base_score: Optional[float] = None
    vector: Optional[str] = None
    version: Optional[str] = None
    severity_normalized: Optional[NormalizedSeverity] = None

    @field_validator("base_score")
    @classmethod
    def clamp_score(cls, v):
        if v is not None:
            return round(max(0.0, min(10.0, v)), 1)
        return v


class HTTPRequestSchema(BaseModel):
    method: Optional[str] = None
    target: Optional[str] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None


class HTTPResponseSchema(BaseModel):
    status_code: Optional[int] = None
    reason: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None


class ThreatIntelSchema(BaseModel):
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    epss_date: Optional[str] = None
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    kev_ransomware_use: Optional[str] = None
    nvd_description: Optional[str] = None
    nvd_cvss_score: Optional[float] = None
    nvd_cvss_severity: Optional[str] = None
    has_public_exploit: bool = False
    exploit_ids: Optional[List[str]] = None
    exploit_descriptions: Optional[List[str]] = None
    enrichment_attempted: bool = False
    enrichment_errors: Optional[List[str]] = None


class RiskScoreSchema(BaseModel):
    """
    Scoring modes:
      cve_based     - CVE present: CVSS x0.40 + KEV x0.25 + EPSS x0.20 + ExploitDB x0.15
      cwe_estimated - No CVE, CWE present: severity x0.55 + Top25 x0.30 + ExploitDB-count x0.15
      unscored      - No CVE, no CWE (bare open ports etc.)
    """
    cvss_component: Optional[float] = None
    kev_component: Optional[float] = None
    epss_component: Optional[float] = None
    exploitdb_component: Optional[float] = None
    cwe_component: Optional[float] = None
    base_score: Optional[float] = None
    criticality_multiplier: float = 1.0
    final_score: Optional[float] = None
    priority_tier: PriorityTier = PriorityTier.UNSCORED
    scoring_method: Optional[str] = None


class DeduplicationSchema(BaseModel):
    dedup_key: Optional[str] = None
    dedup_method: Optional[str] = None
    duplicate_of: Optional[str] = None
    is_duplicate: bool = False
    source_scanners: List[str] = Field(default_factory=list)
    corroboration_count: int = 1


class FalsePositiveSchema(BaseModel):
    fp_rules_applied: Optional[List[str]] = None
    fp_status: FindingStatus = FindingStatus.ACTIVE
    fp_reason: Optional[str] = None
    ml_fp_probability: Optional[float] = None  # future ML placeholder


# ─────────────────────────────────────────────
# MAIN CANONICAL FINDING
# ─────────────────────────────────────────────

class CanonicalFinding(BaseModel):
    """ONE unified schema for ZAP, Nuclei, Nmap, OpenVAS."""

    # Identity
    finding_id: Optional[str] = None
    raw_finding_id: Optional[str] = None

    # Source
    source_tool: SourceTool
    source_format: SourceFormat
    scan_date: Optional[str] = None

    # Vulnerability Info
    vulnerability_name: str
    description: Optional[str] = None
    impact: Optional[str] = None
    solution: Optional[str] = None
    references: Optional[List[str]] = None

    # Identifiers
    cve_id: Optional[str] = None
    cve_ids: Optional[List[str]] = None
    cwe_id: Optional[str] = None
    wasc_id: Optional[str] = None
    nvt_oid: Optional[str] = None

    # Severity
    raw_severity: Optional[str] = None
    severity: NormalizedSeverity = NormalizedSeverity.UNKNOWN
    confidence: Optional[str] = None
    cvss: Optional[CVSSSchema] = None

    # Asset
    asset: AssetSchema

    # Web-specific (ZAP / Nuclei)
    http_method: Optional[str] = None
    parameter: Optional[str] = None
    attack: Optional[str] = None
    evidence: Optional[str] = None
    matcher_name: Optional[str] = None
    http_request: Optional[HTTPRequestSchema] = None
    http_response: Optional[HTTPResponseSchema] = None

    # Network-specific (Nmap / OpenVAS)
    port_state: Optional[str] = None
    service_method: Optional[str] = None
    nvt_family: Optional[str] = None
    qod: Optional[int] = None
    solution_type: Optional[str] = None

    # Tags & Metadata
    tags: Optional[List[str]] = None
    finding_type: Optional[str] = None
    is_systemic: bool = False
    data_completeness: DataCompleteness = DataCompleteness.FULL

    # Threat Intelligence
    threat_intel: Optional[ThreatIntelSchema] = None

    # Risk Scoring
    risk_score: Optional[RiskScoreSchema] = None

    # Deduplication
    deduplication: Optional[DeduplicationSchema] = None

    # False Positive
    false_positive: Optional[FalsePositiveSchema] = None

    # Raw preserved data
    raw_data: Optional[Dict[str, Any]] = None

    def compute_dedup_key(self) -> str:
        """
        Network (Nmap/OpenVAS): host + port + cve_id
        Web (ZAP/Nuclei): host/domain + path + cwe_id
        """
        if self.source_tool in (SourceTool.NMAP, SourceTool.OPENVAS):
            host = self.asset.ip or self.asset.hostname or ""
            port = str(self.asset.port or "")
            cve = self.cve_id or ""
            key_str = f"network|{host}|{port}|{cve}".lower()
        else:
            host = self.asset.domain or self.asset.hostname or self.asset.url or ""
            path = self.asset.path or ""
            cwe = self.cwe_id or ""
            key_str = f"web|{host}|{path}|{cwe}".lower()
        return hashlib.sha256(key_str.encode()).hexdigest()


# ─────────────────────────────────────────────
# SCAN SESSION WRAPPER
# ─────────────────────────────────────────────

class ScanSession(BaseModel):
    """Top-level pipeline response returned to frontend."""
    session_id: str
    uploaded_files: List[str] = Field(default_factory=list)
    tools_detected: List[str] = Field(default_factory=list)
    total_raw_findings: int = 0
    total_after_dedup: int = 0
    total_after_fp_filter: int = 0
    total_scored: int = 0
    total_unscored: int = 0
    findings: List[CanonicalFinding] = Field(default_factory=list)
    processing_errors: List[Dict[str, str]] = Field(default_factory=list)
    processing_time_seconds: Optional[float] = None


# ─────────────────────────────────────────────
# GITHUB INTEGRATION SCHEMAS (DB-backed)
# ─────────────────────────────────────────────

class GitHubConnectionSchema(BaseModel):
    id: Optional[int] = None
    github_user_id: int
    github_username: str
    github_email: Optional[str] = None
    access_token_encrypted: str
    token_scope: Optional[str] = None
    connected_at: Optional[str] = None


class GitHubRepositorySchema(BaseModel):
    id: Optional[int] = None
    connection_id: int
    repo_id: int
    repo_name: str
    repo_full_name: str
    is_private: bool = False
    repo_url: str
    selected_at: Optional[str] = None


class GitHubIssueSchema(BaseModel):
    id: Optional[int] = None
    connection_id: int
    repository_id: int
    finding_id: str
    issue_number: int
    issue_url: str
    issue_title: str
    status: str = "open"
    assignee: Optional[str] = None
    labels: Optional[List[str]] = None
    milestone: Optional[str] = None
    created_at: Optional[str] = None
    closed_at: Optional[str] = None


class CreateIssueRequest(BaseModel):
    finding_id: str
    finding_data: CanonicalFinding
    repo_full_name: str
    assignee: Optional[str] = None
    labels: Optional[List[str]] = Field(
        default_factory=lambda: ["security", "vulnerability"]
    )
    milestone: Optional[str] = None


class CreateIssueResponse(BaseModel):
    success: bool
    issue_number: Optional[int] = None
    issue_url: Optional[str] = None
    issue_title: Optional[str] = None
    error: Optional[str] = None
