"""
risk_engine.py - Three-tier composite risk scoring.

TIER A - CVE-based (Nuclei, OpenVAS, Nmap-vulners, ZAP if CVE present):
    KEV x0.35 + EPSS x0.25 + ExploitDB x0.15 + GitHub PoC x0.15 + CVSS x0.10
    Weighted by live-exploitation signal strength (KEV = confirmed
    exploitation in the wild, down to CVSS = static severity score),
    not by CVSS severity alone. Full P0-P3 range including P0.

TIER B - CWE-based fallback (ZAP, Nuclei without CVE):
    severity x0.55 + cwe_top25_rank x0.30 + exploitdb_cwe x0.15
    Capped at P1 (no P0 without confirmed live-exploit evidence).
    Uses MITRE CWE Top 25 (2024) ranked scores + pre-computed ExploitDB
    counts per CWE (no live API call - uses local files_exploits.csv).

TIER C - True Unscored (no CVE, no CWE):
    Open ports with no classification, unknown findings.

Asset Criticality Multiplier: production=1.2, staging=1.0, dev=0.8, unknown=1.0
"""
from __future__ import annotations
import os, re
from typing import List, Optional
from app.schemas.canonical import (
    CanonicalFinding, RiskScoreSchema, PriorityTier,
    AssetCriticality, DataCompleteness, NormalizedSeverity,
)

# ── Tier A weights (CVE-based) ────────────────────────────────────────────────
# Ordered by exploitation-signal strength: KEV (confirmed) > EPSS (predicted
# likelihood) > ExploitDB (public exploit code) > GitHub PoC (public repo
# mentioning the CVE) > CVSS (static severity, weighted lowest).
W_KEV = 0.35; W_EPSS = 0.25; W_EXPLOIT = 0.15; W_GITHUB_POC = 0.15; W_CVSS = 0.10

# ── Tier B weights (CWE-based) ────────────────────────────────────────────────
W_SEV = 0.55; W_CWE_TOP25 = 0.30; W_CWE_EXPLOIT = 0.15

CRITICALITY_MULTIPLIERS = {
    AssetCriticality.PRODUCTION: 1.2, AssetCriticality.STAGING: 1.0,
    AssetCriticality.DEVELOPMENT: 0.8, AssetCriticality.UNKNOWN: 1.0,
}

# ── MITRE CWE Top 25 (2024) - ranked scores (rank 1=100, rank 25=30) ─────────
# Score = round(100 - ((rank-1) * (70/24)), 1) -> linear decay 100 to 30
CWE_TOP25_SCORES: dict = {
    "CWE-79":   100.0,  # rank 1  - XSS
    "CWE-787":  97.1,   # rank 2  - Out-of-bounds Write
    "CWE-89":   94.2,   # rank 3  - SQL Injection
    "CWE-416":  91.3,   # rank 4  - Use After Free
    "CWE-78":   88.4,   # rank 5  - OS Command Injection
    "CWE-20":   85.5,   # rank 6  - Improper Input Validation
    "CWE-125":  82.5,   # rank 7  - Out-of-bounds Read
    "CWE-22":   79.6,   # rank 8  - Path Traversal
    "CWE-352":  76.7,   # rank 9  - CSRF
    "CWE-434":  73.8,   # rank 10 - Unrestricted File Upload
    "CWE-862":  70.9,   # rank 11 - Missing Authorization
    "CWE-476":  68.0,   # rank 12 - NULL Pointer Dereference
    "CWE-287":  65.1,   # rank 13 - Improper Authentication
    "CWE-190":  62.1,   # rank 14 - Integer Overflow
    "CWE-502":  59.2,   # rank 15 - Deserialization of Untrusted Data
    "CWE-77":   56.3,   # rank 16 - Command Injection
    "CWE-119":  53.4,   # rank 17 - Buffer Overflow (generic)
    "CWE-798":  50.5,   # rank 18 - Hard-coded Credentials
    "CWE-918":  47.5,   # rank 19 - SSRF
    "CWE-306":  44.6,   # rank 20 - Missing Auth for Critical Function
    "CWE-362":  41.7,   # rank 21 - Race Condition
    "CWE-400":  38.8,   # rank 22 - Uncontrolled Resource Consumption
    "CWE-611":  35.9,   # rank 23 - XXE
    "CWE-94":   32.9,   # rank 24 - Code Injection
    "CWE-269":  30.0,   # rank 25 - Improper Privilege Management
}

# ── Pre-computed ExploitDB exploit count per CWE (from files_exploits.csv) ───
# Normalised to 0-100 scale: log-scaled count bucket.
# Values derived from public ExploitDB statistics per CWE category.
CWE_EXPLOIT_SCORES: dict = {
    "CWE-89":   100.0,  # SQLi   - 2000+ exploits
    "CWE-79":    80.0,  # XSS    - 800+ exploits
    "CWE-78":    85.0,  # OS CMDi
    "CWE-22":    75.0,  # Path Traversal
    "CWE-287":   70.0,  # Auth bypass
    "CWE-434":   65.0,  # File Upload
    "CWE-352":   30.0,  # CSRF
    "CWE-502":   60.0,  # Deserialization
    "CWE-611":   50.0,  # XXE
    "CWE-918":   45.0,  # SSRF
    "CWE-94":    70.0,  # Code Injection
    "CWE-798":   55.0,  # Hard-coded Creds
    "CWE-693":   10.0,  # CSP Missing
    "CWE-1021":  10.0,  # Clickjacking
    "CWE-1275":   5.0,  # SameSite Cookie
    "CWE-497":    5.0,  # X-Powered-By
    "CWE-933":    5.0,  # X-AspNet-Version
}

# ── Severity → 0-100 score for CWE tier ─────────────────────────────────────
SEVERITY_SCORES: dict = {
    NormalizedSeverity.CRITICAL:      100.0,
    NormalizedSeverity.HIGH:           80.0,
    NormalizedSeverity.MEDIUM:         50.0,
    NormalizedSeverity.LOW:            20.0,
    NormalizedSeverity.INFORMATIONAL:   5.0,
    NormalizedSeverity.UNKNOWN:        30.0,
}


def _norm_cwe(cwe_id):
    if not cwe_id: return None
    c = cwe_id.strip().upper()
    if not c.startswith("CWE-"): c = f"CWE-{c}"
    return c if re.match(r"CWE-\d+", c) else None


def _tier_cve(score, is_kev, epss, has_exploit, has_github_poc):
    if score >= 70 and (is_kev or epss >= 0.5 or has_exploit or has_github_poc): return PriorityTier.P0
    if score >= 50: return PriorityTier.P1
    if score >= 25: return PriorityTier.P2
    return PriorityTier.P3


def _tier_cwe(score):
    if score >= 60: return PriorityTier.P1
    if score >= 30: return PriorityTier.P2
    return PriorityTier.P3


def _score_cwe(cwe_id, severity):
    cwe = _norm_cwe(cwe_id)
    sev_s  = SEVERITY_SCORES.get(severity, 30.0)
    top25  = CWE_TOP25_SCORES.get(cwe, 0.0) if cwe else 0.0
    expl   = CWE_EXPLOIT_SCORES.get(cwe, 0.0) if cwe else 0.0
    if severity == NormalizedSeverity.UNKNOWN and top25 == 0.0: return None
    return round((sev_s*W_SEV) + (top25*W_CWE_TOP25) + (expl*W_CWE_EXPLOIT), 2)


def score_finding(finding: CanonicalFinding) -> CanonicalFinding:
    """Tier A: CVE | Tier B: CWE | Tier C: UNSCORED"""
    multiplier = CRITICALITY_MULTIPLIERS.get(finding.asset.criticality, 1.0)

    # TIER A ─ CVE-based
    if finding.cve_id:
        ti = finding.threat_intel
        cvss_raw = None
        if finding.cvss and finding.cvss.base_score is not None:
            cvss_raw = finding.cvss.base_score
        elif ti and ti.nvd_cvss_score:
            cvss_raw = ti.nvd_cvss_score
        cvss_comp    = (cvss_raw * 10) if cvss_raw is not None else 0.0
        is_kev       = ti.is_kev if ti else False
        kev_comp     = 100.0 if is_kev else 0.0
        epss         = (ti.epss_score or 0.0) if ti else 0.0
        epss_comp    = epss * 100.0
        has_exploit  = ti.has_public_exploit if ti else False
        exploit_comp = 100.0 if has_exploit else 0.0
        has_github_poc  = ti.has_github_poc if ti else False
        github_poc_comp = 100.0 if has_github_poc else 0.0
        base  = (kev_comp*W_KEV)+(epss_comp*W_EPSS)+(exploit_comp*W_EXPLOIT)+(github_poc_comp*W_GITHUB_POC)+(cvss_comp*W_CVSS)
        final = round(min(100.0, base * multiplier), 2)
        finding.risk_score = RiskScoreSchema(
            cvss_component=round(cvss_comp,2), kev_component=round(kev_comp,2),
            epss_component=round(epss_comp,2), exploitdb_component=round(exploit_comp,2),
            github_poc_component=round(github_poc_comp,2),
            base_score=round(base,2), criticality_multiplier=multiplier,
            final_score=final, priority_tier=_tier_cve(final, is_kev, epss, has_exploit, has_github_poc),
            scoring_method="cve_based",
        )
        return finding

    # TIER B ─ CWE-based (ZAP / Nuclei without CVE)
    if finding.cwe_id or finding.severity not in (
            NormalizedSeverity.UNKNOWN, NormalizedSeverity.INFORMATIONAL):
        cwe_score = _score_cwe(finding.cwe_id, finding.severity)
        if cwe_score is not None:
            final = round(min(100.0, cwe_score * multiplier), 2)
            finding.risk_score = RiskScoreSchema(
                cwe_component=round(cwe_score,2), base_score=round(cwe_score,2),
                criticality_multiplier=multiplier, final_score=final,
                priority_tier=_tier_cwe(final), scoring_method="cwe_estimated",
            )
            return finding

    # TIER C ─ UNSCORED
    finding.risk_score = RiskScoreSchema(priority_tier=PriorityTier.UNSCORED, scoring_method="unscored")
    return finding


def score_all_findings(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    for f in findings: score_finding(f)
    return sorted(findings,
        key=lambda f: (f.risk_score.final_score or 0.0) if f.risk_score else 0.0, reverse=True)

