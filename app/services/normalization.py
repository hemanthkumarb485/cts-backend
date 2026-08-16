"""
normalization.py — Maps raw parser dicts to CanonicalFinding.
Strips INFO/Informational/Log/N/A severity findings (not vulnerabilities).
Handles CVSS v2.0 vs v3.1 differences with normalized severity.
"""
from __future__ import annotations
import uuid, re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from app.schemas.canonical import (
    CanonicalFinding, AssetSchema, CVSSSchema,
    HTTPRequestSchema, HTTPResponseSchema,
    SourceTool, SourceFormat, NormalizedSeverity,
    DataCompleteness, DeduplicationSchema,
)

# ─── Severity Maps ─────────────────────────────────────────────────────────────
_SEV_MAP = {
    "critical": NormalizedSeverity.CRITICAL, "high": NormalizedSeverity.HIGH,
    "medium": NormalizedSeverity.MEDIUM, "moderate": NormalizedSeverity.MEDIUM,
    "low": NormalizedSeverity.LOW, "informational": NormalizedSeverity.INFORMATIONAL,
    "info": NormalizedSeverity.INFORMATIONAL, "log": NormalizedSeverity.INFORMATIONAL,
    "false positive": NormalizedSeverity.INFORMATIONAL, "unknown": NormalizedSeverity.UNKNOWN,
}
_SKIP = {"informational", "info", "log", "false positive", "na", "n/a", "none", ""}
_ZAP_RISK_RE = re.compile(r"(critical|high|medium|low|informational|info)", re.IGNORECASE)
_V2 = [(0.0, 3.9, NormalizedSeverity.LOW), (4.0, 6.9, NormalizedSeverity.MEDIUM), (7.0, 10.0, NormalizedSeverity.HIGH)]
_V3 = [(0.1, 3.9, NormalizedSeverity.LOW), (4.0, 6.9, NormalizedSeverity.MEDIUM),
       (7.0, 8.9, NormalizedSeverity.HIGH), (9.0, 10.0, NormalizedSeverity.CRITICAL)]


def _sev(raw: str, score: Optional[float] = None, ver: Optional[str] = None) -> NormalizedSeverity:
    raw_l = (raw or "").lower().strip()
    m = _ZAP_RISK_RE.search(raw_l)
    if m: raw_l = m.group(1).lower()
    mapped = _SEV_MAP.get(raw_l, NormalizedSeverity.UNKNOWN)
    if mapped == NormalizedSeverity.UNKNOWN and score is not None:
        thresholds = _V2 if (ver or "").startswith("2") else _V3
        for lo, hi, s in thresholds:
            if lo <= score <= hi: return s
    return mapped


def _skip(raw_sev: str) -> bool:
    return (raw_sev or "").lower().strip() in _SKIP


def _cve(c: str) -> Optional[str]:
    c = (c or "").strip().upper()
    return c if re.match(r"CVE-\d{4}-\d+", c) else None


def _cwe(c: str) -> Optional[str]:
    c = (c or "").strip()
    if not c or c == "0": return None
    if c.isdigit(): return f"CWE-{c}"
    if re.match(r"CWE-\d+", c, re.IGNORECASE): return c.upper()
    return None


def _refs(raw_str: str) -> List[str]:
    return [r.strip() for r in re.split(r"[\n,]", raw_str or "") if r.strip()]


def _dedup(finding: CanonicalFinding, tool: str) -> DeduplicationSchema:
    return DeduplicationSchema(
        dedup_key=finding.compute_dedup_key(),
        source_scanners=[tool], corroboration_count=1,
    )


def normalize_zap(raw: Dict[str, Any]) -> Optional[CanonicalFinding]:
    risk_desc = raw.get("risk_desc", "")
    raw_sev = risk_desc.split()[0] if risk_desc else raw.get("level", "")
    if _skip(raw_sev): return None
    severity = _sev(raw_sev)
    host = raw.get("host", "")
    uri = raw.get("uri", "")
    port_raw = raw.get("port", "")
    try: port = int(port_raw) if port_raw else None
    except ValueError: port = None
    url_path = urlparse(uri).path if uri else ""
    src_fmt = {"sarif": SourceFormat.SARIF, "xml": SourceFormat.XML}.get(raw.get("_format", ""), SourceFormat.JSON)
    f = CanonicalFinding(
        finding_id=str(uuid.uuid4()), raw_finding_id=raw.get("rule_id", ""),
        source_tool=SourceTool.ZAP, source_format=src_fmt,
        vulnerability_name=raw.get("name", "Unknown"),
        description=raw.get("description", raw.get("message", "")),
        solution=raw.get("solution", ""), references=_refs(raw.get("references", "")),
        raw_severity=raw_sev, severity=severity, confidence=raw.get("confidence", ""),
        cwe_id=_cwe(raw.get("cwe_id", "")), wasc_id=raw.get("wasc_id") or None,
        asset=AssetSchema(hostname=host, domain=host, port=port, url=uri,
                          path=url_path, protocol=raw.get("protocol", "")),
        http_method=raw.get("method", raw.get("req_method", "")),
        parameter=raw.get("param", ""), attack=raw.get("attack", ""),
        evidence=raw.get("evidence", raw.get("snippet", "")),
        http_request=HTTPRequestSchema(
            method=raw.get("req_method", ""), target=raw.get("req_target", ""),
            protocol=raw.get("req_protocol", ""), version=raw.get("req_version", ""),
            headers=raw.get("req_headers") or None, body=raw.get("req_body") or None,
        ) if raw.get("req_method") else None,
        http_response=HTTPResponseSchema(
            status_code=raw.get("res_status"), reason=raw.get("res_reason", ""),
            headers=raw.get("res_headers") or None, body=raw.get("res_body") or None,
        ) if raw.get("res_status") else None,
        data_completeness=DataCompleteness.PARTIAL if not raw.get("cwe_id") else DataCompleteness.FULL,
    )
    f.deduplication = _dedup(f, "zap")
    return f


def normalize_nuclei(raw: Dict[str, Any]) -> Optional[CanonicalFinding]:
    raw_sev = raw.get("severity", "")
    if _skip(raw_sev): return None
    cve_ids = [c for c in (raw.get("cve_ids") or []) if _cve(c)]
    cve_primary = cve_ids[0] if cve_ids else None
    cwe_primary = _cwe((raw.get("cwe_ids") or [""])[0])
    try: cvss_score = float(raw.get("cvss_score")) if raw.get("cvss_score") else None
    except (ValueError, TypeError): cvss_score = None
    severity = _sev(raw_sev, cvss_score, "3.1")
    host = raw.get("host", "")
    matched_at = raw.get("matched_at", "")
    parsed = urlparse(matched_at or host)
    refs = raw.get("references", [])
    if isinstance(refs, str): refs = [refs]
    port = raw.get("port") or parsed.port
    f = CanonicalFinding(
        finding_id=str(uuid.uuid4()), raw_finding_id=raw.get("raw_finding_id", ""),
        source_tool=SourceTool.NUCLEI, source_format=SourceFormat.JSONL,
        scan_date=raw.get("timestamp", ""),
        vulnerability_name=raw.get("name", "Unknown"),
        description=raw.get("description", ""), impact=raw.get("impact", ""),
        solution=raw.get("solution", ""), references=refs,
        raw_severity=raw_sev, severity=severity,
        cve_id=cve_primary, cve_ids=cve_ids if len(cve_ids) > 1 else None,
        cwe_id=cwe_primary,
        cvss=CVSSSchema(base_score=cvss_score, vector=raw.get("cvss_vector"),
                        version="3.1", severity_normalized=severity) if cvss_score else None,
        tags=raw.get("tags") or None, matcher_name=raw.get("matcher_name") or None,
        finding_type=raw.get("finding_type") or None,
        evidence=", ".join(raw.get("extracted_results") or []) or None,
        asset=AssetSchema(hostname=host, domain=parsed.netloc or host,
                          port=int(port) if port else None, url=matched_at,
                          path=parsed.path, ip=raw.get("ip") or None,
                          protocol=parsed.scheme or None),
        data_completeness=DataCompleteness.NO_CVE if not cve_primary else DataCompleteness.FULL,
    )
    f.deduplication = _dedup(f, "nuclei")
    return f


def normalize_openvas(raw: Dict[str, Any]) -> Optional[CanonicalFinding]:
    raw_sev = raw.get("threat", "")
    if _skip(raw_sev): return None
    try: cvss_score = float(raw.get("cvss_score")) if raw.get("cvss_score") else None
    except (ValueError, TypeError): cvss_score = None
    severity = _sev(raw_sev, cvss_score, "2.0")
    cve_ids = [c for c in (raw.get("cve_ids") or []) if _cve(c)]
    cve_primary = cve_ids[0] if cve_ids else None
    cwe_primary = _cwe((raw.get("cwe_ids") or [""])[0])
    f = CanonicalFinding(
        finding_id=str(uuid.uuid4()), raw_finding_id=raw.get("nvt_oid", ""),
        nvt_oid=raw.get("nvt_oid") or None,
        source_tool=SourceTool.OPENVAS, source_format=SourceFormat.XML,
        scan_date=raw.get("scan_date", ""),
        vulnerability_name=raw.get("name", "Unknown"),
        description=raw.get("description", ""), solution=raw.get("solution", ""),
        references=raw.get("references") or None,
        raw_severity=raw_sev, severity=severity,
        cve_id=cve_primary, cve_ids=cve_ids if len(cve_ids) > 1 else None,
        cwe_id=cwe_primary,
        cvss=CVSSSchema(base_score=cvss_score, vector=raw.get("cvss_vector"),
                        version="2.0", severity_normalized=severity) if cvss_score else None,
        asset=AssetSchema(ip=raw.get("host_ip", ""), hostname=raw.get("hostname", ""),
                          port=raw.get("port"), protocol=raw.get("protocol", "")),
        nvt_family=raw.get("nvt_family") or None, qod=raw.get("qod"),
        solution_type=raw.get("solution_type") or None,
        data_completeness=DataCompleteness.NO_CVE if not cve_primary else DataCompleteness.FULL,
    )
    f.deduplication = _dedup(f, "openvas")
    return f


def normalize_nmap(raw: Dict[str, Any]) -> Optional[CanonicalFinding]:
    cve_ids = [c for c in (raw.get("cve_ids") or []) if _cve(c)]
    cve_primary = cve_ids[0] if cve_ids else None
    try: cvss_score = float(raw.get("cvss_score")) if raw.get("cvss_score") else None
    except (ValueError, TypeError): cvss_score = None
    severity = _sev("", cvss_score, "2.0") if (cve_primary and cvss_score) else NormalizedSeverity.LOW
    src_fmt = {"nmap_xml": SourceFormat.XML, "nmap_normal": SourceFormat.NORMAL_TEXT}.get(
        raw.get("_format", ""), SourceFormat.GREPABLE)
    f = CanonicalFinding(
        finding_id=str(uuid.uuid4()), raw_finding_id=raw.get("raw_finding_id", ""),
        source_tool=SourceTool.NMAP, source_format=src_fmt,
        scan_date=raw.get("scan_date", ""),
        vulnerability_name=raw.get("name", "Open Port"),
        description=raw.get("description", ""),
        raw_severity=severity.value, severity=severity,
        cve_id=cve_primary, cve_ids=cve_ids if len(cve_ids) > 1 else None,
        cvss=CVSSSchema(base_score=cvss_score, version="2.0",
                        severity_normalized=severity) if cvss_score else None,
        asset=AssetSchema(ip=raw.get("host_ip", ""), hostname=raw.get("hostname", ""),
                          port=raw.get("port"), protocol=raw.get("protocol", "tcp"),
                          service_name=raw.get("service_name", ""),
                          service_version=raw.get("service_version", "")),
        port_state=raw.get("port_state", ""),
        service_method=raw.get("service_method") or None,
        tags=["open-port"], finding_type="network",
        data_completeness=DataCompleteness.NO_CVE if not cve_primary else DataCompleteness.FULL,
    )
    f.deduplication = _dedup(f, "nmap")
    return f


def normalize_findings(tool: str, raw_records: List[Dict[str, Any]]) -> List[CanonicalFinding]:
    """Normalize raw parser records. Skips INFO/Log/NA. Returns CanonicalFindings."""
    fn = {"zap": normalize_zap, "nuclei": normalize_nuclei,
          "openvas": normalize_openvas, "nmap": normalize_nmap}.get(tool.lower())
    if not fn: raise ValueError(f"Unknown tool: {tool}")
    results = []
    for raw in raw_records:
        try:
            finding = fn(raw)
            if finding: results.append(finding)
        except Exception:
            pass
    return results


