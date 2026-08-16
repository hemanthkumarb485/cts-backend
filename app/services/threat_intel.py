"""
threat_intel.py
ROOT CAUSE OF "Stuck at 0%":
  Old code: fetch_nvd() called sequentially per CVE with timeout=20s each.
  If scan has 50 CVEs → 50×20s = 1000s blocking. THAT was the hang.

FIXED:
  - NVD calls now run in PARALLEL (ThreadPoolExecutor, max 5 workers)
  - NVD_TIMEOUT = 8s per call, NVD_MAX_CVES = 30 (hard cap)
  - EPSS_TIMEOUT = 8s (1 batch call)
  - No internet? → pipeline finishes instantly (all fallback to 0.0/None)
"""
from __future__ import annotations
import json, os, re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import requests

from app.core.config import NVD_API_KEY, NVD_API_URL, EPSS_API_URL, KEV_FILE, EXPLOITDB_FILE
from app.schemas.canonical import CanonicalFinding, ThreatIntelSchema, DataCompleteness

NVD_TIMEOUT = 8
NVD_MAX_PARALLEL = 5
NVD_MAX_CVES = 30
EPSS_TIMEOUT = 8

_kev_cache: Optional[Dict[str, dict]] = None
_exploitdb_cache = None


def _load_kev() -> Dict[str, dict]:
    global _kev_cache
    if _kev_cache is not None: return _kev_cache
    if not os.path.exists(KEV_FILE): _kev_cache = {}; return _kev_cache
    try:
        with open(KEV_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        _kev_cache = {v["cveID"].upper(): v for v in data.get("vulnerabilities", [])}
    except Exception: _kev_cache = {}
    return _kev_cache

def check_kev(cve_id): return _load_kev().get((cve_id or "").upper())

def _load_exploitdb():
    global _exploitdb_cache
    if _exploitdb_cache is not None: return _exploitdb_cache
    if not os.path.exists(EXPLOITDB_FILE): return None
    try:
        import pandas as pd
        _exploitdb_cache = pd.read_csv(EXPLOITDB_FILE, low_memory=False)
        return _exploitdb_cache
    except Exception: return None

def check_exploitdb(cve_id):
    df = _load_exploitdb()
    if df is None or not cve_id or "codes" not in df.columns: return False, []
    try:
        mask = df["codes"].astype(str).str.contains(re.escape(cve_id), na=False, case=False)
        m = df[mask][["id", "description"]].to_dict("records")
        return len(m) > 0, m
    except Exception: return False, []

def fetch_epss_batch(cve_ids):
    if not cve_ids: return {}
    try:
        r = requests.get(EPSS_API_URL, params={"cve": ",".join(cve_ids)}, timeout=EPSS_TIMEOUT)
        r.raise_for_status()
        return {d["cve"].upper(): float(d["epss"]) for d in r.json().get("data", [])}
    except Exception: return {}

def _fetch_nvd_single(cve_id):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        r = requests.get(NVD_API_URL, headers=headers, params={"cveId": cve_id}, timeout=NVD_TIMEOUT)
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns: return cve_id, None
        cve_data = vulns[0].get("cve", {})
        desc = next((d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "")
        metrics = cve_data.get("metrics", {})
        score = sev = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                e = metrics[key][0].get("cvssData", {})
                score, sev = e.get("baseScore"), e.get("baseSeverity")
                break
        return cve_id, {"description": desc, "cvss_score": score, "cvss_severity": sev}
    except Exception: return cve_id, None

def fetch_nvd_parallel(cve_ids):
    results = {cve: None for cve in cve_ids}
    capped = cve_ids[:NVD_MAX_CVES]
    if not capped: return results
    with ThreadPoolExecutor(max_workers=NVD_MAX_PARALLEL) as pool:
        futures = {pool.submit(_fetch_nvd_single, cve): cve for cve in capped}
        for future in as_completed(futures, timeout=NVD_TIMEOUT * 4):
            try:
                cid, data = future.result(timeout=NVD_TIMEOUT + 2)
                results[cid] = data
            except Exception: pass
    return results

def enrich_findings(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    unique_cves = list({f.cve_id for f in findings
                        if f.cve_id and re.match(r"CVE-\d{4}-\d+", f.cve_id or "")})
    epss_map = fetch_epss_batch(unique_cves) if unique_cves else {}
    nvd_cache = fetch_nvd_parallel(unique_cves) if unique_cves else {}

    for finding in findings:
        cve = finding.cve_id
        ti = ThreatIntelSchema(enrichment_attempted=bool(cve))
        errors = []
        if not cve:
            finding.data_completeness = DataCompleteness.NO_CVE
            finding.threat_intel = ti
            continue
        kev = check_kev(cve)
        if kev:
            ti.is_kev = True
            ti.kev_date_added = kev.get("dateAdded")
            ti.kev_due_date = kev.get("dueDate")
            ti.kev_ransomware_use = kev.get("knownRansomwareCampaignUse")
        epss_val = epss_map.get(cve.upper())
        ti.epss_score = epss_val if epss_val is not None else 0.0
        if epss_val is None: errors.append("EPSS: defaulted 0.0")
        has_exploit, exploits = check_exploitdb(cve)
        ti.has_public_exploit = has_exploit
        if has_exploit:
            ti.exploit_ids = [str(e.get("id","")) for e in exploits[:10]]
            ti.exploit_descriptions = [str(e.get("description","")) for e in exploits[:10]]
        nvd = nvd_cache.get(cve)
        if nvd:
            ti.nvd_description = nvd.get("description")
            ti.nvd_cvss_score = nvd.get("cvss_score")
            ti.nvd_cvss_severity = nvd.get("cvss_severity")
        else:
            errors.append("NVD: no data")
        if errors:
            ti.enrichment_errors = errors
            finding.data_completeness = (
                DataCompleteness.NO_ENRICHMENT if (not nvd and epss_val is None)
                else DataCompleteness.PARTIAL)
        finding.threat_intel = ti
    return findings
