"""
nuclei_parser.py — Parses ALL Nuclei output formats.
Supports: JSONL, JSON (array), SARIF JSON, Markdown.
Nuclei unique finding ID = sha256(template-id + host + matched-at).
"""
from __future__ import annotations
import json, hashlib, re
from typing import List, Dict, Any


def _nuclei_id(template_id: str, host: str, matched_at: str) -> str:
    key = f"{template_id}|{host}|{matched_at}".lower()
    return hashlib.sha256(key.encode()).hexdigest()


def _parse_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    info = rec.get("info", {})
    clf = info.get("classification", {})
    tid = rec.get("template-id", "")
    host = rec.get("host", "")
    mat = rec.get("matched-at", "")
    cve_ids = clf.get("cve-id") or []
    if isinstance(cve_ids, str): cve_ids = [cve_ids]
    cwe_ids = clf.get("cwe-id") or []
    if isinstance(cwe_ids, str): cwe_ids = [cwe_ids]
    try: port = int(str(rec.get("port", ""))) if rec.get("port") else None
    except ValueError: port = None
    return {
        "_format": "nuclei", "raw_finding_id": _nuclei_id(tid, host, mat),
        "template_id": tid, "name": info.get("name", ""),
        "severity": info.get("severity", ""), "description": info.get("description", ""),
        "impact": info.get("impact", ""), "solution": info.get("remediation", ""),
        "references": info.get("reference", []),
        "tags": list(info.get("tags", [])) if info.get("tags") else [],
        "cve_ids": cve_ids, "cwe_ids": cwe_ids,
        "cvss_vector": clf.get("cvss-metrics", ""), "cvss_score": clf.get("cvss-score"),
        "host": host, "port": port, "ip": rec.get("ip", ""),
        "matched_at": mat, "matcher_name": rec.get("matcher-name", ""),
        "extracted_results": rec.get("extracted-results", []),
        "finding_type": rec.get("type", ""), "timestamp": rec.get("timestamp", ""),
        "request": rec.get("request", ""), "response": rec.get("response", ""),
    }


def parse_nuclei_jsonl(content: str) -> List[Dict[str, Any]]:
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if not line: continue
        try: findings.append(_parse_record(json.loads(line)))
        except json.JSONDecodeError: continue
    return findings


def parse_nuclei_json(content: str) -> List[Dict[str, Any]]:
    try: data = json.loads(content)
    except json.JSONDecodeError as e: raise ValueError(f"Nuclei JSON: {e}")
    if isinstance(data, list): return [_parse_record(r) for r in data if isinstance(r, dict)]
    if isinstance(data, dict): return [_parse_record(data)]
    return []


def parse_nuclei_sarif(content: str) -> List[Dict[str, Any]]:
    try: data = json.loads(content)
    except json.JSONDecodeError as e: raise ValueError(f"Nuclei SARIF: {e}")
    findings = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rid = result.get("ruleId", "")
            rule = rules.get(rid, {})
            props = result.get("properties", {})
            loc = (result.get("locations") or [{}])[0]
            uri = loc.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
            msg = result.get("message", {}).get("text", "")
            findings.append({
                "_format": "nuclei_sarif",
                "raw_finding_id": _nuclei_id(rid, uri, msg[:64]),
                "template_id": rid, "name": rule.get("name", rid),
                "severity": props.get("severity", result.get("level", "")),
                "description": rule.get("fullDescription", {}).get("text", ""),
                "solution": props.get("remediation", ""),
                "references": rule.get("helpUri", ""), "tags": props.get("tags", []),
                "cve_ids": props.get("cve-id", []), "cwe_ids": props.get("cwe-id", []),
                "cvss_score": props.get("cvss-score"), "cvss_vector": props.get("cvss-metrics", ""),
                "host": uri, "matched_at": uri, "matcher_name": props.get("matcher-name", ""),
                "finding_type": props.get("type", ""), "timestamp": "",
            })
    return findings


def parse_nuclei_markdown(content: str) -> List[Dict[str, Any]]:
    findings = []
    for block in re.split(r"\n## ", content):
        if not block.strip(): continue
        lines = block.strip().splitlines()
        name = lines[0].strip().lstrip("# ").strip() if lines else ""
        data: Dict[str, Any] = {"_format": "nuclei_markdown", "name": name}
        for line in lines[1:]:
            m = re.match(r"\*?\*?([A-Za-z\s\-]+)\*?\*?:\s*(.+)", line)
            if m:
                k = m.group(1).strip().lower().replace(" ", "_").replace("-", "_")
                data[k] = m.group(2).strip()
        host = data.get("target", data.get("host", data.get("matched_at", "")))
        tid = data.get("template_id", data.get("template", name.lower().replace(" ", "-")))
        data.update({
            "raw_finding_id": _nuclei_id(tid, host, host),
            "template_id": tid, "host": host, "matched_at": host,
            "severity": data.get("severity", ""), "cve_ids": [], "cwe_ids": [],
        })
        findings.append(data)
    return findings


def parse_nuclei(content: str, fmt: str) -> List[Dict[str, Any]]:
    """fmt: 'jsonl'|'json'|'sarif'|'markdown'"""
    fmt = fmt.lower().strip()
    if fmt == "jsonl": return parse_nuclei_jsonl(content)
    elif fmt == "json": return parse_nuclei_json(content)
    elif fmt == "sarif": return parse_nuclei_sarif(content)
    elif fmt == "markdown": return parse_nuclei_markdown(content)
    stripped = content.strip()
    if stripped.startswith("#"): return parse_nuclei_markdown(content)
    try:
        d = json.loads(stripped)
        if "runs" in d: return parse_nuclei_sarif(content)
        if isinstance(d, list): return parse_nuclei_json(content)
    except Exception: pass
    return parse_nuclei_jsonl(content)
