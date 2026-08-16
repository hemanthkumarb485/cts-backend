"""
zap_parser.py — Parses ALL ZAP output formats into raw dicts.
Supports: ZAP SARIF JSON, ZAP Native XML, ZAP Native JSON.
User selects format via dropdown; auto-detect fallback is also provided.
INFO/Informational severity is kept here and stripped during normalization.
"""
from __future__ import annotations
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


# ─── ZAP SARIF JSON ───────────────────────────────────────────────────────────

def parse_zap_sarif(content: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"ZAP SARIF JSON parse error: {e}")

    findings = []
    for run in data.get("runs", []):
        rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            props = result.get("properties", {})
            location = (result.get("locations") or [{}])[0]
            phys = location.get("physicalLocation", {})
            artifact = phys.get("artifactLocation", {})
            region = phys.get("region", {})
            web_req = result.get("webRequest", {})
            web_res = result.get("webResponse", {})

            findings.append({
                "_format": "sarif",
                "rule_id": rule_id,
                "level": result.get("level", ""),
                "message": result.get("message", {}).get("text", ""),
                "name": rule.get("name", "") or rule_id,
                "description": rule.get("fullDescription", {}).get("text", "") or props.get("description", ""),
                "uri": artifact.get("uri", ""),
                "start_line": region.get("startLine"),
                "snippet": region.get("snippet", {}).get("text", ""),
                "attack": props.get("attack", ""),
                "confidence": props.get("confidence", ""),
                "risk_desc": props.get("riskdesc", ""),
                "cwe_id": str(props.get("cweid", "")),
                "wasc_id": str(props.get("wascid", "")),
                "solution": props.get("solution", ""),
                "references": props.get("reference", ""),
                "req_method": web_req.get("method", ""),
                "req_target": web_req.get("target", ""),
                "req_protocol": web_req.get("protocol", ""),
                "req_version": web_req.get("version", ""),
                "req_headers": web_req.get("headers", {}),
                "req_body": web_req.get("body", {}).get("text", "") if isinstance(web_req.get("body"), dict) else "",
                "res_status": web_res.get("statusCode"),
                "res_reason": web_res.get("reasonPhrase", ""),
                "res_headers": web_res.get("headers", {}),
                "res_body": web_res.get("body", {}).get("text", "") if isinstance(web_res.get("body"), dict) else "",
            })
    return findings


# ─── ZAP Native XML ───────────────────────────────────────────────────────────

def parse_zap_xml(content: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"ZAP XML parse error: {e}")

    findings = []
    for site in root.findall(".//site"):
        site_host = site.get("host", "")
        site_port = site.get("port", "")
        ssl = site.get("ssl", "false")
        protocol = "https" if ssl.lower() == "true" else "http"

        for alert in site.findall(".//alertitem"):
            def txt(tag: str) -> str:
                el = alert.find(tag)
                return (el.text or "").strip() if el is not None else ""

            instances = []
            for inst in alert.findall(".//instance"):
                def itxt(t): 
                    el = inst.find(t)
                    return (el.text or "").strip() if el is not None else ""
                instances.append({
                    "uri": itxt("uri"), "method": itxt("method"),
                    "param": itxt("param"), "attack": itxt("attack"), "evidence": itxt("evidence"),
                })

            findings.append({
                "_format": "xml", "rule_id": txt("pluginid"), "name": txt("name"),
                "risk_desc": txt("riskdesc"), "confidence": txt("confidence"),
                "description": txt("desc"), "solution": txt("solution"),
                "references": txt("reference"), "cwe_id": txt("cweid"),
                "wasc_id": txt("wascid"), "host": site_host, "port": site_port,
                "protocol": protocol, "uri": txt("uri"), "method": txt("method"),
                "param": txt("param"), "attack": txt("attack"), "evidence": txt("evidence"),
                "instances": instances,
            })
    return findings


# ─── ZAP Native JSON ──────────────────────────────────────────────────────────

def parse_zap_native_json(content: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"ZAP native JSON parse error: {e}")

    findings = []
    sites = data.get("site", data.get("sites", []))
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_host = site.get("@host", site.get("host", ""))
        site_port = site.get("@port", site.get("port", ""))
        ssl = site.get("@ssl", site.get("ssl", "false"))
        protocol = "https" if str(ssl).lower() == "true" else "http"
        alerts = site.get("alerts", {})
        if isinstance(alerts, dict):
            alerts = alerts.get("alertItem", [])
        if isinstance(alerts, dict):
            alerts = [alerts]

        for alert in alerts:
            instances = alert.get("instances", {})
            if isinstance(instances, dict):
                instances = instances.get("instance", [])
            if isinstance(instances, dict):
                instances = [instances]

            findings.append({
                "_format": "native_json",
                "rule_id": str(alert.get("pluginid", "")),
                "name": alert.get("name", ""),
                "risk_desc": alert.get("riskdesc", ""),
                "confidence": alert.get("confidence", alert.get("confidencedesc", "")),
                "description": alert.get("desc", ""),
                "solution": alert.get("solution", ""),
                "references": alert.get("reference", ""),
                "cwe_id": str(alert.get("cweid", "")),
                "wasc_id": str(alert.get("wascid", "")),
                "host": site_host, "port": site_port, "protocol": protocol,
                "uri": alert.get("uri", ""), "method": alert.get("method", ""),
                "param": alert.get("param", ""), "attack": alert.get("attack", ""),
                "evidence": alert.get("evidence", ""),
                "instances": instances if isinstance(instances, list) else [],
            })
    return findings


# ─── DISPATCHER ───────────────────────────────────────────────────────────────

def parse_zap(content: str, fmt: str) -> List[Dict[str, Any]]:
    """Route to correct ZAP parser. fmt: 'sarif' | 'xml' | 'json'"""
    fmt = fmt.lower().strip()
    if fmt == "sarif":
        return parse_zap_sarif(content)
    elif fmt == "xml":
        return parse_zap_xml(content)
    elif fmt in ("json", "native_json"):
        return parse_zap_native_json(content)
    else:
        stripped = content.strip()
        if stripped.startswith("<"):
            return parse_zap_xml(content)
        try:
            d = json.loads(stripped)
            return parse_zap_sarif(content) if "runs" in d else parse_zap_native_json(content)
        except Exception:
            raise ValueError(f"Cannot auto-detect ZAP format: {stripped[:80]}")

