"""
openvas_parser.py — Parses OpenVAS XML report into normalized raw dicts.
Strips Log/NA severity at normalization stage (kept here for completeness).
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from typing import List, Dict, Any


def _txt(el, tag: str, default: str = "") -> str:
    found = el.find(tag)
    return (found.text or "").strip() if found is not None else default


def _attr(el, attr: str, default: str = "") -> str:
    return el.get(attr, default)


def parse_openvas_xml(content: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise ValueError(f"OpenVAS XML parse error: {e}")

    findings = []

    # Collect host-level CVE details (appear in <host><detail> blocks)
    host_cve_map: Dict[str, List[str]] = {}
    for host_el in root.findall(".//host"):
        host_ip = _txt(host_el, "ip")
        if not host_ip:
            ip_el = host_el.find("ip")
            host_ip = (ip_el.text or "").strip() if ip_el is not None else ""
        cves: List[str] = []
        for detail in host_el.findall("detail"):
            name_el = detail.find("name")
            val_el = detail.find("value")
            if name_el is not None and (name_el.text or "").strip() == "Closed CVE":
                if val_el is not None and val_el.text:
                    for c in val_el.text.split(","):
                        c = c.strip()
                        if c: cves.append(c)
        if host_ip and cves:
            host_cve_map[host_ip] = cves

    # Parse result blocks
    for result in root.findall(".//result"):
        nvt = result.find("nvt")
        if nvt is None:
            nvt = ET.Element("nvt")

        nvt_oid = _attr(nvt, "oid")
        name = _txt(result, "name") or _txt(nvt, "name")
        threat = _txt(result, "threat")         # Log / Low / Medium / High
        description = _txt(result, "description")
        host_raw = _txt(result, "host")
        host_ip = host_raw.split()[0] if host_raw else ""
        hostname_el = result.find("host/hostname")
        hostname = (hostname_el.text or "").strip() if hostname_el is not None else ""
        port_raw = _txt(result, "port")          # e.g. "80/tcp"
        port_num = None
        port_proto = None
        if "/" in port_raw:
            parts = port_raw.split("/", 1)
            try: port_num = int(parts[0])
            except ValueError: pass
            port_proto = parts[1]

        # CVSS
        cvss_base = _txt(nvt, "cvss_base")
        sev_el = nvt.find("severities/severity/value")
        cvss_vector = (sev_el.text or "").strip() if sev_el is not None else ""
        severity_from_result = _txt(result, "severity")
        try: cvss_score = float(cvss_base or severity_from_result or 0)
        except ValueError: cvss_score = None

        # CVE — prefer host-level detail block, fallback to refs
        cve_ids: List[str] = host_cve_map.get(host_ip, [])
        if not cve_ids:
            for ref in nvt.findall("refs/ref"):
                if _attr(ref, "type").lower() == "cve":
                    val = _attr(ref, "id")
                    if val: cve_ids.append(val)

        # CWE
        cwe_ids: List[str] = []
        for ref in nvt.findall("refs/ref"):
            if _attr(ref, "type").lower() == "cwe":
                cwe_ids.append(_attr(ref, "id"))

        # References (URLs)
        ref_urls: List[str] = []
        for ref in nvt.findall("refs/ref"):
            if _attr(ref, "type").lower() == "url":
                ref_urls.append(_attr(ref, "id"))

        # Solution
        solution_el = nvt.find("solution")
        solution_text = (solution_el.text or "").strip() if solution_el is not None else ""
        solution_type = _attr(solution_el, "type") if solution_el is not None else ""

        # QoD
        qod_el = result.find("qod/value")
        try: qod = int((qod_el.text or "").strip()) if qod_el is not None else None
        except ValueError: qod = None

        # NVT Family
        nvt_family = _txt(nvt, "family")

        # Scan date
        scan_date = _txt(result, "creation_time")

        # Scanner version
        scanner_version = _txt(result, "scan_nvt_version")

        findings.append({
            "_format": "openvas_xml",
            "raw_finding_id": nvt_oid,
            "nvt_oid": nvt_oid,
            "name": name,
            "threat": threat,
            "description": description,
            "host_ip": host_ip,
            "hostname": hostname,
            "port": port_num,
            "protocol": port_proto,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cve_ids": cve_ids,
            "cwe_ids": cwe_ids,
            "references": ref_urls,
            "solution": solution_text,
            "solution_type": solution_type,
            "nvt_family": nvt_family,
            "qod": qod,
            "scan_date": scan_date,
            "scanner_version": scanner_version,
        })
    return findings


def parse_openvas(content: str, fmt: str = "xml") -> List[Dict[str, Any]]:
    """Currently only XML is supported for OpenVAS. fmt param for future use."""
    return parse_openvas_xml(content)
