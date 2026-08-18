"""
nmap_parser.py — Parses ALL Nmap output formats.
Supports: XML (-oX), Normal text (-oN), Grepable (-oG).
Open ports without CVE are kept; tagged data_completeness=no_cve in normalizer.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
import re
from typing import List, Dict, Any


def parse_nmap_xml(content: str) -> List[Dict[str, Any]]:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        # Try to repair truncated XML
        try:
            # Strip trailing unfinished tag, e.g. anything after the last '<' if there is no matching '>'
            last_lt = content.rfind('<')
            last_gt = content.rfind('>')
            repaired_content = content
            if last_lt > last_gt:
                repaired_content = content[:last_lt]
            
            tags = ["nmaprun", "host", "ports", "port", "hostnames", "script", "table"]
            open_tags = []
            for match in re.finditer(r'<(/?)(\w+)[^>]*>', repaired_content):
                if match.group(0).endswith('/>'):
                    continue
                is_close = bool(match.group(1))
                tag_name = match.group(2)
                if tag_name in tags:
                    if is_close:
                        if open_tags and open_tags[-1] == tag_name:
                            open_tags.pop()
                    else:
                        open_tags.append(tag_name)
            
            for tag in reversed(open_tags):
                repaired_content += f"\n</{tag}>"
            
            root = ET.fromstring(repaired_content)
        except Exception:
            raise ValueError(f"Nmap XML parse error: {e}")

    findings = []
    scanner_version = root.get("version", "")
    scan_start = root.get("startstr", "")

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state", "").lower() != "up":
            continue
        ip = ""
        for addr in host.findall("address"):
            if addr.get("addrtype", "").lower() == "ipv4":
                ip = addr.get("addr", "")
                break
        hn = host.find("hostnames/hostname")
        hostname = hn.get("name", "") if hn is not None else ""

        for port_el in host.findall("ports/port"):
            state_el = port_el.find("state")
            port_state = state_el.get("state", "") if state_el is not None else ""
            if port_state.lower() not in ("open", "open|filtered"):
                continue
            port_num = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")
            svc = port_el.find("service")
            svc_name = svc.get("name", "") if svc is not None else ""
            svc_ver = f"{svc.get('product','') or ''} {svc.get('version','') or ''}".strip() if svc is not None else ""
            svc_method = svc.get("method", "") if svc is not None else ""

            base = {
                "_format": "nmap_xml", "scanner_version": scanner_version,
                "scan_date": scan_start, "host_ip": ip, "hostname": hostname,
                "port": port_num, "protocol": protocol, "port_state": port_state,
                "service_name": svc_name, "service_version": svc_ver,
                "service_method": svc_method, "cve_ids": [], "cvss_score": None,
                "is_exploit": False, "vuln_url": "", "script_id": "",
                "name": f"Open Port: {svc_name or protocol}/{port_num}",
                "description": f"Port {port_num}/{protocol} is open. Service: {svc_name} {svc_ver}".strip(),
            }

            vuln_records = []
            for script in port_el.findall("script"):
                sid = script.get("id", "")
                for table in script.findall("table"):
                    cve_id = table.get("key", "")
                    if not re.match(r"CVE-\d{4}-\d+", cve_id, re.IGNORECASE):
                        continue
                    elems = {e.get("key", ""): (e.text or "").strip() for e in table.findall("elem")}
                    try: cvss = float(elems.get("cvss", elems.get("cvss3", 0)))
                    except (ValueError, TypeError): cvss = None
                    is_exploit = elems.get("is_exploit", "false").lower() == "true"
                    vuln_records.append({
                        **base, "raw_finding_id": f"{ip}:{port_num}:{cve_id.upper()}",
                        "name": f"{svc_name} — {cve_id.upper()}",
                        "cve_ids": [cve_id.upper()], "cvss_score": cvss,
                        "is_exploit": is_exploit, "vuln_url": elems.get("type", ""),
                        "script_id": sid,
                        "description": (
                            f"{cve_id.upper()} on {ip}:{port_num}/{protocol} ({svc_name}). "
                            f"CVSS: {cvss}. Exploit: {is_exploit}."
                        ),
                    })

            if vuln_records:
                findings.extend(vuln_records)
            else:
                base["raw_finding_id"] = f"{ip}:{port_num}:{protocol}"
                findings.append(base)
    return findings


def parse_nmap_normal(content: str) -> List[Dict[str, Any]]:
    findings = []
    current_ip = ""
    current_hostname = ""
    for line in content.splitlines():
        ip_match = re.match(r"Nmap scan report for (.+)", line)
        if ip_match:
            host_part = ip_match.group(1).strip()
            ip_extract = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", host_part)
            if ip_extract:
                current_ip = ip_extract.group(1)
                hn_m = re.match(r"(.+?)\s+\(", host_part)
                current_hostname = hn_m.group(1).strip() if hn_m else ""
            else:
                current_hostname = host_part
                current_ip = ""
            continue
        port_match = re.match(r"(\d+)/(tcp|udp)\s+(open\S*)\s+(.*)", line)
        if port_match and current_ip:
            pn = int(port_match.group(1))
            proto = port_match.group(2)
            state = port_match.group(3)
            svc_info = port_match.group(4).strip()
            parts = svc_info.split(None, 1)
            svc_name = parts[0] if parts else ""
            findings.append({
                "_format": "nmap_normal", "scan_date": "",
                "raw_finding_id": f"{current_ip}:{pn}:{proto}",
                "host_ip": current_ip, "hostname": current_hostname,
                "port": pn, "protocol": proto, "port_state": state,
                "service_name": svc_name,
                "service_version": parts[1] if len(parts) > 1 else "",
                "service_method": "", "cve_ids": [], "cvss_score": None,
                "is_exploit": False, "script_id": "",
                "name": f"Open Port: {svc_name or proto}/{pn}",
                "description": f"Port {pn}/{proto} is {state}. Service: {svc_info}",
            })
    return findings


def parse_nmap_grepable(content: str) -> List[Dict[str, Any]]:
    findings = []
    for line in content.splitlines():
        line = line.strip()
        if not line.startswith("Host:"):
            continue
        hm = re.match(r"Host:\s+(\S+)\s+\(([^)]*)\)", line)
        if not hm:
            continue
        ip, hostname = hm.group(1), hm.group(2)
        pm = re.search(r"Ports:\s+(.+?)(?:\t|$)", line)
        if not pm:
            continue
        for ps in pm.group(1).split(","):
            parts = ps.strip().split("/")
            if len(parts) < 3:
                continue
            try: pn = int(parts[0])
            except ValueError: continue
            state = parts[1].lower()
            proto = parts[2].lower()
            if "open" not in state:
                continue
            svc_name = parts[4] if len(parts) > 4 else ""
            svc_ver = parts[6] if len(parts) > 6 else ""
            findings.append({
                "_format": "nmap_grepable", "scan_date": "",
                "raw_finding_id": f"{ip}:{pn}:{proto}",
                "host_ip": ip, "hostname": hostname,
                "port": pn, "protocol": proto, "port_state": state,
                "service_name": svc_name, "service_version": svc_ver,
                "service_method": "", "cve_ids": [], "cvss_score": None,
                "is_exploit": False, "script_id": "",
                "name": f"Open Port: {svc_name or proto}/{pn}",
                "description": f"Port {pn}/{proto} is open. Service: {svc_name} {svc_ver}".strip(),
            })
    return findings


def parse_nmap(content: str, fmt: str) -> List[Dict[str, Any]]:
    """fmt: 'xml' | 'normal' | 'grepable'"""
    fmt = fmt.lower().strip()
    if fmt == "xml": return parse_nmap_xml(content)
    elif fmt in ("normal", "txt", "text"): return parse_nmap_normal(content)
    elif fmt in ("grepable", "gnmap"): return parse_nmap_grepable(content)
    stripped = content.strip()
    if stripped.startswith("<"): return parse_nmap_xml(content)
    if "Ports:" in stripped[:300]: return parse_nmap_grepable(content)
    return parse_nmap_normal(content)

