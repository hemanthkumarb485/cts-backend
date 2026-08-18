import sys
sys.path.insert(0, ".")

import re
import xml.etree.ElementTree as ET
from app.services.parsers.nmap_parser import parse_nmap_xml

# Simulating a truncated XML content
TRUNCATED_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99" startstr="Fri Aug 14 13:19:38 2026">
  <host>
    <status state="up"/>
    <address addr="10.129.8.178" addrtype="ipv4"/>
    <hostnames><hostname name="target.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"
"""

try:
    print("Parsing truncated XML...")
    findings = parse_nmap_xml(TRUNCATED_XML)
    print("Parsed successfully!")
    print(f"Findings found: {len(findings)}")
    for f in findings:
        print(f" - {f['name']}")
except Exception as e:
    print(f"Failed: {e}")
    sys.exit(1)
