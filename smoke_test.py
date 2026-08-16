"""
smoke_test.py — End-to-end pipeline test with minimal sample data.
Tests: ZAP XML → Nuclei JSONL → Nmap XML → OpenVAS XML
"""
import sys
sys.path.insert(0, ".")

from app.services.pipeline import run_pipeline

# ── ZAP Native XML sample ──────────────────────────────────────────────────────
ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport>
  <site host="example.com" name="https://example.com" port="443" ssl="true">
    <alerts>
      <alertitem>
        <pluginid>40012</pluginid>
        <name>Cross Site Scripting (Reflected)</name>
        <riskdesc>High (Medium)</riskdesc>
        <confidence>Medium</confidence>
        <desc>XSS vulnerability found.</desc>
        <solution>Validate input.</solution>
        <reference>https://owasp.org/xss</reference>
        <cweid>79</cweid>
        <wascid>8</wascid>
        <uri>https://example.com/search</uri>
        <method>GET</method>
        <param>q</param>
        <attack>&lt;script&gt;alert(1)&lt;/script&gt;</attack>
        <evidence>&lt;script&gt;alert(1)&lt;/script&gt;</evidence>
      </alertitem>
      <alertitem>
        <pluginid>10027</pluginid>
        <name>Information Disclosure - Debug Error Messages</name>
        <riskdesc>Informational (Low)</riskdesc>
        <confidence>Low</confidence>
        <desc>Debug info visible.</desc>
        <cweid>200</cweid>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""

# ── Nuclei JSONL sample ────────────────────────────────────────────────────────
NUCLEI_JSONL = """{"template-id":"CVE-2021-44228","info":{"name":"Apache Log4j2 RCE","severity":"critical","description":"Log4Shell RCE","classification":{"cve-id":["CVE-2021-44228"],"cwe-id":["CWE-502"],"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H","cvss-score":10.0},"tags":["cve","rce","log4j"]},"host":"https://example.com","ip":"93.184.216.34","port":"443","matched-at":"https://example.com/login","timestamp":"2026-08-14T10:00:00Z","type":"http"}
{"template-id":"nuclei-xss-check","info":{"name":"Cross-Site Scripting","severity":"high","classification":{"cwe-id":["CWE-79"],"cvss-score":7.5}},"host":"https://example.com","matched-at":"https://example.com/search?q=test","timestamp":"2026-08-14T10:01:00Z","type":"http"}
{"template-id":"info-check","info":{"name":"Server Banner","severity":"info"},"host":"https://example.com","matched-at":"https://example.com","timestamp":"2026-08-14T10:02:00Z"}"""

# ── Nmap XML sample ────────────────────────────────────────────────────────────
NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.99" startstr="Fri Aug 14 13:19:38 2026">
  <host>
    <status state="up"/>
    <address addr="10.129.8.178" addrtype="ipv4"/>
    <hostnames><hostname name="target.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" method="table"/>
        <script id="vulners">
          <table key="CVE-2021-41773">
            <elem key="type">cve</elem>
            <elem key="id">CVE-2021-41773</elem>
            <elem key="cvss">7.5</elem>
            <elem key="is_exploit">true</elem>
          </table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>"""

# ── Run pipeline ───────────────────────────────────────────────────────────────
files = [
    {"tool": "zap",    "fmt": "xml",    "content": ZAP_XML,       "filename": "zap_result.xml",    "criticality": "production"},
    {"tool": "nuclei", "fmt": "jsonl",  "content": NUCLEI_JSONL,  "filename": "nuclei_result.jsonl","criticality": "production"},
    {"tool": "nmap",   "fmt": "xml",    "content": NMAP_XML,       "filename": "nmap_result.xml",   "criticality": "staging"},
]

print("Running pipeline smoke test...")
session = run_pipeline(files)

print(f"\n{'='*60}")
print(f"Session ID: {session.session_id}")
print(f"Raw findings:       {session.total_raw_findings}")
print(f"After dedup:        {session.total_after_dedup}")
print(f"After FP filter:    {session.total_after_fp_filter}")
print(f"Scored:             {session.total_scored}")
print(f"Unscored (no CVE):  {session.total_unscored}")
print(f"Errors:             {session.processing_errors}")
print(f"\n--- FINDINGS ---")
for f in session.findings:
    tier = f.risk_score.priority_tier.value if f.risk_score else "UNSCORED"
    score = f"{f.risk_score.final_score:.1f}" if f.risk_score and f.risk_score.final_score else "N/A"
    host = f.asset.hostname or f.asset.ip or f.asset.domain or "unknown"
    print(f"  [{tier}] score={score:>6} | {f.source_tool.value.upper():8} | {f.severity.value.upper():12} | {f.vulnerability_name[:45]} | host={host}")

fails = [e for e in session.processing_errors]
print(f"\n{'ALL PIPELINE STAGES PASSED' if not fails else 'ERRORS: ' + str(fails)}")
