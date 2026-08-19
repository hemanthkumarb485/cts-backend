"""
Full pipeline mapping audit — traces every finding's CVSS and EPSS
from parser → normalization → enrichment → risk scoring → frontend JSON.
"""
import sys, json
sys.path.insert(0, ".")

from app.services.pipeline import run_pipeline

# We'll use the same scan data the user uploaded (ZAP + OpenVAS + Nuclei + Nmap)
# but first let's just check what the pipeline actually outputs

# Minimal representative samples matching the user's scan
ZAP_XML = """<?xml version="1.0"?>
<OWASPZAPReport>
  <site host="testaspnet.vulnweb.com" name="http://testaspnet.vulnweb.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <pluginid>40018</pluginid>
        <name>SQL Injection</name>
        <riskdesc>High (Medium)</riskdesc>
        <confidence>Medium</confidence>
        <desc>SQL injection may be possible.</desc>
        <solution>Parameterize queries.</solution>
        <cweid>89</cweid>
        <uri>http://testaspnet.vulnweb.com/search</uri>
      </alertitem>
      <alertitem>
        <pluginid>40012</pluginid>
        <name>Cross Site Scripting (Reflected)</name>
        <riskdesc>High (Medium)</riskdesc>
        <confidence>Medium</confidence>
        <desc>XSS vulnerability found.</desc>
        <cweid>79</cweid>
        <uri>http://testaspnet.vulnweb.com/search</uri>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""

OPENVAS_XML = """<?xml version="1.0"?>
<report>
  <results>
    <result>
      <name>Cleartext Transmission of Sensitive Information via HTTP</name>
      <host>testasp.vulnweb.com</host>
      <port>80/tcp</port>
      <threat>Medium</threat>
      <severity>4.8</severity>
      <description>Cleartext HTTP detected.</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.108440">
        <name>Cleartext Transmission of Sensitive Information via HTTP</name>
        <cvss_base>4.8</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2000-0071"/>
        </refs>
      </nvt>
    </result>
    <result>
      <name>ICMP Timestamp Reply Information Disclosure</name>
      <host>testasp.vulnweb.com</host>
      <port>general/icmp</port>
      <threat>Low</threat>
      <severity>2.1</severity>
      <description>ICMP timestamp reply.</description>
      <nvt oid="1.3.6.1.4.1.25623.1.0.103190">
        <name>ICMP Timestamp Reply Information Disclosure</name>
        <cvss_base>2.1</cvss_base>
        <refs>
          <ref type="cve" id="CVE-2000-0071"/>
        </refs>
      </nvt>
    </result>
  </results>
</report>"""

files = [
    {"tool": "zap",     "fmt": "xml", "content": ZAP_XML,     "filename": "zap.xml",     "criticality": "unknown"},
    {"tool": "openvas", "fmt": "xml", "content": OPENVAS_XML, "filename": "openvas.xml", "criticality": "unknown"},
]

session = run_pipeline(files)

print("=" * 90)
print(f"{'#':<3} {'Vulnerability':<45} {'CVE/CWE':<16} {'CVSS':<8} {'EPSS':<8} {'Score':<8} {'Tier'}")
print("=" * 90)

for i, f in enumerate(session.findings, 1):
    ti = f.threat_intel or type('', (), {'epss_score': None, 'nvd_cvss_score': None})()
    cvss_val = f.cvss.base_score if f.cvss and f.cvss.base_score is not None else None
    epss_val = ti.epss_score if ti.epss_score and ti.epss_score > 0.0001 else None
    identifier = f.cve_id or f.cwe_id or "—"
    risk = f.risk_score
    tier = risk.priority_tier.value if risk and risk.priority_tier else "—"
    score = f"{risk.final_score:.1f}" if risk and risk.final_score is not None else "—"
    cvss_str = f"{cvss_val:.1f}" if cvss_val is not None else "—"
    epss_str = f"{epss_val*100:.1f}%" if epss_val is not None else "—"

    print(f"{i:<3} {f.vulnerability_name[:44]:<45} {identifier:<16} {cvss_str:<8} {epss_str:<8} {score:<8} {tier}")

print("=" * 90)

# Detailed JSON dump of threat_intel for CVE findings
print("\n--- DETAILED THREAT INTEL FOR CVE FINDINGS ---")
for f in session.findings:
    if f.cve_id:
        ti = f.threat_intel
        print(f"\n  {f.vulnerability_name} ({f.cve_id}):")
        print(f"    finding.cvss.base_score  = {f.cvss.base_score if f.cvss else 'None (no cvss object)'}")
        print(f"    ti.epss_score            = {ti.epss_score}")
        print(f"    ti.epss_percentile       = {ti.epss_percentile}")
        print(f"    ti.epss_date             = {ti.epss_date}")
        print(f"    ti.nvd_cvss_score        = {ti.nvd_cvss_score}")
        print(f"    ti.nvd_description       = {(ti.nvd_description or '')[:80]}...")
        print(f"    ti.enrichment_errors     = {ti.enrichment_errors}")
        print(f"    risk.cvss_component      = {f.risk_score.cvss_component if f.risk_score else None}")
        print(f"    risk.epss_component      = {f.risk_score.epss_component if f.risk_score else None}")

print("\n--- FRONTEND JSON SAMPLE (first CVE finding) ---")
for f in session.findings:
    if f.cve_id:
        d = f.model_dump(mode="json")
        subset = {
            "vulnerability_name": d["vulnerability_name"],
            "cve_id": d["cve_id"],
            "cvss": d.get("cvss"),
            "threat_intel.epss_score": d.get("threat_intel", {}).get("epss_score"),
            "threat_intel.epss_percentile": d.get("threat_intel", {}).get("epss_percentile"),
            "threat_intel.nvd_cvss_score": d.get("threat_intel", {}).get("nvd_cvss_score"),
            "risk_score.final_score": d.get("risk_score", {}).get("final_score"),
        }
        print(json.dumps(subset, indent=2))
        break
