import sys, os
sys.path.insert(0, ".")

from app.schemas.canonical import CanonicalFinding, AssetSchema, SourceTool, SourceFormat
from app.services.threat_intel import enrich_findings

finding = CanonicalFinding(
    cve_id="CVE-2000-0071",
    vulnerability_name="Test Finding",
    severity="medium",
    source_tool=SourceTool.OPENVAS,
    source_format=SourceFormat.XML,
    asset=AssetSchema(hostname="example.com")
)

print("Enriched findings output:")
results = enrich_findings([finding])
for f in results:
    ti = f.threat_intel
    print(f"CVE ID: {f.cve_id}")
    print(f"EPSS Score: {ti.epss_score}")
    print(f"EPSS Percentile: {ti.epss_percentile}")
    print(f"EPSS Date: {ti.epss_date}")
    print(f"NVD Description: {ti.nvd_description}")
    print(f"NVD CVSS Score: {ti.nvd_cvss_score}")
    print(f"NVD CVSS Severity: {ti.nvd_cvss_severity}")
    print(f"Enrichment Errors: {ti.enrichment_errors}")
