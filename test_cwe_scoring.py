"""
test_cwe_scoring.py
Verifies CWE-based fallback scoring produces correct scores for all the
findings the user reported as UNSCORED.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from app.services.risk_engine import score_finding, CWE_RISK_MAP
from app.schemas.canonical import (
    CanonicalFinding, AssetSchema, SourceTool, SourceFormat,
    NormalizedSeverity, DataCompleteness, PriorityTier
)

TEST_CASES = [
    # (name, cwe_id, severity, expected_tier)
    ("Cross Site Scripting (Reflected)",        "CWE-79",   NormalizedSeverity.HIGH,   "P1"),
    ("SQL Injection",                            "CWE-89",   NormalizedSeverity.HIGH,   "P1"),
    ("Absence of Anti-CSRF Tokens",             "CWE-352",  NormalizedSeverity.MEDIUM, "P2"),
    ("Content Security Policy Header Not Set",  "CWE-693",  NormalizedSeverity.MEDIUM, "P2"),
    ("Missing Anti-clickjacking Header",        "CWE-1021", NormalizedSeverity.MEDIUM, "P2"),
    ("Cookie without SameSite Attribute",       "CWE-1275", NormalizedSeverity.LOW,    "P3"),
    ("X-Powered-By Header",                     "CWE-497",  NormalizedSeverity.LOW,    "P3"),
    ("X-AspNet-Version Response Header",        "CWE-933",  NormalizedSeverity.LOW,    "P3"),
    ("Open Port: ftp/21",                        None,       NormalizedSeverity.LOW,    "P3"),
]

print("=" * 70)
print(f"{'Name':<45} {'CWE':<10} {'Score':>6}  {'Tier':<8} {'Method'}")
print("=" * 70)

all_pass = True
for name, cwe, sev, expected_tier in TEST_CASES:
    f = CanonicalFinding(
        vulnerability_name=name,
        source_tool=SourceTool.ZAP,
        source_format=SourceFormat.JSON,
        severity=sev,
        cwe_id=cwe,
        cve_id=None,
        asset=AssetSchema(hostname="example.com"),
        data_completeness=DataCompleteness.NO_CVE,
    )
    score_finding(f)
    rs = f.risk_score
    score_str = f"{rs.final_score:.1f}" if rs.final_score is not None else "N/A"
    tier = rs.priority_tier.value if rs.priority_tier else "UNSCORED"
    method = rs.scoring_method or "?"
    status = "✅" if tier == expected_tier else f"❌ (expected {expected_tier})"
    if tier != expected_tier:
        all_pass = False
    print(f"{name:<45} {str(cwe):<10} {score_str:>6}  {tier:<8} {method}  {status}")

print("=" * 70)
print("ALL PASS ✅" if all_pass else "SOME FAILED ❌")
