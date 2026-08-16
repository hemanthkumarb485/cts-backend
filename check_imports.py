import sys
sys.path.insert(0, ".")

results = []

try:
    from app.schemas.canonical import CanonicalFinding, ScanSession, PriorityTier
    results.append("OK: app.schemas.canonical")
except Exception as e:
    results.append(f"FAIL: app.schemas.canonical — {e}")

try:
    from app.core.config import APP_NAME, NVD_API_URL
    results.append(f"OK: app.core.config (APP_NAME={APP_NAME})")
except Exception as e:
    results.append(f"FAIL: app.core.config — {e}")

try:
    from app.services.parsers.zap_parser import parse_zap
    results.append("OK: zap_parser")
except Exception as e:
    results.append(f"FAIL: zap_parser — {e}")

try:
    from app.services.parsers.nuclei_parser import parse_nuclei
    results.append("OK: nuclei_parser")
except Exception as e:
    results.append(f"FAIL: nuclei_parser — {e}")

try:
    from app.services.parsers.openvas_parser import parse_openvas
    results.append("OK: openvas_parser")
except Exception as e:
    results.append(f"FAIL: openvas_parser — {e}")

try:
    from app.services.parsers.nmap_parser import parse_nmap
    results.append("OK: nmap_parser")
except Exception as e:
    results.append(f"FAIL: nmap_parser — {e}")

try:
    from app.services.normalization import normalize_findings
    results.append("OK: normalization")
except Exception as e:
    results.append(f"FAIL: normalization — {e}")

try:
    from app.services.deduplication import deduplicate
    results.append("OK: deduplication")
except Exception as e:
    results.append(f"FAIL: deduplication — {e}")

try:
    from app.services.false_positive import apply_false_positive_rules
    results.append("OK: false_positive")
except Exception as e:
    results.append(f"FAIL: false_positive — {e}")

try:
    from app.services.threat_intel import enrich_findings
    results.append("OK: threat_intel")
except Exception as e:
    results.append(f"FAIL: threat_intel — {e}")

try:
    from app.services.risk_engine import score_all_findings
    results.append("OK: risk_engine")
except Exception as e:
    results.append(f"FAIL: risk_engine — {e}")

try:
    from app.services.github_service import build_issue_body
    results.append("OK: github_service")
except Exception as e:
    results.append(f"FAIL: github_service — {e}")

try:
    from app.services.pipeline import run_pipeline
    results.append("OK: pipeline")
except Exception as e:
    results.append(f"FAIL: pipeline — {e}")

try:
    from app.main import app
    results.append("OK: main FastAPI app")
except Exception as e:
    results.append(f"FAIL: main — {e}")

print("\n".join(results))
fails = [r for r in results if r.startswith("FAIL")]
print(f"\n{'ALL PASSED' if not fails else str(len(fails)) + ' FAILURES'}")
