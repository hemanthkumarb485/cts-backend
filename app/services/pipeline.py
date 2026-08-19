"""
pipeline.py — Full processing pipeline with SSE progress and console logging.
"""
from __future__ import annotations
import uuid, time, logging
from typing import AsyncGenerator, List, Dict, Any

from app.services.parsers.zap_parser import parse_zap
from app.services.parsers.nuclei_parser import parse_nuclei
from app.services.parsers.openvas_parser import parse_openvas
from app.services.parsers.nmap_parser import parse_nmap
from app.services.normalization import normalize_findings
from app.services.deduplication import deduplicate
from app.services.false_positive import apply_false_positive_rules, filter_active
from app.services.threat_intel import enrich_findings
from app.services.risk_engine import score_all_findings
from app.schemas.canonical import ScanSession, CanonicalFinding, AssetCriticality

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [%(levelname)s] PIPELINE %(message)s")
log = logging.getLogger("pipeline")

PARSER_MAP = {"zap": parse_zap, "nuclei": parse_nuclei,
              "openvas": parse_openvas, "nmap": parse_nmap}


def run_pipeline(files: List[Dict[str, Any]]) -> ScanSession:
    t0 = time.time()
    from datetime import datetime
    scan_time = datetime.now().isoformat()
    session = ScanSession(session_id=str(uuid.uuid4()), scan_date=scan_time)
    all_findings: List[CanonicalFinding] = []
    log.info(f"START session={session.session_id[:8]} files={len(files)}")
    for fi in files:
        tool = fi["tool"].lower()
        fmt, content = fi["fmt"], fi["content"]
        filename = fi.get("filename", f"{tool}_file")
        criticality = fi.get("criticality", "unknown")
        session.uploaded_files.append(filename)
        if tool not in session.tools_detected:
            session.tools_detected.append(tool)
        try:
            log.info(f"  PARSE  tool={tool} fmt={fmt} size={len(content)} chars")
            parser = PARSER_MAP.get(tool)
            if not parser:
                session.processing_errors.append({"file": filename, "error": f"Unknown tool: {tool}"})
                continue
            raw = parser(content, fmt)
            norm = normalize_findings(tool, raw)
            log.info(f"  NORM   {len(raw)} raw -> {len(norm)} findings (INFO stripped)")
            crit = AssetCriticality(criticality) if criticality in [e.value for e in AssetCriticality] else AssetCriticality.UNKNOWN
            for f in norm: f.asset.criticality = crit
            all_findings.extend(norm)
        except Exception as e:
            log.error(f"  ERROR  {filename}: {e}")
            session.processing_errors.append({"file": filename, "error": str(e)})
    session.total_raw_findings = len(all_findings)
    log.info(f"STEP1 DONE  raw={session.total_raw_findings}  t={time.time()-t0:.1f}s")
    log.info("STEP2 Deduplication...")
    deduped = deduplicate(all_findings)
    session.total_after_dedup = len(deduped)
    log.info(f"STEP2 DONE  unique={session.total_after_dedup}  t={time.time()-t0:.1f}s")
    log.info("STEP3 False positive filtering...")
    active = filter_active(apply_false_positive_rules(deduped))
    session.total_after_fp_filter = len(active)
    log.info(f"STEP3 DONE  active={session.total_after_fp_filter}  t={time.time()-t0:.1f}s")
    log.info("STEP4 Threat intel enrichment (NVD/EPSS/KEV/ExploitDB)...")
    enriched = enrich_findings(active)
    log.info(f"STEP4 DONE  t={time.time()-t0:.1f}s")
    log.info("STEP5 Risk scoring...")
    scored = score_all_findings(enriched)
    session.total_scored   = sum(1 for f in scored if f.risk_score and f.risk_score.final_score is not None)
    session.total_unscored = sum(1 for f in scored if not f.risk_score or f.risk_score.final_score is None)
    session.findings = scored
    session.processing_time_seconds = round(time.time() - t0, 2)
    log.info(f"DONE  scored={session.total_scored} unscored={session.total_unscored} time={session.processing_time_seconds}s")
    return session



async def run_pipeline_sse(files: List[Dict[str, Any]], user_id: str = None) -> AsyncGenerator[str, None]:
    """
    SSE generator for /scan/upload endpoint.

    CRITICAL FIX: sse-starlette v3 (EventSourceResponse) automatically wraps
    every yielded string as:   data: <your_string>\r\n\r\n

    Old code yielded  f"data: {json}\n\n"  so the browser received:
        data: data: {...}\r\ndata: \r\ndata: \r\n\r\n
    which is double-prefixed and completely unparseable by the frontend.

    Fix: yield ONLY the raw JSON string. EventSourceResponse adds the prefix.
    """
    import asyncio, json, concurrent.futures
    start = time.time()

    def elapsed():
        return round(time.time() - start, 2)

    def event(stage, pct, msg, data=None):
        p = {"stage": stage, "percent": pct, "message": msg, "elapsed_seconds": elapsed()}
        if data is not None:
            p["data"] = data
        return json.dumps(p)   # raw JSON only — NO "data: " prefix, NO "\n\n"

    yield event("start", 0, "Pipeline started - reading files...")
    await asyncio.sleep(0)
    yield event("parsing", 10, f"Parsing {len(files)} file(s)...")
    await asyncio.sleep(0)

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        yield event("normalization", 25, "Normalizing findings...")
        await asyncio.sleep(0)
        future = loop.run_in_executor(pool, run_pipeline, files)
        while not future.done():
            await asyncio.sleep(1)
            yield event("processing", min(88, 25 + int(elapsed() * 2)),
                        f"Processing... {elapsed()}s elapsed")
        try:
            session: ScanSession = await future
        except Exception as e:
            log.error(f"SSE pipeline error: {e}")
            yield event("error", 100, f"Pipeline failed: {e}")
            return

    yield event("deduplication", 90, f"Dedup: {session.total_after_dedup} unique findings")
    await asyncio.sleep(0)
    yield event("enrichment", 95, "Threat intel enrichment complete")
    await asyncio.sleep(0)
    yield event("scoring", 98, f"Scoring complete - {session.total_scored} scored")
    await asyncio.sleep(0)
    session.processing_time_seconds = elapsed()

    if user_id:
        try:
            from app.services.persistence_service import save_scan_session
            save_scan_session(session, user_id)
        except Exception as e:
            log.error(f"Failed to persist scan session {session.session_id}: {e}")

    yield event("complete", 100, "Pipeline complete!", data=session.model_dump())
