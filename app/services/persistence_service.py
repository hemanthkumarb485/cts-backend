"""
persistence_service.py — Saves completed ScanSession pipeline output to
Supabase Postgres (scan_sessions / findings / risk_scores), and serves the
Targets tab (assets aggregated across a user's scans).

Writes are best-effort from the caller's perspective: the pipeline itself
stays stateless/in-memory, this is purely a persistence side-effect hooked
in after scoring completes. Callers should catch/log failures rather than
let a DB outage break the scan response.
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional
import json

from app.core.db import get_connection
from app.schemas.canonical import ScanSession, CanonicalFinding


def _asset_host(finding: CanonicalFinding) -> str:
    a = finding.asset
    return a.hostname or a.ip or a.domain or a.url or "Unknown"


def save_scan_session(session: ScanSession, user_id: str) -> None:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_sessions
                    (id, user_id, scan_date, uploaded_files, tools_detected,
                     total_raw_findings, total_after_dedup, total_after_fp_filter,
                     total_scored, total_unscored, processing_time_seconds)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
                """,
                (
                    session.session_id, user_id, session.scan_date,
                    json.dumps(session.uploaded_files), json.dumps(session.tools_detected),
                    session.total_raw_findings, session.total_after_dedup,
                    session.total_after_fp_filter, session.total_scored,
                    session.total_unscored, session.processing_time_seconds,
                ),
            )

            for f in session.findings:
                cur.execute(
                    """
                    INSERT INTO findings
                        (finding_id, session_id, user_id, source_tool, vulnerability_name,
                         cve_id, cwe_id, severity, finding_type, asset_host, asset_path, data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        f.finding_id, session.session_id, user_id,
                        f.source_tool.value if f.source_tool else None,
                        f.vulnerability_name, f.cve_id, f.cwe_id,
                        f.severity.value if f.severity else None,
                        f.finding_type, _asset_host(f), f.asset.path or f.asset.url,
                        json.dumps(f.model_dump(mode="json")),
                    ),
                )
                finding_row_id = cur.fetchone()["id"]

                risk = f.risk_score
                if risk is not None:
                    cur.execute(
                        """
                        INSERT INTO risk_scores
                            (session_id, finding_id, cvss_component, kev_component,
                             epss_component, exploitdb_component, github_poc_component,
                             cwe_component, base_score, criticality_multiplier,
                             final_score, priority_tier, scoring_method)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            session.session_id, finding_row_id, risk.cvss_component,
                            risk.kev_component, risk.epss_component, risk.exploitdb_component,
                            getattr(risk, "github_poc_component", None), risk.cwe_component,
                            risk.base_score, risk.criticality_multiplier, risk.final_score,
                            risk.priority_tier.value if risk.priority_tier else None,
                            risk.scoring_method,
                        ),
                    )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_sessions(user_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.id AS session_id, s.scan_date, s.uploaded_files, s.tools_detected,
                       s.total_raw_findings, s.total_after_dedup, s.total_after_fp_filter,
                       s.total_scored, s.total_unscored, s.processing_time_seconds,
                       s.report_generated_at, s.created_at,
                       (
                           SELECT r.id FROM reports r
                           WHERE r.session_id = s.id
                           ORDER BY r.created_at DESC
                           LIMIT 1
                       ) AS report_id,
                       -- A scan_sessions row alone doesn't mean "Store Report"
                       -- was ever clicked: generating a PDF also upserts a
                       -- bare metadata-only row here (see mark_report_generated)
                       -- so the session shows up in History with a finding
                       -- count even though nothing was written to `findings`.
                       -- Targets only reads from `findings`, so surface
                       -- whether this session actually has any.
                       EXISTS (
                           SELECT 1 FROM findings f WHERE f.session_id = s.id
                       ) AS has_findings
                FROM scan_sessions s
                WHERE s.user_id = %s
                ORDER BY s.created_at DESC
                """,
                (user_id,),
            )
            return list(cur.fetchall())
    finally:
        conn.close()


def mark_report_generated(session: ScanSession, user_id: str) -> None:
    """Records when a PDF report was generated for a session — independent
    of whether "Store Report" was ever clicked for it, and safe regardless
    of ordering: upserts a bare scan_sessions row (session metadata only, no
    findings/risk_scores) if one doesn't already exist yet, so the timestamp
    shows up in Session History either way. If "Store Report" is clicked
    later, its own INSERT still runs (ON CONFLICT DO NOTHING only skips the
    session_sessions row itself) and findings/risk_scores get populated as
    normal."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scan_sessions
                    (id, user_id, scan_date, uploaded_files, tools_detected,
                     total_raw_findings, total_after_dedup, total_after_fp_filter,
                     total_scored, total_unscored, processing_time_seconds, report_generated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, now())
                ON CONFLICT (id) DO UPDATE SET report_generated_at = now()
                """,
                (
                    session.session_id, user_id, session.scan_date,
                    json.dumps(session.uploaded_files), json.dumps(session.tools_detected),
                    session.total_raw_findings, session.total_after_dedup,
                    session.total_after_fp_filter, session.total_scored,
                    session.total_unscored, session.processing_time_seconds,
                ),
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def save_report_record(user_id: str, session_id: str, file_name: str, storage_path: str, report_type: str = "pdf") -> str:
    """Indexes a report already uploaded to Supabase Storage. Returns the new report id."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO reports (user_id, session_id, file_name, storage_path, report_type)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, session_id, file_name, storage_path, report_type),
            )
            report_id = cur.fetchone()["id"]
        conn.commit()
        return report_id
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_reports(user_id: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id AS report_id, session_id, file_name, storage_path, report_type, created_at
                FROM reports
                WHERE user_id = %s
                ORDER BY created_at DESC
                """,
                (user_id,),
            )
            return list(cur.fetchall())
    finally:
        conn.close()


def get_report(user_id: str, report_id: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id AS report_id, storage_path, file_name FROM reports WHERE user_id = %s AND id = %s",
                (user_id, report_id),
            )
            return cur.fetchone()
    finally:
        conn.close()


def get_targets(user_id: str) -> List[Dict[str, Any]]:
    """One row per distinct asset host, aggregated across all the user's scans."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                WITH ranked AS (
                    SELECT
                        f.asset_host AS host,
                        f.created_at,
                        r.priority_tier,
                        CASE r.priority_tier
                            WHEN 'P0' THEN 0 WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2 WHEN 'P3' THEN 3 ELSE 4 END AS tier_rank
                    FROM findings f
                    LEFT JOIN risk_scores r ON r.finding_id = f.id
                    WHERE f.user_id = %s AND f.asset_host IS NOT NULL
                )
                SELECT
                    host,
                    COUNT(*) AS finding_count,
                    MAX(created_at) AS last_seen,
                    (ARRAY_AGG(priority_tier ORDER BY tier_rank))[1] AS highest_tier
                FROM ranked
                GROUP BY host
                ORDER BY last_seen DESC
                """,
                (user_id,),
            )
            return list(cur.fetchall())
    finally:
        conn.close()


def get_target_findings(user_id: str, host: str) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT finding_id, created_at, data FROM findings
                WHERE user_id = %s AND asset_host = %s
                ORDER BY created_at DESC
                """,
                (user_id, host),
            )
            return list(cur.fetchall())
    finally:
        conn.close()


def get_finding_by_id(user_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    """Look up a single persisted finding by its pipeline finding_id — used
    as a fallback by the finding detail page when the finding isn't in the
    caller's current in-memory scan session (e.g. reached via Targets, which
    aggregates across all past sessions, not just the active one)."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT data FROM findings
                WHERE user_id = %s AND finding_id = %s
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (user_id, finding_id),
            )
            row = cur.fetchone()
            return row["data"] if row else None
    finally:
        conn.close()
