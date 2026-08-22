"""
report.py — /api/v1/report endpoints.
GET /export/json  → Returns ScanSession findings as JSON
POST /export/pdf  → Generates PDF report using PyMuPDF/ReportLab
"""
from __future__ import annotations
import json
import io
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from xml.sax.saxutils import escape as _xml_escape
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.responses import StreamingResponse, JSONResponse
from app.schemas.canonical import ScanSession, CanonicalFinding, PriorityTier
from app.core.config import GROQ_API_KEY
from app.core.security import get_current_user_optional
from app.services import ai_service
from app.services.persistence_service import mark_report_generated, save_report_record
from app.services.storage_service import upload_pdf

log = logging.getLogger("report_endpoint")

router = APIRouter(prefix="/report", tags=["Report"])

# Findings included in the PDF at all (condensed summary table at minimum).
TOTAL_FINDINGS_CAP = 100
# Of those, the highest-risk get a full narrative section: AI overview,
# AI remediation, threat-intel table, risk breakdown, evidence. Capped so
# report generation (which fires up to 2 Groq calls per detailed finding,
# in parallel) stays well inside the frontend's request timeout.
DETAILED_FINDINGS_CAP = 25
AI_MAX_WORKERS = 8


# ReportLab's core Helvetica font is drawn with WinAnsiEncoding, which has
# no glyph for Unicode hyphen variants / minus sign (only ASCII '-' and soft
# hyphen). Groq's model output routinely uses U+2011 (non-breaking hyphen)
# inside compound words and CVE IDs -- left as-is those render as a black
# "notdef" box in the PDF. Normalize them to ASCII. Written as \u escapes
# (not literal glyphs) so the mapping is unambiguous in any editor/encoding.
_UNICODE_FIXUPS = str.maketrans({
    "\u2010": "-",  # hyphen
    "\u2011": "-",  # non-breaking hyphen
    "\u2012": "-",  # figure dash
    "\u2013": "-",  # en dash (kept ASCII for safety even though WinAnsi has a glyph)
    "\u2014": "-",  # em dash (kept ASCII for safety even though WinAnsi has a glyph)
    "\u2015": "-",  # horizontal bar
    "\u2212": "-",  # minus sign
    "\u200b": "",  # zero-width space
    "\u200c": "",  # zero-width non-joiner
    "\u200d": "",  # zero-width joiner
    "\ufeff": "",  # BOM / zero-width no-break space
    "\u00a0": " ",  # non-breaking space
    "\u202f": " ",  # narrow no-break space
    "\u2009": " ",  # thin space
})


def _safe(text: Optional[str], limit: Optional[int] = None) -> str:
    """Escape free text for ReportLab's mini-XML Paragraph markup and cap
    its length. Scanner evidence/attack fields routinely contain literal
    '<script>...' or '&'-laced payloads (that's the vulnerability being
    reported) — without escaping, those break Paragraph's parser or render
    as if they were markup instead of the literal text they are."""
    if not text:
        return "—"
    t = str(text).translate(_UNICODE_FIXUPS)
    if limit and len(t) > limit:
        t = t[:limit].rstrip() + "…"
    return _xml_escape(t).replace("\n", "<br/>")


def _ai_markup(text: Optional[str], limit: Optional[int] = None) -> str:
    """Like _safe(), but additionally promotes the AI's markdown-lite output
    (**bold**, `code`, and ```fenced code```) into real ReportLab Paragraph
    tags instead of leaving literal asterisks/backticks in the PDF.
    Escaping happens first (via _safe), so this only ever turns already-
    escaped, already-safe text into <b>/<font face="Courier"> spans — it
    can't introduce new markup from unescaped input.

    This is a single-pass, boundary-respecting tokenizer rather than two
    independent global regex substitutions (bold, then code) — the latter
    reliably crashes on real model output: a ```fenced code block``` has
    3+3 backticks, and blindly pairing every backtick left-to-right across
    the WHOLE text (ignoring fence/bold boundaries) produces spans that
    cross a bold span's boundary, e.g. `<b>...<font>...</b>...</font>` —
    ReportLab's strict parser (a subclass of Python's html.parser) rejects
    that as "saw </font> instead of expected </b>". Consuming each token as
    a self-contained unit, in the order it actually appears, makes crossing
    tags structurally impossible."""
    t = _safe(text, limit)
    out = []
    i, n = 0, len(t)
    while i < n:
        if t.startswith("```", i):
            end = t.find("```", i + 3)
            if end != -1:
                content = t[i + 3:end]
                # Drop a leading language tag on its own line ("apache<br/>...").
                content = re.sub(r"^[A-Za-z0-9_+-]*<br/>", "", content, count=1)
                out.append(f'<font face="Courier">{content}</font>')
                i = end + 3
                continue
        if t.startswith("**", i):
            end = t.find("**", i + 2)
            if end != -1:
                inner = t[i + 2:end]
                # Support the common "**`code`**" nesting case — scoped to
                # this span only, so it can't cross into surrounding text.
                inner = re.sub(r"`([^`]+?)`", r'<font face="Courier">\1</font>', inner)
                out.append(f"<b>{inner}</b>")
                i = end + 2
                continue
        if t[i] == "`":
            end = t.find("`", i + 1)
            if end != -1:
                out.append(f'<font face="Courier">{t[i + 1:end]}</font>')
                i = end + 1
                continue
        # No token starts here (or it has no matching close) — copy verbatim
        # up to the next character that could start one.
        j = i + 1
        while j < n and t[j] not in ("*", "`"):
            j += 1
        out.append(t[i:j])
        i = j
    return "".join(out)


def _parse_dt(raw: Optional[str]):
    """Parses an ISO-8601 timestamp defensively. Some scanners/DB drivers
    emit sub-microsecond (e.g. nanosecond) fractional seconds, which
    Python's fromisoformat rejects outright (it only accepts 0/3/6 fraction
    digits) — that made every such date fall back to being displayed as the
    raw, unreadable string. Truncate any longer fraction to 6 digits first."""
    if not raw:
        return None
    s = raw.strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _format_scan_date(raw: Optional[str], fmt: str = "%d:%m:%Y-%H:%M:%S") -> Optional[str]:
    dt = _parse_dt(raw)
    return dt.strftime(fmt) if dt else None


def _shield_logo(size: float = 60, color_hex: str = "#18181b"):
    """VulneraX's actual shield-exclamation mark — the exact Heroicons glyph
    used in the app sidebar (viewBox 0 0 24 24, stroke-width 1.6):
        M12 9v3.75m0-10.036A11.959 11.959 0 0 1 3.598 6
        11.99 11.99 0 0 0 3 9.75c0 5.592 3.824 10.29 9 11.622
        5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152
        c-3.196 0-6.1-1.25-8.25-3.286Zm0 13.036h.008v.008H12v-.008Z
    ReportLab's Path has no SVG-arc primitive, so the two elliptical `A`
    commands were converted to cubic beziers with the standard endpoint-to-
    center arc parameterization (computed once, not approximated by eye) —
    every other point below is a direct, exact transcription of the SVG
    path data. Coordinates are y-flipped (y' = 24 - y) to go from SVG's
    top-down space to ReportLab's bottom-up one.
    """
    from reportlab.graphics.shapes import Drawing, Group, Path
    from reportlab.lib.colors import HexColor

    stroke = HexColor(color_hex)
    d = Drawing(size, size)
    g = Group()
    scale = size / 24.0
    g.transform = (scale, 0, 0, scale, 0, 0)

    shield = Path(strokeColor=stroke, strokeWidth=1.6, fillColor=None,
                  strokeLineJoin=1, strokeLineCap=1)
    # Subpath 1 — the exclamation mark's stem: M12 9 v3.75
    shield.moveTo(12, 15)
    shield.lineTo(12, 11.25)
    # Subpath 2 — the shield outline (two arcs + four cubic curves + one line, closed)
    shield.moveTo(12, 21.286)
    shield.curveTo(9.9228, 19.3134, 6.4624, 17.96, 3.598, 18.0)
    shield.curveTo(3.2064, 16.8069, 2.9989, 15.5058, 3.0, 14.25)
    shield.curveTo(3.0, 8.658, 6.824, 3.96, 12.0, 2.628)
    shield.curveTo(17.176, 3.96, 21.0, 8.658, 21.0, 14.25)
    shield.curveTo(21.0, 15.56, 20.79, 16.82, 20.402, 18.0)
    shield.lineTo(20.25, 18.0)
    shield.curveTo(17.054, 18.0, 14.15, 19.25, 12.0, 21.286)
    shield.closePath()
    # Subpath 3 — the exclamation mark's dot: a near-zero square, stroked
    # thick and round-jointed so it renders as a solid dot (same trick the
    # source SVG uses).
    shield.moveTo(12, 8.25)
    shield.lineTo(12.008, 8.25)
    shield.lineTo(12.008, 8.242)
    shield.lineTo(12, 8.242)
    shield.closePath()
    g.add(shield)

    d.add(g)
    d.hAlign = "CENTER"
    return d


def _gather_ai_content(findings: List[CanonicalFinding]) -> Dict[str, Tuple[str, bool, str, bool]]:
    """For each finding, fetch an AI-generated overview + remediation in
    parallel (same Groq calls the finding-detail page makes one at a time).
    Falls back to the scanner's own description/solution per-finding — and
    skips Groq entirely if it isn't configured — so a slow/down AI provider
    never blocks the PDF, it just makes that finding's section less rich.
    Returns finding_id -> (overview, overview_is_ai, remediation, remediation_is_ai).
    """
    results: Dict[str, Tuple[str, bool, str, bool]] = {}
    if not GROQ_API_KEY:
        for f in findings:
            results[f.finding_id] = (
                f.description or "No description provided by the scanner.", False,
                f.solution or "No remediation guidance provided by the scanner.", False,
            )
        return results

    def _fetch(f: CanonicalFinding):
        try:
            overview = ai_service.generate_overview(f)
            overview_ai = True
        except Exception as e:
            log.warning(f"AI overview failed for finding {f.finding_id}: {e}")
            overview = f.description or "No description provided by the scanner."
            overview_ai = False
        try:
            remediation = ai_service.suggest_remediation(f)
            remediation_ai = True
        except Exception as e:
            log.warning(f"AI remediation failed for finding {f.finding_id}: {e}")
            remediation = f.solution or "No remediation guidance provided by the scanner."
            remediation_ai = False
        return f.finding_id, overview, overview_ai, remediation, remediation_ai

    with ThreadPoolExecutor(max_workers=AI_MAX_WORKERS) as pool:
        futures = [pool.submit(_fetch, f) for f in findings]
        for fut in as_completed(futures):
            fid, overview, overview_ai, remediation, remediation_ai = fut.result()
            results[fid] = (overview, overview_ai, remediation, remediation_ai)
    return results


def _compress_pdf(pdf_bytes: bytes) -> bytes:
    """Losslessly recompresses a PDF via PyMuPDF (already a dependency —
    used elsewhere for PDF text extraction) before it's stored/downloaded:
    max garbage collection to drop unused/duplicate objects, deflate to
    recompress content streams and embedded fonts. Reports have no images,
    so nothing is rasterized/downsampled — just structural fat trimmed.
    Falls back to the original bytes if compression fails for any reason,
    so a PyMuPDF hiccup never blocks the user from getting their report."""
    try:
        import pymupdf
        doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
        out = doc.tobytes(garbage=4, deflate=True, deflate_fonts=True, clean=True)
        doc.close()
        before_kb, after_kb = len(pdf_bytes) / 1024, len(out) / 1024
        log.info(f"PDF compressed: {before_kb:.1f} KB -> {after_kb:.1f} KB "
                  f"({(1 - after_kb / before_kb) * 100:.0f}% smaller)" if before_kb else "PDF compressed")
        return out
    except Exception as e:
        log.error(f"PDF compression failed, using uncompressed bytes: {e}")
        return pdf_bytes


@router.post("/export/json")
async def export_json(session: ScanSession):
    """Return the ScanSession as a downloadable JSON file."""
    # Both timestamps must share the same clock — session.scan_date is set
    # server-side as UTC (see pipeline.py), so "now" has to be UTC too, or
    # the two times in the same report look inconsistent (e.g. generation
    # appearing hours *after* it should relative to ingestion) depending on
    # what timezone the backend host happens to be running in.
    generation_time_str = datetime.now(timezone.utc).strftime("%d:%m:%Y-%H:%M:%S") + " UTC"
    _scan_fmt = _format_scan_date(session.scan_date)
    scan_time_str = f"{_scan_fmt} UTC" if _scan_fmt else generation_time_str

    data = session.model_dump()
    data["report_metadata"] = {
        "session_id": session.session_id,
        "scan_ingestion_time": scan_time_str,
        "report_generation_and_download_time": generation_time_str
    }
    
    content = json.dumps(data, indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulnerax_report.json"},
    )


@router.post("/export/pdf")
async def export_pdf(
    session: ScanSession,
    current_user: Optional[dict] = Depends(get_current_user_optional),
    authorization: Optional[str] = Header(None),
):
    """Generate and return a PDF report from a ScanSession. Works anonymously;
    if the caller is logged in, the PDF is also uploaded to their private
    Supabase Storage folder and indexed in `reports` so it can be re-downloaded
    later from Session History."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Table, TableStyle,
            Spacer, HRFlowable, PageBreak, KeepTogether,
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
    except ImportError:
        raise HTTPException(status_code=500, detail="reportlab not installed.")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            rightMargin=2*cm, leftMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=18, spaceAfter=12)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceAfter=6)
    normal = styles["Normal"]

    # Title-page-only styles.
    # NOTE: ParagraphStyle does NOT auto-scale `leading` when you override
    # `fontSize` on a style with a parent — it inherits the parent's leading
    # verbatim. styles["Title"]'s leading (~22pt) is smaller than the 34pt
    # wordmark font, which made the tagline below it render inside the
    # wordmark's own line box (visible overlap) — every style below that
    # bumps fontSize past its parent's must set `leading` explicitly.
    wordmark_style = ParagraphStyle("Wordmark", parent=styles["Title"], fontSize=34, leading=42,
                                     alignment=TA_CENTER, textColor=colors.HexColor("#18181b"), spaceAfter=8)
    tagline_style = ParagraphStyle("Tagline", parent=styles["Normal"], fontSize=10, leading=13,
                                    alignment=TA_CENTER, textColor=colors.HexColor("#71717a"),
                                    spaceBefore=2, spaceAfter=40, tracking=1)
    report_title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=20, leading=25,
                                         alignment=TA_CENTER, spaceAfter=14)
    confidential_style = ParagraphStyle("Confidential", parent=styles["Normal"], fontSize=13, leading=16,
                                         alignment=TA_CENTER, textColor=colors.HexColor("#2563eb"), spaceAfter=20)

    # Finding-section styles
    finding_title_style = ParagraphStyle("FindingTitle", parent=styles["Heading3"], fontSize=12,
                                          textColor=colors.white, spaceAfter=0, spaceBefore=0)
    label_style = ParagraphStyle("Label", parent=styles["Normal"], fontSize=8,
                                  textColor=colors.HexColor("#71717a"), spaceAfter=1)
    value_style = ParagraphStyle("Value", parent=styles["Normal"], fontSize=10,
                                  textColor=colors.HexColor("#18181b"), spaceAfter=6)
    subhead_style = ParagraphStyle("SubHead", parent=styles["Heading4"], fontSize=10.5,
                                    spaceBefore=8, spaceAfter=3, textColor=colors.HexColor("#18181b"))
    body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=13.5, spaceAfter=6)
    mono_style = ParagraphStyle("Mono", parent=styles["Normal"], fontName="Courier", fontSize=8,
                                 leading=11, textColor=colors.HexColor("#27272a"), spaceAfter=2)
    ai_badge_style = ParagraphStyle("AIBadge", parent=styles["Normal"], fontSize=7.5,
                                     textColor=colors.HexColor("#2563eb"), spaceAfter=3)
    # ReportLab's Table does NOT auto-wrap plain-string cell content — a
    # long string just overflows past the column border on one fixed-height
    # line instead of wrapping. Any cell whose text length isn't bounded
    # short must be wrapped in a Paragraph using this style so it actually
    # wraps within colWidths (verified: plain string row height stays fixed
    # regardless of content length; a Paragraph-wrapped cell grows the row).
    cell_style = ParagraphStyle("Cell", parent=styles["Normal"], fontSize=9, leading=12)
    cell_style_bold_white = ParagraphStyle("CellBoldWhite", parent=cell_style,
                                            textColor=colors.white, fontName="Helvetica-Bold")

    TIER_COLORS = {
        PriorityTier.P0: colors.HexColor("#c0392b"),
        PriorityTier.P1: colors.HexColor("#e67e22"),
        PriorityTier.P2: colors.HexColor("#f1c40f"),
        PriorityTier.P3: colors.HexColor("#27ae60"),
        PriorityTier.UNSCORED: colors.HexColor("#7f8c8d"),
    }
    TIER_LABELS = {
        PriorityTier.P0: "P0 — Critical", PriorityTier.P1: "P1 — High",
        PriorityTier.P2: "P2 — Medium", PriorityTier.P3: "P3 — Low",
        PriorityTier.UNSCORED: "Unscored",
    }

    # Both timestamps must share the same clock — session.scan_date is set
    # server-side as UTC (see pipeline.py), so "now" has to be UTC too, or
    # the two times printed on the title page look inconsistent (generation
    # appearing hours before/after ingestion) purely because of whatever
    # timezone the backend host happens to be running in.
    now = datetime.now(timezone.utc)
    generation_time_str = now.strftime("%d:%m:%Y-%H:%M:%S") + " UTC"
    report_date_str = now.strftime("%B %d, %Y")
    _scan_fmt = _format_scan_date(session.scan_date)
    scan_time_str = f"{_scan_fmt} UTC" if _scan_fmt else generation_time_str

    story = []

    # ── Title page ───────────────────────────────────────────────────────
    # The Date/Session ID/Scan Ingestion/Generation block is drawn directly
    # on the canvas near the bottom of the page (see _first_page below,
    # mirroring the reference template's bottom-anchored meta block) rather
    # than flowed here — flowing it right after "Business Confidential"
    # left a large dead gap between it and the page bottom.
    story.append(Spacer(1, 5*cm))
    story.append(_shield_logo(60, "#18181b"))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("VulneraX", wordmark_style))
    story.append(Paragraph("VULNERABILITY RISK PRIORITIZATION", tagline_style))
    story.append(Paragraph("Vulnerability Risk Assessment Report", report_title_style))
    story.append(Paragraph("Business Confidential", confidential_style))
    story.append(PageBreak())

    # ── About this report ────────────────────────────────────────────────
    story.append(Paragraph("About This Report", h2))
    story.append(Paragraph(
        "This report was generated automatically by VulneraX from vulnerability scanner output "
        f"({', '.join(t.upper() for t in session.tools_detected) or '—'}). Findings were normalized, "
        "deduplicated, filtered for false positives, enriched with live threat intelligence "
        "(NVD, EPSS, CISA KEV, Exploit-DB, GitHub proof-of-concept search), and risk-scored. "
        "It is not a substitute for manual review — a qualified security professional should validate "
        "findings, particularly anything marked Unscored or Needs Review, before remediation is prioritized.",
        normal,
    ))
    story.append(Spacer(1, 0.5*cm))

    # ── Severity / priority tier ratings ─────────────────────────────────
    story.append(Paragraph("Priority Tier Ratings", h2))
    tier_rows = [["Tier", "Meaning"]]
    tier_defs = {
        PriorityTier.P0: "Confirmed high-severity risk with active exploitation evidence (KEV listing, EPSS ≥ 0.5, or a known public exploit/PoC). Remediate immediately.",
        PriorityTier.P1: "High composite risk score, or a CWE-based finding matching a MITRE Top-25 weakness at high severity. Remediate as soon as possible.",
        PriorityTier.P2: "Moderate composite risk. Plan remediation after P0/P1 items are resolved.",
        PriorityTier.P3: "Low composite risk, or informational. Address during routine maintenance.",
        PriorityTier.UNSCORED: "No CVE or CWE to score against (e.g. an open port with no known vulnerability). Requires manual triage.",
    }
    for tier, desc in tier_defs.items():
        tier_rows.append([TIER_LABELS[tier], Paragraph(desc, cell_style)])
    tier_table = Table(tier_rows, colWidths=[3.5*cm, 12.5*cm])
    tier_style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    for i, tier in enumerate(tier_defs.keys(), start=1):
        tier_style_cmds.append(("TEXTCOLOR", (0, i), (0, i), TIER_COLORS[tier]))
        tier_style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    tier_table.setStyle(TableStyle(tier_style_cmds))
    story.append(tier_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*cm))

    # ── Executive summary ────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2))
    # Summary table
    summary_data = [
        ["Metric", "Count"],
        ["Total Raw Findings", str(session.total_raw_findings)],
        ["After Deduplication", str(session.total_after_dedup)],
        ["After FP Filter", str(session.total_after_fp_filter)],
        ["Scored Findings", str(session.total_scored)],
        ["Unscored (No CVE)", str(session.total_unscored)],
        ["Tools Used", Paragraph(", ".join(session.tools_detected) or "—", cell_style)],
    ]
    summary_table = Table(summary_data, colWidths=[8*cm, 8*cm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*cm))

    # ── Vulnerabilities by priority ──────────────────────────────────────
    story.append(Paragraph("Vulnerabilities by Priority", h2))
    tier_counts = {t: 0 for t in TIER_LABELS}
    for f in session.findings:
        tier_counts[f.risk_score.priority_tier if f.risk_score else PriorityTier.UNSCORED] += 1
    count_row = [TIER_LABELS[t] for t in tier_counts]
    value_row = [str(n) for n in tier_counts.values()]
    count_table = Table([count_row, value_row], colWidths=[3.2*cm] * len(tier_counts))
    count_style_cmds = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, 1), 16),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("TOPPADDING", (0, 1), (-1, 1), 6),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 6),
    ]
    for i, t in enumerate(tier_counts):
        count_style_cmds.append(("TEXTCOLOR", (i, 0), (i, 1), TIER_COLORS[t]))
    count_table.setStyle(TableStyle(count_style_cmds))
    story.append(count_table)
    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.3*cm))

    # ── Detailed findings (highest-risk first) ───────────────────────────
    # session.findings is already sorted by final_score descending
    # (score_all_findings), so the first N are the highest-priority ones.
    capped_findings = session.findings[:TOTAL_FINDINGS_CAP]
    # Unscored (Tier C) findings are bare open ports/unclassified results with
    # no CVE or CWE — there's no risk narrative worth an AI call, so they
    # never take a "detailed" slot even if there aren't enough scored
    # findings to fill it; they always land in the condensed section.
    scored = [f for f in capped_findings
              if f.risk_score and f.risk_score.priority_tier != PriorityTier.UNSCORED]
    scored_ids = {f.finding_id for f in scored}
    unscored = [f for f in capped_findings if f.finding_id not in scored_ids]
    detailed = scored[:DETAILED_FINDINGS_CAP]
    additional = scored[DETAILED_FINDINGS_CAP:] + unscored
    ai_content = _gather_ai_content(detailed)

    story.append(Paragraph("Detailed Findings", h2))
    story.append(Paragraph(
        f"The {len(detailed)} highest-risk finding(s) below include a full metadata "
        "breakdown, threat-intelligence signals, and an AI-generated overview and "
        "remediation grounded in this scan's data.", normal,
    ))
    story.append(Spacer(1, 0.3*cm))

    for i, f in enumerate(detailed):
        # Each detailed finding gets its own page.
        story.append(PageBreak())

        tier = f.risk_score.priority_tier if f.risk_score else PriorityTier.UNSCORED
        score = f"{f.risk_score.final_score:.1f}" if f.risk_score and f.risk_score.final_score is not None else "N/A"
        tier_color = TIER_COLORS.get(tier, colors.grey)
        host = f.asset.hostname or f.asset.ip or f.asset.domain or f.asset.url or "—"
        if f.asset.path:
            target_display = f"{host}{f.asset.path}"
        elif f.asset.url and f.asset.url != host:
            target_display = f.asset.url
        elif f.asset.port:
            target_display = f"{host}:{f.asset.port}"
        else:
            target_display = host
        # Raw scan_date can carry sub-microsecond precision or an odd offset
        # that both breaks fromisoformat and overflows the narrow DETECTED
        # column (wrapping mid-string) — reformat to something short & clean.
        detected = _format_scan_date(f.scan_date or session.scan_date, "%b %d, %Y %H:%M") or "—"

        section = []

        # Header bar: title + tier/score
        header = Table(
            [[Paragraph(f"#{i+1} · {_safe(f.vulnerability_name, 120)}", finding_title_style),
              Paragraph(f"{tier.value} · Risk {score}/100", finding_title_style)]],
            colWidths=[12.5*cm, 4.5*cm],
        )
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), tier_color),
            ("ALIGN", (1, 0), (1, 0), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (0, 0), 8), ("RIGHTPADDING", (1, 0), (1, 0), 8),
        ]))
        section.append(header)

        # Affected target / detected / severity strip
        meta = Table(
            [[Paragraph("SEVERITY", label_style), Paragraph("AFFECTED TARGET", label_style), Paragraph("DETECTED", label_style)],
             [Paragraph(_safe(f.severity.value.upper() if f.severity else "UNKNOWN"), value_style),
              Paragraph(_safe(target_display, 80), value_style),
              Paragraph(_safe(detected), value_style)]],
            colWidths=[3.5*cm, 9*cm, 4.5*cm],
        )
        meta.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e4e4e7")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4), ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ]))
        section.append(meta)

        # Identifiers line
        source_scanners = f.deduplication.source_scanners if f.deduplication else [f.source_tool.value]
        corroboration = f.deduplication.corroboration_count if f.deduplication else 1
        ident_bits = [
            f"Tool: {f.source_tool.value.upper()}",
            f"CVE: {_safe(f.cve_id) if f.cve_id else '—'}",
            f"CWE: {_safe(f.cwe_id) if f.cwe_id else '—'}",
            f"CVSS: {f.cvss.base_score if f.cvss and f.cvss.base_score is not None else '—'}",
            f"Asset criticality: {f.asset.criticality.value}",
        ]
        if corroboration > 1:
            ident_bits.append(f"Corroborated by {corroboration} scanners ({', '.join(source_scanners)})")
        section.append(Paragraph(" &nbsp;|&nbsp; ".join(ident_bits), body_style))

        # Threat intel table (CVE-based findings only)
        ti = f.threat_intel
        if ti and (ti.epss_score is not None or ti.is_kev or ti.has_public_exploit or ti.has_github_poc):
            ti_rows = [["EPSS", "KEV", "ExploitDB", "GitHub PoC"], [
                f"{ti.epss_score*100:.1f}%" if ti.epss_score is not None else "—",
                "Yes" + (f" ({ti.kev_date_added})" if ti.kev_date_added else "") if ti.is_kev else "No",
                "Yes" if ti.has_public_exploit else "No",
                "Yes" if ti.has_github_poc else "No",
            ]]
            ti_table = Table(ti_rows, colWidths=[4.25*cm]*4)
            ti_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f4f4f5")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e4e4e7")),
            ]))
            section.append(Spacer(1, 0.15*cm))
            section.append(ti_table)

        # Risk score breakdown
        if f.risk_score:
            rs = f.risk_score
            comps = []
            if rs.kev_component is not None: comps.append(("KEV", rs.kev_component))
            if rs.epss_component is not None: comps.append(("EPSS", rs.epss_component))
            if rs.exploitdb_component is not None: comps.append(("ExploitDB", rs.exploitdb_component))
            if rs.github_poc_component is not None: comps.append(("GitHub PoC", rs.github_poc_component))
            if rs.cvss_component is not None: comps.append(("CVSS", rs.cvss_component))
            if rs.cwe_component is not None: comps.append(("CWE", rs.cwe_component))
            if comps:
                section.append(Spacer(1, 0.15*cm))
                section.append(Paragraph(
                    "Risk breakdown: " + ", ".join(f"{name} {val:.0f}" for name, val in comps) +
                    f" &nbsp;-&nbsp; base {rs.base_score:.1f} × {rs.criticality_multiplier} = <b>{score}</b> "
                    f"({rs.scoring_method})", body_style,
                ))

        # AI overview + remediation
        overview, overview_ai, remediation, remediation_ai = ai_content.get(
            f.finding_id, (f.description or "—", False, f.solution or "—", False))
        # Matches the frontend finding-detail page, which just says
        # "Overview" (with a small "AI Analysis" badge) rather than putting
        # "AI-Generated" in the heading itself.
        section.append(Paragraph("Overview", subhead_style))
        if overview_ai:
            section.append(Paragraph("Generated by VulneraX AI from this finding's scan data — verify before acting.", ai_badge_style))
        section.append(Paragraph(_ai_markup(overview), body_style))

        section.append(Paragraph("AI-Recommended Remediation" if remediation_ai else "Remediation", subhead_style))
        if remediation_ai:
            section.append(Paragraph("Generated by VulneraX AI from this finding's scan data — verify before acting.", ai_badge_style))
        section.append(Paragraph(_ai_markup(remediation), body_style))

        # Evidence / instance block (web findings)
        if f.http_method or f.parameter or f.attack or f.evidence or f.asset.url:
            section.append(Paragraph("Instance", subhead_style))
            if f.asset.url:
                section.append(Paragraph(f"uri: {_safe(f.asset.url, 200)}", mono_style))
            if f.http_method:
                section.append(Paragraph(f"method: {_safe(f.http_method)}", mono_style))
            if f.parameter:
                section.append(Paragraph(f"param: {_safe(f.parameter)}", mono_style))
            if f.attack:
                section.append(Paragraph(f"attack: {_safe(f.attack, 300)}", mono_style))
            if f.evidence:
                section.append(Paragraph(f"evidence: {_safe(f.evidence, 300)}", mono_style))

        # References
        if f.references:
            section.append(Paragraph("References", subhead_style))
            for ref in f.references[:5]:
                section.append(Paragraph(_safe(ref, 150), mono_style))

        section.append(Spacer(1, 0.2*cm))
        section.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#d4d4d8")))
        section.append(Spacer(1, 0.35*cm))

        story.append(KeepTogether(section[:2]))  # keep header+meta from splitting across pages
        story.extend(section[2:])

    # ── Additional findings (condensed, no AI narrative) ─────────────────
    if additional:
        story.append(PageBreak())
        story.append(Paragraph("Additional Findings", h2))
        story.append(Paragraph(
            f"The remaining {len(additional)} lower-risk finding(s) are summarized below without "
            "AI-generated narrative, to keep report generation fast. Open any finding in VulneraX "
            "for its full AI overview and remediation guidance.", normal,
        ))
        story.append(Spacer(1, 0.3*cm))
        for i, f in enumerate(additional, start=len(detailed) + 1):
            tier = f.risk_score.priority_tier if f.risk_score else PriorityTier.UNSCORED
            score = f"{f.risk_score.final_score:.1f}" if f.risk_score and f.risk_score.final_score is not None else "N/A"
            tier_color = TIER_COLORS.get(tier, colors.grey)
            host = f.asset.hostname or f.asset.ip or f.asset.domain or "—"

            finding_data = [
                [Paragraph(f"#{i} [{tier.value}] {_safe(f.vulnerability_name, 100)}", cell_style_bold_white),
                 f"Risk: {score}/100"],
                [f"Tool: {f.source_tool.value.upper()} | Severity: {f.severity.value.upper()}",
                 Paragraph(f"Host: {_safe(host, 60)}", cell_style)],
                [f"CVE: {_safe(f.cve_id) if f.cve_id else '—'} | CWE: {_safe(f.cwe_id) if f.cwe_id else '—'}",
                 f"CVSS: {f.cvss.base_score if f.cvss and f.cvss.base_score is not None else '—'}"],
            ]
            ft = Table(finding_data, colWidths=[12*cm, 5*cm])
            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), tier_color),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.lightgrey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]))
            story.append(ft)
            if f.description:
                story.append(Paragraph(f"Description: {_safe(f.description, 300)}", normal))
            story.append(Spacer(1, 0.3*cm))

    def _footer(canvas, doc_):
        canvas.saveState()
        canvas.setStrokeColor(colors.grey)
        canvas.setLineWidth(0.5)
        canvas.line(2*cm, 1.5*cm, A4[0] - 2*cm, 1.5*cm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#808080"))
        canvas.drawCentredString(A4[0] / 2, 1.1*cm, "VulneraX — Confidential")
        canvas.drawRightString(A4[0] - 2*cm, 1.1*cm, f"Page {doc_.page}")
        canvas.restoreState()

    def _first_page(canvas, doc_):
        _footer(canvas, doc_)
        # Date / Session ID / Scan Ingestion / Generation block, anchored
        # near the bottom of the title page (mirrors the reference
        # template's bottom-left meta block) instead of flowing right below
        # "Business Confidential" with a large dead gap after it.
        canvas.saveState()
        canvas.setFont("Helvetica", 10)
        canvas.setFillColor(colors.HexColor("#18181b"))
        x, y = 2*cm, 4.6*cm
        for line in (
            f"Date: {report_date_str}",
            f"Session ID: {session.session_id}",
            f"Scan Ingestion Time: {scan_time_str}",
            f"Report Generation & Download Time: {generation_time_str}",
        ):
            canvas.drawString(x, y, line)
            y -= 0.5*cm
        canvas.restoreState()

    doc.build(story, onFirstPage=_first_page, onLaterPages=_footer)
    pdf_bytes = _compress_pdf(buffer.getvalue())

    if current_user and authorization:
        try:
            user_jwt = authorization.split(" ", 1)[1].strip()
            file_name = f"{session.session_id}.pdf"
            # Ensure the scan_sessions row exists (upserts a bare one if
            # "Store Report" was never clicked) BEFORE save_report_record,
            # since reports.session_id has a foreign key on scan_sessions —
            # PDF download must work standalone, independent of Store Report.
            mark_report_generated(session, current_user["id"])
            storage_path = upload_pdf(user_jwt, current_user["id"], file_name, pdf_bytes)
            save_report_record(current_user["id"], session.session_id, file_name, storage_path)
        except Exception as e:
            # Best-effort — the caller still gets their PDF even if the
            # Storage upload/index step fails for some reason.
            log.error(f"Failed to store report for session {session.session_id}: {e}")

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=vulnerax_report.pdf"},
    )
