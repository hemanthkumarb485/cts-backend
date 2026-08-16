"""
report.py — /api/v1/report endpoints.
GET /export/json  → Returns ScanSession findings as JSON
POST /export/pdf  → Generates PDF report using PyMuPDF/ReportLab
"""
from __future__ import annotations
import json
import io
from typing import Optional
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from app.schemas.canonical import ScanSession, CanonicalFinding, PriorityTier

router = APIRouter(prefix="/report", tags=["Report"])


@router.post("/export/json")
async def export_json(session: ScanSession):
    """Return the ScanSession as a downloadable JSON file."""
    content = session.model_dump_json(indent=2)
    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulnrisk_report.json"},
    )


@router.post("/export/pdf")
async def export_pdf(session: ScanSession):
    """Generate and return a PDF report from a ScanSession."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Table, TableStyle,
            Spacer, HRFlowable, PageBreak,
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

    TIER_COLORS = {
        PriorityTier.P0: colors.HexColor("#c0392b"),
        PriorityTier.P1: colors.HexColor("#e67e22"),
        PriorityTier.P2: colors.HexColor("#f1c40f"),
        PriorityTier.P3: colors.HexColor("#27ae60"),
        PriorityTier.UNSCORED: colors.HexColor("#7f8c8d"),
    }

    story = []

    # Title
    story.append(Paragraph("VulnRisk Prioritization Report", title_style))
    story.append(Paragraph(f"Session ID: {session.session_id}", normal))
    story.append(Spacer(1, 0.3*cm))

    # Summary table
    summary_data = [
        ["Metric", "Count"],
        ["Total Raw Findings", str(session.total_raw_findings)],
        ["After Deduplication", str(session.total_after_dedup)],
        ["After FP Filter", str(session.total_after_fp_filter)],
        ["Scored Findings", str(session.total_scored)],
        ["Unscored (No CVE)", str(session.total_unscored)],
        ["Tools Used", ", ".join(session.tools_detected)],
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

    # Findings
    story.append(Paragraph("Findings", h2))
    for i, f in enumerate(session.findings[:100]):  # Cap at 100 for PDF size
        tier = f.risk_score.priority_tier if f.risk_score else PriorityTier.UNSCORED
        score = f"{f.risk_score.final_score:.1f}" if f.risk_score and f.risk_score.final_score else "N/A"
        tier_color = TIER_COLORS.get(tier, colors.grey)
        host = f.asset.hostname or f.asset.ip or f.asset.domain or "—"

        finding_data = [
            [f"#{i+1} [{tier.value}] {f.vulnerability_name}", f"Risk: {score}/100"],
            [f"Tool: {f.source_tool.value.upper()} | Severity: {f.severity.value.upper()}",
             f"Host: {host}"],
            [f"CVE: {f.cve_id or '—'} | CWE: {f.cwe_id or '—'}",
             f"CVSS: {f.cvss.base_score if f.cvss else '—'}"],
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
            story.append(Paragraph(f"Description: {f.description[:300]}{'...' if len(f.description)>300 else ''}", normal))
        story.append(Spacer(1, 0.3*cm))

    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=vulnrisk_report.pdf"},
    )
