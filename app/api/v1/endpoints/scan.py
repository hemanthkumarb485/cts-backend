"""
scan.py — /api/v1/scan endpoints.
POST /upload      → Upload files per-tool, returns SSE stream with progress + final JSON
POST /process     → Synchronous process (for testing)
"""
from __future__ import annotations
import json
import logging
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from app.services.pipeline import run_pipeline_sse, run_pipeline
from app.schemas.canonical import ScanSession
from app.core.security import get_current_user
from app.services.persistence_service import save_scan_session

log = logging.getLogger("scan_endpoint")

router = APIRouter(prefix="/scan", tags=["Scan"])

ALLOWED_TOOLS = {"zap", "nuclei", "openvas", "nmap"}
ALLOWED_FORMATS = {
    "zap": ["sarif", "xml", "json"],
    "nuclei": ["jsonl", "json", "sarif", "markdown"],
    "openvas": ["xml"],
    "nmap": ["xml", "normal", "grepable"],
}
MAX_SIZE_BYTES = 1024 * 1024 * 1024  # 1 GB


async def _read_file_content(upload: UploadFile) -> str:
    """Read uploaded file — handle both text and binary (for PDF/HTML via Playwright)."""
    raw = await upload.read()
    filename = (upload.filename or "").lower()

    if filename.endswith(".pdf"):
        return await _extract_pdf(raw)
    if filename.endswith(".html") or filename.endswith(".htm"):
        return await _extract_html(raw.decode("utf-8", errors="replace"))

    return raw.decode("utf-8", errors="replace")


async def _extract_pdf(raw: bytes) -> str:
    """Extract text from PDF using PyMuPDF (fitz)."""
    try:
        import fitz  # PyMuPDF
        doc = fitz.open(stream=raw, filetype="pdf")
        text = "\n".join(page.get_text() for page in doc)
        return text
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"PDF extraction failed: {e}")


async def _extract_html(html: str) -> str:
    """Extract text from HTML using BeautifulSoup."""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        return soup.get_text(separator="\n")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"HTML extraction failed: {e}")


@router.post("/upload")
async def upload_and_process(
    # Each tool gets its own file + format selection
    zap_file: Optional[UploadFile] = File(None),
    zap_format: Optional[str] = Form(None),
    nuclei_file: Optional[UploadFile] = File(None),
    nuclei_format: Optional[str] = Form(None),
    openvas_file: Optional[UploadFile] = File(None),
    openvas_format: Optional[str] = Form("xml"),
    nmap_file: Optional[UploadFile] = File(None),
    nmap_format: Optional[str] = Form(None),
    # Asset criticality per scan session
    asset_criticality: str = Form("unknown"),
    current_user: dict = Depends(get_current_user),
):
    """
    Upload scan results for one or more tools.
    Returns an SSE stream with real-time progress updates.
    Final event contains the complete ScanSession JSON.
    """
    files = []
    pairs = [
        ("zap", zap_file, zap_format),
        ("nuclei", nuclei_file, nuclei_format),
        ("openvas", openvas_file, openvas_format),
        ("nmap", nmap_file, nmap_format),
    ]

    for tool, upload, fmt in pairs:
        if upload is None:
            continue
        content = await _read_file_content(upload)
        resolved_fmt = (fmt or "").lower().strip() or "auto"
        files.append({
            "tool": tool,
            "fmt": resolved_fmt,
            "content": content,
            "filename": upload.filename or f"{tool}_file",
            "criticality": asset_criticality,
        })

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded. Provide at least one scanner result.")

    return EventSourceResponse(run_pipeline_sse(files, user_id=current_user["id"]))


@router.post("/process", response_model=ScanSession)
async def process_sync(
    zap_file: Optional[UploadFile] = File(None),
    zap_format: Optional[str] = Form(None),
    nuclei_file: Optional[UploadFile] = File(None),
    nuclei_format: Optional[str] = Form(None),
    openvas_file: Optional[UploadFile] = File(None),
    openvas_format: Optional[str] = Form("xml"),
    nmap_file: Optional[UploadFile] = File(None),
    nmap_format: Optional[str] = Form(None),
    asset_criticality: str = Form("unknown"),
    current_user: dict = Depends(get_current_user),
):
    """Synchronous version — returns ScanSession JSON directly (no SSE)."""
    files = []
    pairs = [("zap", zap_file, zap_format), ("nuclei", nuclei_file, nuclei_format),
             ("openvas", openvas_file, openvas_format), ("nmap", nmap_file, nmap_format)]
    for tool, upload, fmt in pairs:
        if upload is None: continue
        content = await _read_file_content(upload)
        files.append({"tool": tool, "fmt": (fmt or "auto").lower().strip(),
                       "content": content, "filename": upload.filename or f"{tool}_file",
                       "criticality": asset_criticality})
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded.")
    session = run_pipeline(files)
    try:
        save_scan_session(session, current_user["id"])
    except Exception as e:
        log.error(f"Failed to persist scan session {session.session_id}: {e}")
    return session
