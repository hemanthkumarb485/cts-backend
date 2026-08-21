"""
reports.py — /api/v1/reports endpoints.
Lists a user's stored PDF reports and issues short-lived signed URLs to
download them from Supabase Storage (the bucket is private — nothing is
downloadable without a fresh signed URL, since these can contain sensitive
vulnerability details).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Header
from typing import Optional

from app.core.security import get_current_user
from app.services.persistence_service import get_reports, get_report
from app.services.storage_service import create_signed_url

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("")
async def list_reports(current_user: dict = Depends(get_current_user)):
    try:
        reports = get_reports(current_user["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load reports: {e}")
    return {"count": len(reports), "reports": reports}


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
    authorization: Optional[str] = Header(None),
):
    report = get_report(current_user["id"], report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    try:
        user_jwt = authorization.split(" ", 1)[1].strip()
        url = create_signed_url(user_jwt, report["storage_path"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create download link: {e}")
    return {"url": url, "file_name": report["file_name"]}
