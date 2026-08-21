"""
findings.py — /api/v1/findings endpoints.
Backend fallback lookup for the finding detail page, used when a finding
isn't present in the caller's current in-memory scan session (e.g. reached
via Targets, which aggregates persisted findings across all past sessions).
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user
from app.services.persistence_service import get_finding_by_id

router = APIRouter(prefix="/findings", tags=["Findings"])


@router.get("/{finding_id}")
async def get_finding(finding_id: str, current_user: dict = Depends(get_current_user)):
    try:
        finding = get_finding_by_id(current_user["id"], finding_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load finding: {e}")
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
