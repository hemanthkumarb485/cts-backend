"""
targets.py — /api/v1/targets endpoints.
Aggregated view of scanned assets across a user's persisted scan history.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user
from app.services.persistence_service import get_targets, get_target_findings

router = APIRouter(prefix="/targets", tags=["Targets"])


@router.get("")
async def list_targets(current_user: dict = Depends(get_current_user)):
    try:
        targets = get_targets(current_user["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load targets: {e}")
    return {"count": len(targets), "targets": targets}


@router.get("/{host}/findings")
async def target_findings(host: str, current_user: dict = Depends(get_current_user)):
    try:
        findings = get_target_findings(current_user["id"], host)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load target findings: {e}")
    return {"host": host, "count": len(findings), "findings": findings}
