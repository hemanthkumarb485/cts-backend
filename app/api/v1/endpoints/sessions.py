"""
sessions.py — /api/v1/sessions endpoints.
Powers the "Session History" page: for a logged-in user, when they uploaded
scans, which tools were involved, and when (if ever) a PDF report was
generated for each session.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user
from app.services.persistence_service import get_sessions

router = APIRouter(prefix="/sessions", tags=["Sessions"])


@router.get("")
async def list_sessions(current_user: dict = Depends(get_current_user)):
    try:
        sessions = get_sessions(current_user["id"])
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load session history: {e}")
    return {"user_id": current_user["id"], "count": len(sessions), "sessions": sessions}
