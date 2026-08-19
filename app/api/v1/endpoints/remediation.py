"""
remediation.py — /api/v1/remediation endpoints.
Powers the "Get AI Remediation" button on the finding detail page.
"""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user
from app.schemas.canonical import CanonicalFinding
from app.services.ai_service import suggest_remediation, generate_overview

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.post("/suggest")
async def remediation_suggest(finding: CanonicalFinding, current_user: dict = Depends(get_current_user)):
    try:
        suggestion = suggest_remediation(finding)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"suggestion": suggestion}


@router.post("/overview")
async def remediation_overview(finding: CanonicalFinding, current_user: dict = Depends(get_current_user)):
    try:
        overview = generate_overview(finding)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    return {"overview": overview}
