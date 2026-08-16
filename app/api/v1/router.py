"""
router.py — Aggregates all v1 endpoint routers.
"""
from fastapi import APIRouter
from app.api.v1.endpoints.scan import router as scan_router
from app.api.v1.endpoints.github import router as github_router
from app.api.v1.endpoints.report import router as report_router

api_router = APIRouter()
api_router.include_router(scan_router)
api_router.include_router(github_router)
api_router.include_router(report_router)
