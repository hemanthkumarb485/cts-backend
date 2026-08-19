"""
main.py — FastAPI application entry point.
DB is NOT initialized on startup — stateless pipeline only.
Supabase Postgres is used for GitHub integration + persisted scan results.
"""
import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.router import api_router
from app.core.config import APP_NAME, APP_VERSION, ALLOWED_ORIGINS, UPLOAD_TEMP_DIR
from app.core.db import check_db_connection

# Ensure temp upload dir exists
os.makedirs(UPLOAD_TEMP_DIR, exist_ok=True)

app = FastAPI(
    title=APP_NAME,
    description=(
        "Vulnerability Risk Prioritization & Ticketing System.\n\n"
        "Parses results from ZAP, Nuclei, OpenVAS, Nmap — normalizes, deduplicates, "
        "enriches with NVD/EPSS/KEV/ExploitDB, scores (0-100), and assigns P0-P3 tiers.\n\n"
        "GitHub Issues integration for one-click ticket creation."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routes ───────────────────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")


# ─── Health ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    db_status = check_db_connection()
    return {
        "status": "online",
        "app": APP_NAME,
        "version": APP_VERSION,
        "database": "connected" if db_status else "not configured (stateless mode active)",
        "pipeline": "ready",
        "supported_tools": ["zap", "nuclei", "openvas", "nmap"],
    }


@app.get("/", tags=["Root"])
async def root():
    return {
        "message": f"Welcome to {APP_NAME}",
        "docs": "/docs",
        "health": "/health",
    }
