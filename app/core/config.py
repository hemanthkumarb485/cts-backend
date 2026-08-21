"""
VulnRisk — App Configuration
Loads all settings from .env file via python-dotenv
"""
import os
from dotenv import load_dotenv

load_dotenv()

# --- App ---
APP_NAME: str = os.getenv("APP_NAME", "VulnRisk Prioritization System")
APP_VERSION: str = os.getenv("APP_VERSION", "1.0.0")
DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"

# --- Supabase / Postgres ---
# Auth tokens are verified via Supabase's public JWKS endpoint (see
# app/core/security.py) — no shared JWT secret needs to be stored here.
DATABASE_URL: str = os.getenv("DATABASE_URL", "")
SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
# The publishable/anon key — safe to be public, required as the `apikey`
# header on Supabase Storage REST calls (see app/services/storage_service.py).
# We upload/download as the calling user via their own JWT, not this key —
# this just identifies the project, it never bypasses Storage RLS.
SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")

# --- Groq (remediation suggestions / ticket description enhancement) ---
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

# --- NVD API ---
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- EPSS API ---
EPSS_API_URL: str = "https://api.first.org/data/v1/epss"

# --- GitHub Search (unauthenticated PoC lookup) ---
GITHUB_SEARCH_API_URL: str = "https://api.github.com/search/repositories"

# --- GitHub OAuth ---
GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI: str = os.getenv(
    "GITHUB_REDIRECT_URI", "http://localhost:8000/api/v1/github/callback"
)

# --- Security ---
SECRET_KEY: str = os.getenv("SECRET_KEY", "changeme_minimum_32_characters_long_secret")

# --- CORS ---
FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")
ALLOWED_ORIGINS: list = [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
]

# --- Data file paths ---
BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_DIR: str = os.path.join(BASE_DIR, "data")
KEV_FILE: str = os.path.join(DATA_DIR, "known_exploited_vulnerabilities.json")
EXPLOITDB_FILE: str = os.path.join(DATA_DIR, "files_exploits.csv")

# --- File Upload ---
MAX_UPLOAD_SIZE_MB: int = int(os.getenv("MAX_UPLOAD_SIZE_MB", "1024"))
UPLOAD_TEMP_DIR: str = os.path.join(BASE_DIR, "tmp", "uploads")
