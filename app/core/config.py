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

# --- MySQL ---
DB_HOST: str = os.getenv("DB_HOST", "localhost")
DB_PORT: int = int(os.getenv("DB_PORT", "3306"))
DB_NAME: str = os.getenv("DB_NAME", "vulnrisk_db")
DB_USER: str = os.getenv("DB_USER", "root")
DB_PASSWORD: str = os.getenv("DB_PASSWORD", "")

# --- NVD API ---
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# --- EPSS API ---
EPSS_API_URL: str = "https://api.first.org/data/v1/epss"

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

