"""
db.py — Supabase Postgres connection helper.
Used by github_service.py and persistence_service.py for all DB access.
"""
import psycopg2
import psycopg2.extras
from app.core.config import DATABASE_URL


def get_connection():
    """Returns a raw psycopg2 connection with dict-row cursors."""
    return psycopg2.connect(
        DATABASE_URL,
        sslmode="require",
        cursor_factory=psycopg2.extras.RealDictCursor,
    )


def check_db_connection() -> bool:
    """Health check — returns True if DB is reachable, False otherwise."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception:
        return False
