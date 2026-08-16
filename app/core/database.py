"""
database.py — MySQL connection stub.
DB is NOT active during stateless pipeline processing.
This module is used ONLY by the GitHub integration (token/repo/issue persistence).
Full DB initialization will be done separately via database_setup.sql.
"""
import pymysql
import pymysql.cursors
from app.core.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


def get_connection():
    """
    Returns a raw PyMySQL connection.
    Called only when GitHub integration endpoints need DB access.
    """
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
    )


def check_db_connection() -> bool:
    """
    Health check — returns True if DB is reachable, False otherwise.
    Used in /health endpoint to show DB status without crashing.
    """
    try:
        conn = get_connection()
        conn.ping(reconnect=False)
        conn.close()
        return True
    except Exception:
        return False
