"""
storage_service.py — Supabase Storage client for generated PDF reports.

PDF bytes never touch a Postgres row — they're uploaded to a private
"reports" bucket, one folder per user (reports/{user_id}/...), and only the
metadata (file name, path) is stored in Postgres (see persistence_service's
save_report_record). Every call here authenticates as the calling user by
forwarding their own Supabase JWT, so Storage's RLS policies
(reports_insert_own / reports_select_own, defined in supabase_schema.sql)
enforce that a user can only ever touch their own folder — the backend
never needs (and doesn't hold) a service-role key that bypasses that.
"""
from __future__ import annotations
import requests

from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

BUCKET = "reports"
STORAGE_URL = f"{SUPABASE_URL}/storage/v1"


def _headers(user_jwt: str, content_type: str | None = None) -> dict:
    h = {"apikey": SUPABASE_ANON_KEY, "Authorization": f"Bearer {user_jwt}"}
    if content_type:
        h["Content-Type"] = content_type
    return h


def upload_pdf(user_jwt: str, user_id: str, file_name: str, pdf_bytes: bytes) -> str:
    """Uploads a PDF to reports/{user_id}/{file_name} and returns the storage path."""
    storage_path = f"{user_id}/{file_name}"
    resp = requests.post(
        f"{STORAGE_URL}/object/{BUCKET}/{storage_path}",
        headers=_headers(user_jwt, "application/pdf"),
        data=pdf_bytes,
        params={"upsert": "true"},
        timeout=30,
    )
    if not resp.ok:
        raise RuntimeError(f"Supabase Storage upload failed ({resp.status_code}): {resp.text}")
    return storage_path


def create_signed_url(user_jwt: str, storage_path: str, expires_in: int = 300) -> str:
    """Returns a short-lived signed URL for downloading a private report."""
    resp = requests.post(
        f"{STORAGE_URL}/object/sign/{BUCKET}/{storage_path}",
        headers=_headers(user_jwt, "application/json"),
        json={"expiresIn": expires_in},
        timeout=15,
    )
    if not resp.ok:
        raise RuntimeError(f"Failed to create signed URL ({resp.status_code}): {resp.text}")
    signed = resp.json().get("signedURL")
    if not signed:
        raise RuntimeError("Supabase Storage returned no signedURL")
    return f"{STORAGE_URL}{signed}" if signed.startswith("/") else signed
