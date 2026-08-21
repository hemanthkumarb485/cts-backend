"""
security.py — Verifies Supabase Auth JWTs sent by the frontend.
The frontend signs in with @supabase/supabase-js and sends the resulting
access token as `Authorization: Bearer <token>`.

This project uses Supabase's asymmetric JWT signing keys (ES256/ECC), not
the legacy shared HS256 secret — so tokens are verified against Supabase's
public JWKS endpoint rather than a shared secret we'd have to store.
"""
from __future__ import annotations
import time
from typing import Optional
import requests
from fastapi import Header, HTTPException
from jose import jwt, JWTError

from app.core.config import SUPABASE_URL

JWKS_URL = f"{SUPABASE_URL}/auth/v1/.well-known/jwks.json"
JWKS_CACHE_TTL = 3600  # seconds

_jwks_cache: dict = {"keys": [], "fetched_at": 0.0}


def _get_jwks() -> list:
    now = time.time()
    if not _jwks_cache["keys"] or (now - _jwks_cache["fetched_at"]) > JWKS_CACHE_TTL:
        resp = requests.get(JWKS_URL, timeout=10)
        resp.raise_for_status()
        _jwks_cache["keys"] = resp.json().get("keys", [])
        _jwks_cache["fetched_at"] = now
    return _jwks_cache["keys"]


def _find_key(kid: str, refreshed: bool = False) -> Optional[dict]:
    for key in _get_jwks():
        if key.get("kid") == kid:
            return key
    if not refreshed:
        # kid not found — force a cache refresh once in case of key rotation.
        _jwks_cache["fetched_at"] = 0.0
        return _find_key(kid, refreshed=True)
    return None


def verify_supabase_jwt(token: str) -> dict:
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        alg = header.get("alg", "ES256")
        key = _find_key(kid) if kid else None
        if key is None:
            raise HTTPException(status_code=401, detail="Unknown signing key (kid) — could not verify token")
        payload = jwt.decode(
            token,
            key,
            algorithms=[alg],
            audience="authenticated",
        )
    except HTTPException:
        raise
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid or expired token: {e}")
    if not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Token missing subject claim")
    return payload


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token> header")
    token = authorization.split(" ", 1)[1].strip()
    payload = verify_supabase_jwt(token)
    return {"id": payload["sub"], "email": payload.get("email")}


async def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[dict]:
    """Like get_current_user, but returns None instead of 401 when there's no
    (or an invalid) token — for endpoints that work anonymously but do
    something extra when the caller happens to be logged in."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = verify_supabase_jwt(token)
    except HTTPException:
        return None
    return {"id": payload["sub"], "email": payload.get("email")}
