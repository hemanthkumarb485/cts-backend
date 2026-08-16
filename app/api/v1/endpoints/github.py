"""
github.py — GitHub OAuth + Issues API endpoints.
Tokens stored encrypted in MySQL. Issues tracked in MySQL.
"""
from __future__ import annotations
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.responses import RedirectResponse

from fastapi.responses import RedirectResponse, HTMLResponse
from pydantic import BaseModel
from app.services.github_service import (
    get_oauth_url, exchange_code_for_token, get_github_user,
    get_github_scopes, list_user_repos, create_github_issue, _encrypt, _decrypt,
    save_github_connection,
)
from app.schemas.canonical import CreateIssueRequest, CreateIssueResponse

router = APIRouter(prefix="/github", tags=["GitHub"])


class ConnectPATRequest(BaseModel):
    pat: str


# ─── OAuth ────────────────────────────────────────────────────────────────────

@router.get("/login")
async def github_login():
    """Redirect user to GitHub OAuth login page."""
    import secrets
    state = secrets.token_hex(16)
    url = get_oauth_url(state=state)
    return {"oauth_url": url, "state": state}


@router.get("/callback", response_class=HTMLResponse)
async def github_callback(code: str = Query(...), state: str = Query("")):
    """
    Handle GitHub OAuth callback.
    Exchanges code for token, stores in MySQL, and returns an HTML page that communicates
    with the opener window via postMessage and then closes itself.
    """
    token, scope = exchange_code_for_token(code)
    if not token:
        return HTMLResponse(
            status_code=400,
            content="<html><body><h2>GitHub OAuth failed — no token received.</h2></body></html>"
        )

    user = get_github_user(token)
    if not user:
        return HTMLResponse(
            status_code=400,
            content="<html><body><h2>Could not fetch GitHub user info.</h2></body></html>"
        )

    encrypted_token = _encrypt(token)

    # Persist to MySQL github_connections table
    try:
        save_github_connection(
            user_id=user.get("id"),
            username=user.get("login"),
            email=user.get("email"),
            encrypted_token=encrypted_token,
            scope=scope
        )
    except Exception as e:
        # Log database errors but don't completely block user session
        print(f"Error persisting github connection in callback: {e}")

    # Return HTML that sends token to parent window via postMessage
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>GitHub Connected</title>
        <style>
            body {{
                background-color: #0f172a;
                color: #f1f5f9;
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
            }}
            .spinner {{
                border: 4px solid rgba(255,255,255,0.1);
                width: 36px;
                height: 36px;
                border-radius: 50%;
                border-left-color: #6366f1;
                animation: spin 1s linear infinite;
                margin-bottom: 20px;
            }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
    </head>
    <body>
        <div class="spinner"></div>
        <h2>GitHub Connected Successfully!</h2>
        <p>Connecting {user.get("login")}... This window will close automatically.</p>
        <script>
            const data = {{
                type: "github-connected",
                github_username: "{user.get("login")}",
                encrypted_token: "{encrypted_token}"
            }};
            if (window.opener) {{
                window.opener.postMessage(data, "*");
            }}
            setTimeout(() => window.close(), 1000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@router.post("/connect-pat")
async def connect_pat(req: ConnectPATRequest):
    """
    Validate a raw GitHub Personal Access Token (PAT),
    encrypt it, store it in MySQL, and return connection details.
    """
    token = req.pat.strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token cannot be empty")

    user = get_github_user(token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid GitHub Personal Access Token.")

    encrypted_token = _encrypt(token)

    # Check classic-token scopes — warn early if 'repo' (issues write) is missing.
    scopes = get_github_scopes(token)
    warning = None
    if scopes:
        if "repo" not in scopes and "public_repo" not in scopes:
            warning = ("This classic token has scope(s): " + ", ".join(scopes) +
                       ". It cannot create issues. Regenerate it with the 'repo' scope "
                       "(or 'public_repo' for public repos only).")
    else:
        # Fine-grained token — permissions are per-repo; remind the user.
        warning = ("Fine-grained token detected (or scope header unavailable). Make sure it has "
                   "'Issues: Read and write' permission on the repository you will select.")

    # Save connection to MySQL (non-fatal — OAuth flow tolerates DB being down)
    try:
        save_github_connection(
            user_id=user.get("id"),
            username=user.get("login"),
            email=user.get("email"),
            encrypted_token=encrypted_token,
            scope="pat"
        )
    except Exception as e:
        print(f"Error persisting github connection (PAT): {e}")

    return {
        "status": "connected",
        "github_username": user.get("login"),
        "github_user_id": user.get("id"),
        "github_email": user.get("email"),
        "scope": "pat",
        "encrypted_token": encrypted_token,
        "message": "GitHub connected successfully using PAT.",
        "warning": warning,
    }



# ─── Repositories ─────────────────────────────────────────────────────────────

@router.get("/repositories")
async def get_repositories(encrypted_token: str = Query(...)):
    """List all repos for the connected GitHub user."""
    token = _decrypt(encrypted_token)
    repos = list_user_repos(token)
    return {
        "count": len(repos),
        "repositories": [
            {
                "repo_id": r.get("id"),
                "name": r.get("name"),
                "full_name": r.get("full_name"),
                "is_private": r.get("private", False),
                "url": r.get("html_url"),
                "description": r.get("description"),
            }
            for r in repos
        ]
    }


# ─── Create Issue ─────────────────────────────────────────────────────────────

@router.post("/issues/create", response_model=CreateIssueResponse)
async def create_issue(
    req: CreateIssueRequest,
    encrypted_token: str = Query(...),
):
    """
    Create a GitHub issue from a CanonicalFinding.
    The issue body is auto-generated with full vuln details, threat intel, and risk score.
    """
    token = _decrypt(encrypted_token)
    try:
        result = create_github_issue(token, req)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return CreateIssueResponse(success=False, error=f"Unexpected error creating issue: {e}")

    if result.success:
        # TODO: Persist to MySQL github_issues table when DB is ready
        pass

    return result


@router.get("/issues/{issue_number}")
async def get_issue(
    issue_number: int,
    repo_full_name: str = Query(...),
    encrypted_token: str = Query(...),
):
    """Fetch a GitHub issue by number."""
    import requests
    from app.services.github_service import GITHUB_API_BASE
    token = _decrypt(encrypted_token)
    resp = requests.get(
        f"{GITHUB_API_BASE}/repos/{repo_full_name}/issues/{issue_number}",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        timeout=10,
    )
    if not resp.ok:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    data = resp.json()
    return {
        "issue_number": data.get("number"),
        "title": data.get("title"),
        "status": data.get("state"),
        "url": data.get("html_url"),
        "created_at": data.get("created_at"),
        "assignees": [a.get("login") for a in data.get("assignees", [])],
        "labels": [l.get("name") for l in data.get("labels", [])],
    }
