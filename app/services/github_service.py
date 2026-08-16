"""
github_service.py — GitHub Issues API integration.
Creates richly-formatted issues from CanonicalFinding objects.
Tokens are encrypted before MySQL storage.
"""
from __future__ import annotations
from typing import List, Optional, Tuple
import requests

from app.core.config import GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_REDIRECT_URI, SECRET_KEY
from app.schemas.canonical import CanonicalFinding, CreateIssueRequest, CreateIssueResponse

GITHUB_OAUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_BASE = "https://api.github.com"


def _encrypt(token: str) -> str:
    try:
        from cryptography.fernet import Fernet
        import base64, hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
        return Fernet(key).encrypt(token.encode()).decode()
    except Exception: return token


def _decrypt(enc: str) -> str:
    try:
        from cryptography.fernet import Fernet
        import base64, hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
        return Fernet(key).decrypt(enc.encode()).decode()
    except Exception: return enc


def get_oauth_url(state: str = "") -> str:
    return (f"{GITHUB_OAUTH_URL}?client_id={GITHUB_CLIENT_ID}"
            f"&redirect_uri={GITHUB_REDIRECT_URI}&scope=repo+read:user+user:email&state={state}")


def exchange_code_for_token(code: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        resp = requests.post(GITHUB_TOKEN_URL, headers={"Accept": "application/json"},
            data={"client_id": GITHUB_CLIENT_ID, "client_secret": GITHUB_CLIENT_SECRET,
                  "code": code, "redirect_uri": GITHUB_REDIRECT_URI}, timeout=15)
        data = resp.json()
    except Exception:
        return None, None
    return data.get("access_token"), data.get("scope")


def get_github_user(token: str) -> Optional[dict]:
    try:
        resp = requests.get(f"{GITHUB_API_BASE}/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}, timeout=10)
        return resp.json() if resp.ok else None
    except Exception:
        return None


def get_github_scopes(token: str) -> List[str]:
    """
    Return the scopes granted to a classic PAT (from the X-OAuth-Scopes header).
    Fine-grained tokens return an empty list — their permissions can't be
    introspected this way, so they are treated as 'unknown / per-repo config'.
    """
    try:
        resp = requests.get(f"{GITHUB_API_BASE}/user",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}, timeout=10)
        if resp.ok:
            scopes = resp.headers.get("X-OAuth-Scopes", "")
            return [s.strip().lower() for s in scopes.split(",") if s.strip()]
    except Exception:
        pass
    return []


def list_user_repos(token: str) -> List[dict]:
    repos, page = [], 1
    while True:
        resp = requests.get(f"{GITHUB_API_BASE}/user/repos",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
            params={"per_page": 50, "page": page, "sort": "updated"}, timeout=15)
        if not resp.ok: break
        batch = resp.json()
        repos.extend(batch)
        if len(batch) < 50: break
        page += 1
    return repos


def build_issue_body(finding: CanonicalFinding) -> str:
    ti = finding.threat_intel
    risk = finding.risk_score
    asset = finding.asset
    def row(l, v): return f"| **{l}** | {v or '—'} |"
    def f1(v): return f"{v:.1f}" if v is not None else "—"
    def f2(v): return f"{v:.2f}" if v is not None else "—"
    severity = (finding.severity.value if finding.severity else "UNKNOWN").upper()
    lines = [
        f"## 🔴 {finding.vulnerability_name}", "",
        "### 📋 Summary", "", "| Field | Value |", "|---|---|",
        row("Priority", risk.priority_tier.value if risk and risk.priority_tier else "UNSCORED"),
        row("Severity", severity),
        row("Risk Score", f"{risk.final_score:.1f}/100" if risk and risk.final_score is not None else "N/A"),
        row("Source Tool", finding.source_tool.value.upper() if finding.source_tool else "—"),
        row("CVE ID", finding.cve_id or "—"), row("CWE ID", finding.cwe_id or "—"),
        row("CVSS Score", str(finding.cvss.base_score) if finding.cvss and finding.cvss.base_score is not None else "—"), "",
        "### 🎯 Affected Asset", "", "| Field | Value |", "|---|---|",
        row("Host/Domain", asset.hostname or asset.domain or asset.ip or "—"),
        row("IP", asset.ip or "—"), row("Port", str(asset.port) if asset.port else "—"),
        row("URL", asset.url or "—"),
        row("Asset Criticality", asset.criticality.value if asset.criticality else "unknown"), "",
    ]
    if finding.description:
        lines += ["### 📝 Description", "", finding.description, ""]
    if ti:
        lines += [
            "### 🛡️ Threat Intelligence", "", "| Signal | Value |", "|---|---|",
            row("🚨 CISA KEV", "✅ YES — Actively Exploited" if ti.is_kev else "❌ No"),
            row("KEV Date Added", ti.kev_date_added or "—"),
            row("KEV Ransomware", ti.kev_ransomware_use or "—"),
            row("EPSS Score", f"{ti.epss_score:.4f} ({ti.epss_score*100:.1f}%)" if ti.epss_score else "0.0000"),
            row("💣 Public Exploit", "✅ YES" if ti.has_public_exploit else "❌ No"),
            row("Exploit IDs", ", ".join(ti.exploit_ids or []) or "—"), "",
        ]
    if risk:
        method = (risk.scoring_method or "").lower()
        if method == "cve_based":
            lines += [
                "### 📊 Risk Score Breakdown (CVE)", "",
                "| Component | Score | Weight | Contribution |", "|---|---|---|---|",
                f"| CVSS | {f1(risk.cvss_component)}/100 | 40% | {f2((risk.cvss_component or 0)*0.40)} |",
                f"| KEV | {f1(risk.kev_component)}/100 | 25% | {f2((risk.kev_component or 0)*0.25)} |",
                f"| EPSS | {f1(risk.epss_component)}/100 | 20% | {f2((risk.epss_component or 0)*0.20)} |",
                f"| ExploitDB | {f1(risk.exploitdb_component)}/100 | 15% | {f2((risk.exploitdb_component or 0)*0.15)} |",
                f"| **Base Score** | | | **{f2(risk.base_score)}** |",
                f"| **Criticality ×** | | | **×{risk.criticality_multiplier or 1.0}** |",
                f"| **Final Score** | | | **{f1(risk.final_score)}/100** |", "",
            ]
        elif method == "cwe_estimated":
            lines += [
                "### 📊 Risk Score Breakdown (CWE-estimated)", "",
                "No CVE — scored from CWE. Severity×0.55 + CWE Top-25×0.30 + ExploitDB×0.15.",
                "",
                "| Component | Score | Contribution |", "|---|---|---|",
                f"| Severity (×0.55) | {f1(risk.cwe_component)} | {f2((risk.cwe_component or 0)*0.55)} |",
                f"| CWE Top-25 (×0.30) | {f1(risk.cwe_component)} | {f2((risk.cwe_component or 0)*0.30)} |",
                f"| ExploitDB (×0.15) | {f1(risk.cwe_component)} | {f2((risk.cwe_component or 0)*0.15)} |",
                f"| **Base Score** | | **{f2(risk.base_score)}** |",
                f"| **Criticality ×** | | **×{risk.criticality_multiplier or 1.0}** |",
                f"| **Final Score** | | **{f1(risk.final_score)}/100** |", "",
            ]
        else:
            lines += [
                "### 📊 Risk Score", "",
                f"Priority: {risk.priority_tier.value if risk.priority_tier else 'UNSCORED'} · "
                f"Final score: {f1(risk.final_score)}/100",
                "",
            ]
    if finding.solution:
        lines += ["### 🔧 Remediation", "", finding.solution, ""]
    if finding.evidence:
        lines += ["### 🔍 Evidence", "", f"```\n{finding.evidence}\n```", ""]
    if finding.references:
        lines += ["### 🔗 References", ""] + [f"- {r}" for r in finding.references] + [""]
    lines += ["---", f"*VulnRisk System | Finding ID: `{finding.finding_id}`*"]
    return "\n".join(lines)


def _github_error_message(resp: requests.Response, repo_full_name: str = "") -> str:
    """Translate GitHub API errors into actionable guidance."""
    status = resp.status_code
    text = resp.text[:300]
    if status == 403 and "Resource not accessible by personal access token" in text:
        return (
            "GitHub 403: your token can't create issues on this repo. "
            "Use a fine-grained PAT with repository permission 'Issues: Read and write' "
            "selected for this repo (or all repos), or a classic token with the 'repo' "
            "scope ('public_repo' for public repos only). Reconnect GitHub after fixing the token. "
            f"API: {text}"
        )
    if status == 401:
        return f"GitHub 401: token is invalid or expired. Reconnect GitHub. API: {text}"
    if status == 404:
        return (f"GitHub 404: repo '{repo_full_name}' not found or not accessible with this token. "
                f"API: {text}")
    if status == 422:
        return f"GitHub 422: issue payload rejected (e.g. invalid assignee/labels). API: {text}"
    return f"GitHub API {status}: {text}"


def create_github_issue(token: str, req: CreateIssueRequest) -> CreateIssueResponse:
    finding = req.finding_data
    tier = finding.risk_score.priority_tier.value if finding.risk_score else "VULN"
    host = finding.asset.hostname or finding.asset.ip or "Unknown"
    title = f"[{tier}] {finding.vulnerability_name} — {host}"
    payload = {"title": title, "body": build_issue_body(finding),
               "labels": req.labels or ["security", "vulnerability"]}
    if req.assignee: payload["assignees"] = [req.assignee]
    resp = requests.post(f"{GITHUB_API_BASE}/repos/{req.repo_full_name}/issues",
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
        json=payload, timeout=20)
    if resp.ok:
        data = resp.json()
        # Save to DB asynchronously/inline
        try:
            save_github_issue_and_repo(
                token=token,
                repo_full_name=req.repo_full_name,
                finding_id=req.finding_id,
                issue_number=data.get("number"),
                issue_url=data.get("html_url"),
                issue_title=title,
                assignee=req.assignee,
                labels=req.labels,
                milestone=req.milestone
            )
        except Exception as db_err:
            print(f"Failed to persist GitHub issue in DB: {db_err}")
        return CreateIssueResponse(success=True, issue_number=data.get("number"),
                                   issue_url=data.get("html_url"), issue_title=title)
    return CreateIssueResponse(success=False, error=_github_error_message(resp, req.repo_full_name))


def save_github_connection(user_id: int, username: str, email: Optional[str], encrypted_token: str, scope: Optional[str]):
    from app.core.database import get_connection
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO github_connections (github_user_id, github_username, github_email, access_token_encrypted, token_scope)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    github_username = VALUES(github_username),
                    github_email = VALUES(github_email),
                    access_token_encrypted = VALUES(access_token_encrypted),
                    token_scope = VALUES(token_scope)
            """
            cursor.execute(sql, (user_id, username, email, encrypted_token, scope))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def save_github_issue_and_repo(token: str, repo_full_name: str, finding_id: str, issue_number: int, issue_url: str, issue_title: str, assignee: Optional[str], labels: Optional[List[str]], milestone: Optional[str]):
    from app.core.database import get_connection
    import json
    
    # 1. Fetch user info to get github_user_id
    user = get_github_user(token)
    if not user:
        return
    github_user_id = user.get("id")
    
    # 2. Get connection_id from github_connections
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id FROM github_connections WHERE github_user_id = %s", (github_user_id,))
            row = cursor.fetchone()
            if not row:
                return
            connection_id = row["id"]
            
            # 3. Fetch repo details from GitHub to populate github_repositories
            resp = requests.get(f"{GITHUB_API_BASE}/repos/{repo_full_name}",
                                headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json"},
                                timeout=10)
            if not resp.ok:
                return
            repo_data = resp.json()
            repo_id = repo_data.get("id")
            repo_name = repo_data.get("name")
            is_private = 1 if repo_data.get("private") else 0
            repo_url = repo_data.get("html_url")
            
            # 4. Insert or Update github_repositories
            cursor.execute("""
                INSERT INTO github_repositories (connection_id, repo_id, repo_name, repo_full_name, is_private, repo_url)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    repo_name = VALUES(repo_name),
                    repo_full_name = VALUES(repo_full_name),
                    is_private = VALUES(is_private),
                    repo_url = VALUES(repo_url)
            """, (connection_id, repo_id, repo_name, repo_full_name, is_private, repo_url))
            
            # Get the repo's DB id
            cursor.execute("SELECT id FROM github_repositories WHERE connection_id = %s AND repo_id = %s", (connection_id, repo_id))
            repo_row = cursor.fetchone()
            if not repo_row:
                return
            repository_id = repo_row["id"]
            
            # 5. Insert into github_issues
            labels_json = json.dumps(labels or [])
            cursor.execute("""
                INSERT INTO github_issues (connection_id, repository_id, finding_id, issue_number, issue_url, issue_title, status, assignee, labels, milestone)
                VALUES (%s, %s, %s, %s, %s, %s, 'open', %s, %s, %s)
            """, (connection_id, repository_id, finding_id, issue_number, issue_url, issue_title, assignee, labels_json, milestone))
            
        conn.commit()
    except Exception as e:
        conn.rollback()
        # Log error but don't crash issue creation
        print(f"Error saving to DB: {e}")
    finally:
        conn.close()


