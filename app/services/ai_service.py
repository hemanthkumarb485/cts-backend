"""
ai_service.py — Anthropic Claude wrapper for the AI-assisted features:
  1. suggest_remediation()      — Finding detail page "Get AI Remediation" button
  2. enhance_ticket_description() — Ticket composer "Enhance with AI" button
  3. generate_overview()        — Finding detail page "Get AI Overview" button
     (only really needed for CVE-less/CWE-only findings, where there's no NVD
     description to fall back to and the scanner's own text is a generic
     one-liner like "SQL injection may be possible.")
"""
from __future__ import annotations
from typing import Optional
import anthropic

from app.core.config import ANTHROPIC_API_KEY, ANTHROPIC_MODEL
from app.schemas.canonical import CanonicalFinding

_client: Optional[anthropic.Anthropic] = None


def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        if not ANTHROPIC_API_KEY:
            raise RuntimeError("ANTHROPIC_API_KEY is not configured")
        _client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    return _client


def _call_claude(prompt: str, max_tokens: int) -> str:
    """Calls Claude and turns SDK errors into a short, user-facing message
    instead of leaking the raw Anthropic error payload to the frontend."""
    try:
        resp = _get_client().messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text.strip()
    except anthropic.APIStatusError as e:
        body_msg = None
        if isinstance(e.body, dict):
            body_msg = e.body.get("error", {}).get("message")
        msg = body_msg or str(e)
        if "credit balance" in msg.lower():
            raise RuntimeError(
                "Anthropic account has no credit balance. Add credits at "
                "console.anthropic.com/settings/billing to enable AI features."
            ) from e
        if e.status_code == 401:
            raise RuntimeError("Anthropic API key is invalid. Check ANTHROPIC_API_KEY.") from e
        raise RuntimeError(f"Anthropic API error: {msg}") from e
    except anthropic.APIConnectionError as e:
        raise RuntimeError("Could not reach the Anthropic API — check network connectivity.") from e


def _finding_context(finding: CanonicalFinding) -> str:
    asset = finding.asset
    ti = finding.threat_intel
    host = asset.hostname or asset.ip or asset.domain or asset.url or "unknown host"
    location = asset.path or asset.url or ""
    lines = [
        f"Vulnerability: {finding.vulnerability_name}",
        f"Severity: {finding.severity.value if finding.severity else 'unknown'}",
        f"CVE: {finding.cve_id or '—'}",
        f"CWE: {finding.cwe_id or '—'}",
        f"Asset: {host}{(' ' + location) if location else ''}",
        f"Source tool: {finding.source_tool.value if finding.source_tool else '—'}",
    ]
    # Prefer the NVD's authoritative per-CVE description over the scanner's
    # generic per-vuln-type text, when we have it — keeps the model grounded
    # in accurate, CVE-specific facts rather than boilerplate.
    if ti and ti.nvd_description:
        lines.append(f"NVD description: {ti.nvd_description}")
    elif finding.description:
        lines.append(f"Description: {finding.description}")
    if ti:
        if ti.is_kev:
            lines.append("This CVE is on CISA's Known Exploited Vulnerabilities (KEV) list — actively exploited in the wild.")
        if ti.has_public_exploit:
            lines.append(f"Public exploit code exists (ExploitDB): {', '.join(ti.exploit_descriptions or [])}")
        if ti.has_github_poc:
            lines.append("Public proof-of-concept repositories exist on GitHub referencing this CVE.")
    if finding.http_method or finding.parameter:
        lines.append(
            f"Request: {finding.http_method or 'GET'}"
            f"{' parameter=' + finding.parameter if finding.parameter else ''}"
        )
    if finding.attack:
        lines.append(f"Attack payload observed: {finding.attack}")
    if finding.evidence:
        lines.append(f"Evidence from scan: {finding.evidence}")
    return "\n".join(lines)


def generate_overview(finding: CanonicalFinding) -> str:
    prompt = (
        "You are a security analyst explaining a vulnerability finding to someone triaging it. "
        "Using only the facts given below, write a concise, specific 2-4 sentence overview of what "
        "this finding actually is and why it matters for this particular asset — not a generic "
        "definition of the vulnerability class. Ground every claim in the facts below; do not "
        "invent CVEs, scores, or details not present. If the facts are thin, say what's known "
        "plainly rather than padding with generic advice.\n\n"
        f"{_finding_context(finding)}"
    )
    return _call_claude(prompt, max_tokens=300)


def suggest_remediation(finding: CanonicalFinding) -> str:
    prompt = (
        "You are a security engineer writing remediation guidance for a developer. "
        "Given the vulnerability finding below, write clear, actionable remediation steps "
        "grounded in the specific facts given — do not invent details not present below. "
        "Be specific to the vulnerability type and technology where possible. "
        "Keep it under 200 words, formatted as short paragraphs or a brief numbered list.\n\n"
        f"{_finding_context(finding)}"
    )
    return _call_claude(prompt, max_tokens=500)


def enhance_ticket_description(finding: CanonicalFinding, current_description: Optional[str]) -> str:
    prompt = (
        "You are writing a clear, developer-actionable GitHub issue description for a security "
        "vulnerability. Rewrite/expand the description below (or draft one from the finding data "
        "if it's thin) so a developer unfamiliar with the finding understands: what the "
        "vulnerability is, why it matters, and what's affected. Ground it only in the facts given "
        "below — do not invent details. Keep it under 180 words, plain prose (no markdown headers — "
        "the surrounding issue template already has those).\n\n"
        f"{_finding_context(finding)}\n\n"
        f"Current description: {current_description or '(none provided)'}"
    )
    return _call_claude(prompt, max_tokens=400)
