"""
ai_service.py — Groq wrapper for the AI-assisted features:
  1. suggest_remediation()      — Finding detail page "Get AI Remediation"
     button, and reused by the ticket composer's "Enhance with AI" button
     (which enhances the ticket's Remediation field, not its Description —
     the Description doesn't need its own AI pass since the Overview below
     already is the AI-analyzed version of the scanner's raw text).
  2. generate_overview()        — Finding detail page Overview section.
     Always AI-generated (fetched automatically on page load) rather than
     showing the scanner's raw description verbatim — raw scanner/NVD text
     is thin ("SQL injection may be possible.") or generic boilerplate, so
     it's fed in as source material for the model to analyze and rewrite,
     not shown directly.

Note: the default model (openai/gpt-oss-120b) is a reasoning model — it
spends part of the token budget on an internal "reasoning" field before
producing the final answer, so max_tokens per call is set generously higher
than the target reply length to avoid truncating the answer to nothing.
"""
from __future__ import annotations
from typing import Optional
import groq

from app.core.config import GROQ_API_KEY, GROQ_MODEL
from app.schemas.canonical import CanonicalFinding

_client: Optional[groq.Groq] = None


def _get_client() -> groq.Groq:
    global _client
    if _client is None:
        if not GROQ_API_KEY:
            raise RuntimeError("GROQ_API_KEY is not configured")
        _client = groq.Groq(api_key=GROQ_API_KEY)
    return _client


def _call_llm(prompt: str, max_tokens: int) -> str:
    """Calls Groq and turns SDK errors into a short, user-facing message
    instead of leaking the raw API error payload to the frontend."""
    try:
        resp = _get_client().chat.completions.create(
            model=GROQ_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        return (resp.choices[0].message.content or "").strip()
    except groq.APIStatusError as e:
        body_msg = None
        if isinstance(e.body, dict):
            body_msg = e.body.get("error", {}).get("message")
        msg = body_msg or str(e)
        if e.status_code == 401:
            raise RuntimeError("Groq API key is invalid. Check GROQ_API_KEY.") from e
        if e.status_code == 429 or "quota" in msg.lower() or "rate limit" in msg.lower():
            raise RuntimeError("Groq rate limit or quota reached — try again in a moment.") from e
        raise RuntimeError(f"Groq API error: {msg}") from e
    except groq.APIConnectionError as e:
        raise RuntimeError("Could not reach the Groq API — check network connectivity.") from e


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
        "Below is the raw finding data, including the scanner's own (often generic or boilerplate) "
        "description. Analyze it and write a clear, specific overview of what this finding actually "
        "is and why it matters for this particular asset — do not just repeat the scanner text "
        "verbatim, rewrite and explain it in your own words.\n\n"
        "Format: exactly two paragraphs, separated by a blank line, each about 5 sentences long. "
        "First paragraph: what the vulnerability is and how it manifests here. Second paragraph: "
        "why it matters — impact and risk in context (asset criticality, exposure, any exploit/KEV "
        "signals given). Ground every claim in the facts below; do not invent CVEs, scores, or "
        "details not present. Plain prose, no markdown headers or bullet points.\n\n"
        f"{_finding_context(finding)}"
    )
    return _call_llm(prompt, max_tokens=900)


def suggest_remediation(finding: CanonicalFinding) -> str:
    prompt = (
        "You are a security engineer writing remediation guidance for a developer. "
        "Given the vulnerability finding below, write clear, actionable remediation steps "
        "grounded in the specific facts given — do not invent details not present below. "
        "Be specific to the vulnerability type and technology where possible. "
        "Keep it under 200 words, formatted as short paragraphs or a brief numbered list.\n\n"
        f"{_finding_context(finding)}"
    )
    return _call_llm(prompt, max_tokens=1024)
