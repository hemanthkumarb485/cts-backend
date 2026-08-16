"""
false_positive.py — Rule-based FP & Noise Reduction (ML is future placeholder).
Rules: R001-R007. Assigns ACTIVE / NEEDS_REVIEW / SUPPRESSED / CORROBORATED.
"""
from __future__ import annotations
from typing import List
from app.schemas.canonical import CanonicalFinding, FindingStatus, FalsePositiveSchema, NormalizedSeverity


def _fp(finding: CanonicalFinding) -> FalsePositiveSchema:
    if finding.false_positive is None:
        finding.false_positive = FalsePositiveSchema(fp_rules_applied=[])
    if finding.false_positive.fp_rules_applied is None:
        finding.false_positive.fp_rules_applied = []
    return finding.false_positive


def rule_r001(f: CanonicalFinding) -> None:
    """R001: Low confidence + no evidence → needs_review."""
    fp = _fp(f)
    if (f.confidence or "").lower() in ("low", "false positive") and not (f.evidence or "").strip():
        fp.fp_rules_applied.append("R001")
        if fp.fp_status == FindingStatus.ACTIVE:
            fp.fp_status = FindingStatus.NEEDS_REVIEW
            fp.fp_reason = "Low confidence, no evidence"


def rule_r002(f: CanonicalFinding) -> None:
    """R002: Informational severity → suppress."""
    fp = _fp(f)
    if f.severity == NormalizedSeverity.INFORMATIONAL:
        fp.fp_rules_applied.append("R002")
        fp.fp_status = FindingStatus.SUPPRESSED
        fp.fp_reason = "Informational — not a vulnerability"


def rule_r003(f: CanonicalFinding) -> None:
    """R003: Network finding with no CVE/CWE/evidence → needs_review."""
    fp = _fp(f)
    if f.source_tool.value in ("nmap", "openvas") and not f.cve_id and not f.cwe_id and not f.evidence:
        fp.fp_rules_applied.append("R003")
        if fp.fp_status == FindingStatus.ACTIVE:
            fp.fp_status = FindingStatus.NEEDS_REVIEW
            fp.fp_reason = "Network finding without CVE/CWE/evidence"


def rule_r004(f: CanonicalFinding) -> None:
    """R004: OpenVAS QoD < 30 → needs_review."""
    fp = _fp(f)
    if f.qod is not None and f.qod < 30:
        fp.fp_rules_applied.append("R004")
        if fp.fp_status == FindingStatus.ACTIVE:
            fp.fp_status = FindingStatus.NEEDS_REVIEW
            fp.fp_reason = f"OpenVAS QoD={f.qod} (<30)"


def rule_r005(f: CanonicalFinding) -> None:
    """R005: 2+ scanners → CORROBORATED."""
    fp = _fp(f)
    count = f.deduplication.corroboration_count if f.deduplication else 1
    if count >= 2:
        fp.fp_rules_applied.append("R005")
        if fp.fp_status in (FindingStatus.NEEDS_REVIEW, FindingStatus.ACTIVE):
            fp.fp_status = FindingStatus.CORROBORATED
            fp.fp_reason = f"Corroborated by {count} scanners"


def rule_r006(f: CanonicalFinding) -> None:
    """R006: ZAP 'False Positive' confidence → FP."""
    fp = _fp(f)
    if f.source_tool.value == "zap" and (f.confidence or "").lower() == "false positive":
        fp.fp_rules_applied.append("R006")
        fp.fp_status = FindingStatus.FALSE_POSITIVE
        fp.fp_reason = "ZAP flagged as False Positive"


def rule_r007(f: CanonicalFinding) -> None:
    """R007: Threshold-based. conf<40→review, 40-69→review, 70+→active."""
    fp = _fp(f)
    if fp.fp_status in (FindingStatus.SUPPRESSED, FindingStatus.FALSE_POSITIVE, FindingStatus.CORROBORATED):
        return
    conf_map = {"confirmed": 90, "high": 80, "medium": 60, "low": 30, "false positive": 0}
    score = conf_map.get((f.confidence or "").lower(), 50)
    corr = f.deduplication.corroboration_count if f.deduplication else 1
    score = min(100, score + (corr - 1) * 10)
    fp.fp_rules_applied.append("R007")
    if score < 40:
        fp.fp_status = FindingStatus.NEEDS_REVIEW
        fp.fp_reason = fp.fp_reason or f"Confidence score={score} (low)"
    elif score < 70:
        fp.fp_status = FindingStatus.NEEDS_REVIEW
        fp.fp_reason = fp.fp_reason or f"Confidence score={score} (borderline)"


RULES = [rule_r001, rule_r002, rule_r003, rule_r004, rule_r005, rule_r006, rule_r007]


def apply_false_positive_rules(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    for f in findings:
        for rule in RULES:
            rule(f)
    return findings


def filter_active(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    return [f for f in findings if f.false_positive is None or
            f.false_positive.fp_status in (FindingStatus.ACTIVE, FindingStatus.CORROBORATED,
                                           FindingStatus.NEEDS_REVIEW)]
