"""
deduplication.py — Removes duplicate findings across all scanners.
Strategy (inspired by DefectDojo):
  1. Exact match on dedup_key (SHA-256 hash: network=host+port+cve, web=host+path+cwe)
  2. Fuzzy match on vulnerability_name + host using RapidFuzz
  3. (Placeholder) Embedding-based semantic similarity — future enhancement

When duplicates are found, the canonical finding is kept and all source_scanners
are merged onto it. corroboration_count is incremented.
"""
from __future__ import annotations
from typing import List, Dict, Tuple
from rapidfuzz import fuzz

from app.schemas.canonical import CanonicalFinding, DeduplicationSchema, FindingStatus

# Fuzzy match threshold (0-100). Findings above this are considered duplicates.
FUZZY_THRESHOLD = 88


def _merge_into_primary(primary: CanonicalFinding, duplicate: CanonicalFinding) -> CanonicalFinding:
    """Merge duplicate's scanner info into primary finding."""
    if primary.deduplication is None:
        primary.deduplication = DeduplicationSchema(source_scanners=[], corroboration_count=1)
    dup_scanners = (duplicate.deduplication.source_scanners if duplicate.deduplication else [])
    for sc in dup_scanners:
        if sc not in primary.deduplication.source_scanners:
            primary.deduplication.source_scanners.append(sc)
    primary.deduplication.corroboration_count += 1
    # If 2+ scanners confirm: mark corroborated
    if primary.deduplication.corroboration_count >= 2:
        if primary.false_positive:
            primary.false_positive.fp_status = FindingStatus.CORROBORATED
    return primary


def _fuzzy_key(finding: CanonicalFinding) -> str:
    """Generate a fuzzy comparison string from vuln name + host."""
    host = (
        finding.asset.ip or finding.asset.hostname or
        finding.asset.domain or finding.asset.url or ""
    )
    return f"{finding.vulnerability_name.lower().strip()}|{host.lower().strip()}"


def deduplicate(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    """
    Run deduplication in two passes:
    Pass 1: Exact dedup_key match (SHA-256 hash)
    Pass 2: Fuzzy name+host match (RapidFuzz)
    Returns deduplicated list with source_scanners merged.
    """
    # ── Pass 1: Exact key dedup ──────────────────────────────────────────────
    exact_map: Dict[str, CanonicalFinding] = {}
    fuzzy_candidates: List[CanonicalFinding] = []

    for finding in findings:
        key = finding.deduplication.dedup_key if finding.deduplication else finding.compute_dedup_key()
        if key in exact_map:
            primary = exact_map[key]
            _merge_into_primary(primary, finding)
            if finding.deduplication:
                finding.deduplication.is_duplicate = True
                finding.deduplication.duplicate_of = primary.finding_id
                finding.deduplication.dedup_method = "exact"
        else:
            exact_map[key] = finding
            fuzzy_candidates.append(finding)

    # ── Pass 2: Fuzzy name+host dedup ────────────────────────────────────────
    deduplicated: List[CanonicalFinding] = []
    fuzzy_map: List[Tuple[str, CanonicalFinding]] = []

    for finding in fuzzy_candidates:
        fkey = _fuzzy_key(finding)
        matched = False
        for existing_fkey, existing_finding in fuzzy_map:
            score = fuzz.token_sort_ratio(fkey, existing_fkey)
            if score >= FUZZY_THRESHOLD:
                _merge_into_primary(existing_finding, finding)
                if finding.deduplication:
                    finding.deduplication.is_duplicate = True
                    finding.deduplication.duplicate_of = existing_finding.finding_id
                    finding.deduplication.dedup_method = "fuzzy"
                    finding.deduplication.dedup_key = f"fuzzy_score:{score}"
                matched = True
                break
        if not matched:
            fuzzy_map.append((fkey, finding))
            deduplicated.append(finding)

    return deduplicated
