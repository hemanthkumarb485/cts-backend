"""
deduplication.py — Removes duplicate findings across all scanners.
Strategy (inspired by DefectDojo):
  1. Exact match on dedup_key (SHA-256 hash: network=host+port+cve, web=host+path+cwe)
  2. Fuzzy match on vulnerability_name + host using RapidFuzz
  3. Semantic match on vulnerability_name + description via TF-IDF cosine similarity

When duplicates are found, the canonical finding is kept and all source_scanners
are merged onto it. corroboration_count is incremented.
"""
from __future__ import annotations
from typing import List, Dict, Tuple
from rapidfuzz import fuzz
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from app.schemas.canonical import CanonicalFinding, DeduplicationSchema, FindingStatus

# Fuzzy match threshold (0-100). Findings above this are considered duplicates.
FUZZY_THRESHOLD = 88

# Cosine similarity threshold (0-1) for the semantic pass. Findings whose
# TF-IDF vectors of "name + description" are at least this similar are
# treated as duplicates even if the fuzzy name+host match missed them
# (e.g. same vuln worded differently, or host derived differently).
SEMANTIC_THRESHOLD = 0.85


def _semantic_text(finding: CanonicalFinding) -> str:
    return f"{finding.vulnerability_name or ''} {finding.description or ''}".strip()


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
    return f"{finding.vulnerability_name.lower().strip()} | {host.lower().strip()}"


def _semantic_dedup(candidates: List[CanonicalFinding]) -> List[CanonicalFinding]:
    """
    Pass 3: TF-IDF cosine similarity over "name + description", run only on
    survivors of the exact + fuzzy passes (already a small set, so the O(n^2)
    pairwise comparison below stays cheap). Catches near-duplicate findings
    the fuzzy name+host pass missed (reworded name, host derived differently).
    """
    if len(candidates) < 2:
        return candidates

    texts = [_semantic_text(f) for f in candidates]
    if not any(texts):
        return candidates

    try:
        vectors = TfidfVectorizer(stop_words="english").fit_transform(texts)
        similarity = cosine_similarity(vectors)
    except ValueError:
        # All-empty vocabulary (e.g. every text was pure stopwords) — skip pass.
        return candidates

    kept: List[CanonicalFinding] = []
    kept_indices: List[int] = []
    for i, finding in enumerate(candidates):
        matched = False
        for kept_idx in kept_indices:
            if similarity[i][kept_idx] >= SEMANTIC_THRESHOLD:
                primary = candidates[kept_idx]
                _merge_into_primary(primary, finding)
                if finding.deduplication:
                    finding.deduplication.is_duplicate = True
                    finding.deduplication.duplicate_of = primary.finding_id
                    finding.deduplication.dedup_method = "semantic"
                    finding.deduplication.dedup_key = f"cosine_score:{similarity[i][kept_idx]:.3f}"
                matched = True
                break
        if not matched:
            kept.append(finding)
            kept_indices.append(i)
    return kept


def deduplicate(findings: List[CanonicalFinding]) -> List[CanonicalFinding]:
    """
    Run deduplication in three passes:
    Pass 1: Exact dedup_key match (SHA-256 hash)
    Pass 2: Fuzzy name+host match (RapidFuzz)
    Pass 3: Semantic name+description match (TF-IDF cosine similarity)
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

    # ── Pass 3: Semantic name+description dedup ─────────────────────────────
    return _semantic_dedup(deduplicated)
