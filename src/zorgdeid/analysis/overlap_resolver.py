"""
Overlap resolution for PII entity matches.
Handles scenario where multiple recognizers fire on same or closely abutting text.
"""
from copy import deepcopy
from typing import List

from zorgdeid.types import RecognizerResult


def resolve_overlaps(results: List[RecognizerResult]) -> List[RecognizerResult]:
    """
    When two or more findings overlap, keep only the highest-scoring one.
    On equal scores the longer span wins; on equal length the first entity wins.
    Returns a new list; input is never mutated.
    """
    if not results:
        return results

    ranked = sorted(results, key=lambda r: (-r.score, -(r.end - r.start), r.start))
    accepted: List[RecognizerResult] = []

    for candidate in ranked:
        overlaps = any(
            candidate.start < kept.end and candidate.end > kept.start
            for kept in accepted
        )
        if not overlaps:
            accepted.append(candidate)

    return sorted(accepted, key=lambda r: r.start)


def merge_entities(results: List[RecognizerResult], max_gap: int = 2) -> List[RecognizerResult]:
    """
    Merge adjacent or slightly separated findings of the same entity type.

    Creates copies of merged results so the original RecognizerResult objects
    from the analyzer are never mutated (mutation would corrupt the objects
    shared with the findings dict built in anonymization/engine.py).
    """
    if not results:
        return results

    sorted_results = sorted(results, key=lambda x: x.start)
    merged: List[RecognizerResult] = []
    current = deepcopy(sorted_results[0])

    for next_res in sorted_results[1:]:
        if (
            next_res.entity_type == current.entity_type
            and (next_res.start - current.end) <= max_gap
        ):
            current.end = max(current.end, next_res.end)
            current.score = max(current.score, next_res.score)
        else:
            merged.append(current)
            current = deepcopy(next_res)

    merged.append(current)
    return merged
