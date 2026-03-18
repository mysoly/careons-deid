"""Shared utility used by all domain recognizer modules."""
from zorgdeid.types import Pattern


def _p(name: str, regex: str, score: float) -> Pattern:
    """Shorthand Pattern constructor."""
    return Pattern(name=name, regex=regex, score=score)
