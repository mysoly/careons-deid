"""
zorgdeid

A standalone Python library for detecting and anonymizing Dutch PII.
Powered by a custom NLP engine and spaCy.

Package layout
--------------
zorgdeid/
├── types.py              — core data structures (RecognizerResult, Pattern, …)
├── config/               — entity type list and scoring profiles
├── patterns/             — Dutch regex patterns and keyword lists
├── recognizers/
│   ├── base.py           — EntityRecognizer / PatternRecognizer / BaseSpacyRecognizer
│   └── *.py              — domain recognizers (temporal, contact, identity, …)
├── analysis/
│   ├── analyzer.py       — GuardAnalyzer engine + resolve_entities / run helpers
│   ├── context_awareness.py — DutchContextEnhancer score-boosting rules
│   └── overlap_resolver.py  — resolve_overlaps / merge_entities
├── anonymization/
│   ├── engine.py         — GuardEngine (anonymize / tag / i_tag modes)
│   ├── fake_data.py      — synthetic Dutch PII pools
│   └── strategies.py     — OperatorConfig re-export
└── processors/
    ├── text_processor.py — analyze / guard pipelines for plain-text input
    └── doc_processor.py  — file reading (.pdf/.docx/.txt) + text pipelines

Public interface::

    from zorgdeid import analyze, guard, custom_pattern

    analyze.text("Jan de Vries woont in Amsterdam.")
    analyze.doc("/path/to/report.pdf")

    guard.text("Jan de Vries woont in Amsterdam.")
    guard.doc("/path/to/rapport.docx")

    pattern = custom_pattern(name="EMPLOYEE_ID", regex=r"EMP-\\d{4}")
    guard.text(text, config={"custom_patterns": [pattern]})
"""

from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from zorgdeid.config.entities import ALL_NL_ENTITY_TYPES
from zorgdeid.processors.text_processor import analyze as _analyze, guard as _guard
from zorgdeid.processors.doc_processor import (
    UnsupportedFormatError,
    analyze as _analyze_doc,
    guard as _guard_doc,
)

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Public namespace objects
# ---------------------------------------------------------------------------

analyze = SimpleNamespace(
    text=_analyze,
    doc=_analyze_doc,
)

guard = SimpleNamespace(
    text=_guard,
    doc=_guard_doc,
)


def custom_pattern(
    name: str,
    regex: str,
    score: float = 0.85,
    context: Optional[List[str]] = None,
    anonymize_list: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Build a custom pattern definition for use in ``config["custom_patterns"]``.

    Args:
        name           : Entity type label (e.g. ``"EMPLOYEE_ID"``).
        regex          : Python regex string.
        score          : Confidence score (default 0.85).
        context        : Words near the match that boost confidence.
        anonymize_list : Fake replacement values for anonymize mode.

    Returns:
        dict ready for ``config["custom_patterns"]``.

    Example::

        from zorgdeid import guard, custom_pattern

        pattern = custom_pattern(
            name="EMPLOYEE_ID",
            regex=r"EMP-\\d{4}",
            score=0.9,
            context=["medewerker", "employee"],
            anonymize_list=["EMP-0001", "EMP-0002"],
        )
        guard.text(text, config={"custom_patterns": [pattern]})
        guard.doc("/path/to/file.pdf", config={"custom_patterns": [pattern]})
    """
    return {
        "name": name,
        "regex": regex,
        "score": score,
        "context": context,
        "anonymize_list": anonymize_list,
    }

__all__ = [
    "analyze",
    "guard",
    "custom_pattern",
    "ALL_NL_ENTITY_TYPES",
    "UnsupportedFormatError",
    "__version__",
]
