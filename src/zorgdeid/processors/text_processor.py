"""
zorgdeid.processors.text_processor
--------------------------------------
Full analyze and guard pipelines for plain-text input.
"""

from typing import Dict, List, Optional

from zorgdeid.analysis import analyzer as _analyzer
from zorgdeid.anonymization.engine import GuardEngine as _GuardEngine, _VALID_MODES

_VALID_ANALYZE_KEYS = frozenset({"set_entities", "score_threshold", "custom_patterns"})
_VALID_GUARD_KEYS = _VALID_ANALYZE_KEYS | frozenset({"mode"})


def _validate_config(cfg: dict, valid_keys: frozenset, caller: str) -> None:
    unknown = set(cfg) - valid_keys
    if unknown:
        raise ValueError(
            f"{caller}() received unknown config key(s): {sorted(unknown)}. "
            f"Valid keys are: {sorted(valid_keys)}"
        )
    score = cfg.get("score_threshold")
    if score is not None:
        if not isinstance(score, (int, float)):
            raise TypeError(
                f"score_threshold must be a number, got {type(score).__name__!r}"
            )
        if not 0.0 <= float(score) <= 1.0:
            raise ValueError(
                f"score_threshold must be between 0.0 and 1.0, got {score!r}"
            )
    mode = cfg.get("mode")
    if mode is not None and mode not in _VALID_MODES:
        raise ValueError(
            f"Unknown guard mode {mode!r}. Choose from: {sorted(_VALID_MODES)}"
        )


def analyze(text: str, config: Optional[Dict] = None) -> List[Dict]:
    """
    Detect PII in *text* and return a list of findings.

    Parameters
    ----------
    text   : Dutch plain text to analyse.
    config : Optional detection config::

                {
                    "set_entities":    {"keep": [...]} or {"ignore": [...]},
                    "score_threshold": 0.5,
                    "custom_patterns": [...],
                }

    Returns
    -------
    list[dict]
        Each dict: ``{"type": str, "start": int, "end": int, "score": float}``
    """
    cfg = config or {}
    _validate_config(cfg, _VALID_ANALYZE_KEYS, "analyze")
    score_threshold = cfg.get("score_threshold", 0.0)
    patterns = cfg.get("custom_patterns") or []
    entities = _analyzer.resolve_entities(cfg.get("set_entities"), patterns)

    results = _analyzer.run(
        text,
        entities=entities,
        score_threshold=score_threshold,
        custom_patterns=patterns or None,
    )

    return [
        {
            "type": r.entity_type,
            "start": r.start,
            "end": r.end,
            "score": round(r.score, 4),
        }
        for r in results
    ]


def guard(text: str, config: Optional[Dict] = None) -> Dict:
    """
    Detect and anonymize PII in *text*, returning the guarded result.

    Parameters
    ----------
    text   : Dutch plain text to process.
    config : Optional processing config::

                {
                    "set_entities":    {"keep": [...]} or {"ignore": [...]},
                    "score_threshold": 0.5,
                    "mode":            "anonymize",   # or "tag" / "i_tag"
                    "custom_patterns": [...],
                }

    Returns
    -------
    dict
        ``guarded_text`` – text with PII replaced.
        ``findings``     – list of finding dicts.
    """
    cfg = config or {}
    _validate_config(cfg, _VALID_GUARD_KEYS, "guard")
    score_threshold = cfg.get("score_threshold", 0.0)
    mode = cfg.get("mode", "anonymize")
    patterns = cfg.get("custom_patterns") or []
    entities = _analyzer.resolve_entities(cfg.get("set_entities"), patterns)

    extra_entities = [p["name"] for p in patterns if "name" in p]
    anonymize_list = {
        p["name"]: p["anonymize_list"]
        for p in patterns
        if p.get("name") and p.get("anonymize_list")
    }

    analyzer_results = _analyzer.run(
        text,
        entities=entities,
        score_threshold=score_threshold,
        custom_patterns=patterns or None,
    )

    return _GuardEngine.guard(
        text=text,
        analyzer_results=analyzer_results,
        mode=mode,
        extra_entities=extra_entities or None,
        anonymize_list=anonymize_list or None,
    )
