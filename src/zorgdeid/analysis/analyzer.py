"""
GuardAnalyzer — central PII analysis engine configured with all Dutch recognizers.

Architecture
------------
The engine runs the following pipeline on every call:

  1.  Run spaCy NLP pipeline on the text (nl_core_news_lg).
  2.  Remap raw Dutch NER labels (PER→PERSON, LOC/GPE→LOCATION) and build an
      InternalNlpArtifacts object.
  3.  Call each recognizer's .analyze(text, entities, nlp_artifacts).
  4.  Stamp recognition_metadata (recognizer id/name) on every result.
  5.  Context boost is embedded in PatternRecognizer.analyze() itself.
  6.  Remove duplicates via EntityRecognizer.remove_duplicates().
  7.  Apply post-processing: DutchContextEnhancer → score filter →
      merge_entities → resolve_overlaps.

Singleton pattern with double-checked locking ensures the spaCy model is
loaded at most once regardless of concurrency.

Public helpers
--------------
resolve_entities(set_entities, custom_patterns) → list[str] | None
    Resolves the entity filter from a config block.

run(text, entities, score_threshold, custom_patterns) → list[RecognizerResult]
    Convenience wrapper used by processors/.
"""

import logging
import re
import threading
from typing import Any, Dict, List, Optional

import spacy

from zorgdeid.recognizers.base import (
    EntityRecognizer,
    InternalNlpArtifacts,
    PatternRecognizer,
)
from zorgdeid.types import Pattern, RecognizerResult

from zorgdeid.config.entities import ALL_NL_ENTITY_TYPES
from zorgdeid.recognizers import ALL_REGEX_RECOGNIZERS, NlNerRecognizer
from zorgdeid.analysis.overlap_resolver import resolve_overlaps, merge_entities
from zorgdeid.analysis.context_awareness import DutchContextEnhancer

logger = logging.getLogger(__name__)

_ENHANCER = DutchContextEnhancer()

_DEFAULT_NER_SCORE: float = 0.85

# Dutch spaCy label → canonical entity name.
_DUTCH_NER_MAPPING: Dict[str, str] = {
    "PER": "PERSON",
    "PERSON": "PERSON",
    "LOC": "LOCATION",
    "LOCATION": "LOCATION",
    "GPE": "LOCATION",
}


class _MappedSpan:
    """
    Lightweight proxy for a spaCy Span with a remapped entity label.

    BaseSpacyRecognizer.analyze() only needs ``.label_``, ``.start_char``,
    and ``.end_char``.  Using a proxy avoids any mutation of the spaCy Doc.
    """

    __slots__ = ("label_", "start_char", "end_char")

    def __init__(self, span, mapped_label: str) -> None:
        self.label_ = mapped_label
        self.start_char: int = span.start_char
        self.end_char: int = span.end_char


class _EngineState:
    """Holds the loaded spaCy model and instantiated recognizers."""

    __slots__ = ("nlp", "ner_recognizer", "regex_recognizers")

    def __init__(self, nlp, ner_recognizer, regex_recognizers):
        self.nlp = nlp
        self.ner_recognizer: NlNerRecognizer = ner_recognizer
        self.regex_recognizers: List[EntityRecognizer] = regex_recognizers


_SPACY_MODEL = "nl_core_news_lg"


def _ensure_model() -> None:
    """Download the Dutch spaCy model if it is not already installed."""
    if not spacy.util.is_package(_SPACY_MODEL):
        logger.info(
            "spaCy model '%s' not found — downloading automatically...",
            _SPACY_MODEL,
        )
        spacy.cli.download(_SPACY_MODEL)
        logger.info("spaCy model '%s' downloaded successfully.", _SPACY_MODEL)


def _build_state() -> _EngineState:
    """Load the spaCy model and instantiate every registered recognizer."""
    _ensure_model()
    nlp = spacy.load(_SPACY_MODEL)
    ner = NlNerRecognizer()
    regex_recs: List[EntityRecognizer] = [cls() for cls in ALL_REGEX_RECOGNIZERS]
    logger.info(
        "GuardAnalyzer ready — %d recognizers loaded (%d regex + 1 NER)",
        len(regex_recs) + 1,
        len(regex_recs),
    )
    return _EngineState(nlp, ner, regex_recs)


def _build_nlp_artifacts(doc) -> InternalNlpArtifacts:
    """
    Convert a spaCy Doc into an InternalNlpArtifacts.

    Applies _DUTCH_NER_MAPPING to remap raw NER labels; unrecognised labels
    are passed through and filtered by the recognizer's supported_entities check.
    """
    mapped: List[_MappedSpan] = []
    scores: List[float] = []

    for ent in doc.ents:
        canonical = _DUTCH_NER_MAPPING.get(ent.label_, ent.label_)
        mapped.append(_MappedSpan(ent, canonical))
        scores.append(_DEFAULT_NER_SCORE)

    return InternalNlpArtifacts(entities=mapped, scores=scores)


def _build_custom_recognizers(
    custom_patterns: Optional[List[Dict[str, Any]]],
    target_entities: List[str],
) -> List[PatternRecognizer]:
    """Instantiate ad-hoc PatternRecognizers from the caller-supplied spec."""
    recognizers: List[PatternRecognizer] = []
    if not custom_patterns:
        return recognizers

    for p in custom_patterns:
        name = p["name"]
        pattern = Pattern(
            name=name,
            regex=p["regex"],
            score=p.get("score", 0.85),
        )
        recognizer = PatternRecognizer(
            supported_entity=name,
            patterns=[pattern],
            context=p.get("context"),
            supported_language="nl",
        )
        recognizers.append(recognizer)
        if name not in target_entities:
            target_entities.append(name)

    return recognizers


def _stamp_metadata(
    results: List[RecognizerResult],
    recognizer: EntityRecognizer,
) -> None:
    """Ensure every result carries recognizer id and name in recognition_metadata."""
    for result in results:
        if not result.recognition_metadata:
            result.recognition_metadata = {}
        meta = result.recognition_metadata
        if RecognizerResult.RECOGNIZER_IDENTIFIER_KEY not in meta:
            meta[RecognizerResult.RECOGNIZER_IDENTIFIER_KEY] = recognizer.id
        if RecognizerResult.RECOGNIZER_NAME_KEY not in meta:
            meta[RecognizerResult.RECOGNIZER_NAME_KEY] = recognizer.name


class GuardAnalyzer:
    """
    Central PII analysis engine — pure internal implementation.

    Thread-safe singleton: the spaCy model and recognizer instances are shared
    across all calls.  Custom patterns passed to ``analyze()`` are ephemeral —
    they are instantiated per call and never mutate shared state.
    """

    _instance: Optional[_EngineState] = None
    _lock: threading.Lock = threading.Lock()

    @classmethod
    def _get_state(cls) -> _EngineState:
        """Return (or lazily create) the shared engine state."""
        if cls._instance is not None:
            return cls._instance

        with cls._lock:
            if cls._instance is not None:
                return cls._instance
            cls._instance = _build_state()

        return cls._instance

    def analyze(
        self,
        text: str,
        entities: Optional[List[str]] = None,
        score_threshold: float = 0.0,
        custom_patterns: Optional[List[Dict[str, Any]]] = None,
    ) -> List[RecognizerResult]:
        """
        Run analysis on *text* and return a list of RecognizerResult.

        If *entities* is None every registered entity type is scanned.
        Overlapping results are resolved by keeping the highest-scoring match.

        ``custom_patterns`` is a list of dicts with keys:
            - name    (str)   : entity type label, e.g. "EMPLOYEE_ID"
            - regex   (str)   : Python regex string
            - score   (float) : confidence score (default 0.85)
            - context (list)  : optional context words that boost the score
        """
        state = self._get_state()

        target_entities: List[str] = list(entities or ALL_NL_ENTITY_TYPES)
        custom_recognizers = _build_custom_recognizers(custom_patterns, target_entities)

        doc = state.nlp(text)
        nlp_artifacts = _build_nlp_artifacts(doc)

        all_recognizers: List[EntityRecognizer] = (
            [state.ner_recognizer]
            + state.regex_recognizers
            + custom_recognizers
        )

        raw_threshold = min(0.1, score_threshold)
        raw_results: List[RecognizerResult] = []

        for recognizer in all_recognizers:
            try:
                results = recognizer.analyze(
                    text=text,
                    entities=target_entities,
                    nlp_artifacts=nlp_artifacts,
                )
            except (ValueError, TypeError, AttributeError, re.error) as exc:
                logger.exception("Recognizer %s raised an error — skipping: %s", recognizer.name, exc)
                continue

            if results:
                _stamp_metadata(results, recognizer)
                raw_results.extend(results)

        raw_results = EntityRecognizer.remove_duplicates(raw_results)
        raw_results = [r for r in raw_results if r.score >= raw_threshold]

        results = _ENHANCER.enhance(text, raw_results)
        results = [r for r in results if r.score >= score_threshold]
        results = merge_entities(results)
        results = resolve_overlaps(results)

        logger.debug("Analyzed text (%d chars) — %d findings", len(text), len(results))
        return results


# ---------------------------------------------------------------------------
# Public helpers (consumed by processors/)
# ---------------------------------------------------------------------------

def resolve_entities(
    set_entities: Optional[Dict],
    custom_patterns: Optional[List[Dict]] = None,
) -> Optional[List[str]]:
    """
    Resolve the entity filter from a ``set_entities`` config block.

    Parameters
    ----------
    set_entities : dict or None
        ``{"keep": [...]}``  – allowlist: only these types are scanned.
        ``{"ignore": [...]}`` – denylist: these types are skipped.
        ``None``              – no filter; scan everything.
    custom_patterns : list of dicts, optional
        Custom pattern definitions whose ``name`` keys may appear in ``keep``.

    Returns
    -------
    list[str] or None
        Resolved entity list, or ``None`` if no filtering is required.
    """
    if not set_entities:
        return None

    keep = set_entities.get("keep")
    ignore = set_entities.get("ignore")
    custom_names: List[str] = [p["name"] for p in (custom_patterns or []) if "name" in p]

    if keep is not None:
        if not keep:
            return []
        built_in = [e for e in ALL_NL_ENTITY_TYPES if e in keep]
        extras = [e for e in keep if e not in ALL_NL_ENTITY_TYPES and e in custom_names]
        return built_in + extras

    if ignore is not None:
        built_in = [e for e in ALL_NL_ENTITY_TYPES if e not in ignore]
        extras = [e for e in custom_names if e not in ignore and e not in built_in]
        return built_in + extras

    return None


def run(
    text: str,
    entities: Optional[List[str]] = None,
    score_threshold: float = 0.0,
    custom_patterns: Optional[List[Dict[str, Any]]] = None,
) -> List[RecognizerResult]:
    """
    Run PII detection on *text* and return raw ``RecognizerResult`` objects.

    Parameters
    ----------
    text             : Dutch text to analyse.
    entities         : Explicit entity-type list (``None`` = scan all).
    score_threshold  : Minimum score; results below this are dropped.
    custom_patterns  : Additional user-defined regex patterns.

    Returns
    -------
    list[RecognizerResult]
    """
    engine = GuardAnalyzer()
    return engine.analyze(
        text,
        entities=entities,
        score_threshold=score_threshold,
        custom_patterns=custom_patterns,
    )
