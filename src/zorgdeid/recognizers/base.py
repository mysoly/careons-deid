"""
Base recognizer classes and NLP artifacts container for all Dutch PII recognizers.

Classes
-------
EntityRecognizer      – abstract base for all PII recognizers
PatternRecognizer     – concrete regex-based recognizer (extends EntityRecognizer)
InternalNlpArtifacts  – lightweight NLP artifacts container for spaCy NER results
BaseSpacyRecognizer   – abstract base for spaCy NER-based recognizers
"""

from __future__ import annotations

import datetime
import logging
import re
from abc import ABC, abstractmethod
from copy import copy as _copy
from typing import Dict, List, Optional, Tuple

from zorgdeid.types import AnalysisExplanation, Pattern, RecognizerResult
from zorgdeid.config.scoring import SCORE_PROFILES

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# EntityRecognizer
# ---------------------------------------------------------------------------

class EntityRecognizer(ABC):
    """
    Abstract base class for all zorgdeid PII recognizers.

    Subclasses must implement `load()` and `analyze()`.
    """

    MIN_SCORE: float = 0.0
    MAX_SCORE: float = 1.0

    def __init__(
        self,
        supported_entities: List[str],
        name: Optional[str] = None,
        supported_language: str = "nl",
        version: str = "0.0.1",
        context: Optional[List[str]] = None,
    ):
        self.supported_entities = supported_entities
        self.name = name if name is not None else self.__class__.__name__
        self._id = f"{self.name}_{id(self)}"
        self.supported_language = supported_language
        self.version = version
        self.context = context if context else []
        self.is_loaded = False
        self.load()
        logger.info("Loaded recognizer: %s", self.name)
        self.is_loaded = True

    @property
    def id(self) -> str:
        return self._id

    def get_supported_entities(self) -> List[str]:
        return self.supported_entities

    @abstractmethod
    def load(self) -> None:
        """
        Initialise recognizer assets if needed (e.g. ML models).

        Lightweight recognizers should implement this as a no-op ``pass``.
        """

    @abstractmethod
    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional["InternalNlpArtifacts"] = None,
    ) -> List[RecognizerResult]:
        """
        Analyze *text* and return detected PII entities.

        :param text: The text to be analyzed.
        :param entities: Entity types to detect (subset of supported_entities).
        :param nlp_artifacts: Optional NLP pre-processing output; accepted for
            interface compatibility, unused by regex-based recognizers.
        :return: List of RecognizerResult.
        """

    def enhance_using_context(
        self,
        text: str,
        raw_recognizer_results: List[RecognizerResult],
        other_raw_recognizer_results: List[RecognizerResult],
        nlp_artifacts: Optional["InternalNlpArtifacts"] = None,
        context: Optional[List[str]] = None,
    ) -> List[RecognizerResult]:
        """No-op context hook — subclasses may override."""
        return raw_recognizer_results

    def to_dict(self) -> Dict:
        return {
            "supported_entities": self.supported_entities,
            "supported_language": self.supported_language,
            "name": self.name,
            "version": self.version,
        }

    @staticmethod
    def remove_duplicates(
        results: List[RecognizerResult],
    ) -> List[RecognizerResult]:
        """Remove duplicate and fully-contained lower-scoring results."""
        results = list(set(results))
        results = sorted(
            results, key=lambda x: (-x.score, x.start, -(x.end - x.start))
        )
        filtered: List[RecognizerResult] = []

        for result in results:
            if result.score == 0:
                continue

            to_keep = result not in filtered
            if to_keep:
                for kept in filtered:
                    if (
                        result.contained_in(kept)
                        and result.entity_type == kept.entity_type
                    ):
                        to_keep = False
                        break

            if to_keep:
                filtered.append(result)

        return filtered

    @staticmethod
    def sanitize_value(
        text: str, replacement_pairs: List[Tuple[str, str]]
    ) -> str:
        """Replace each (search, replacement) pair in *text* in order."""
        for search_string, replacement_string in replacement_pairs:
            text = text.replace(search_string, replacement_string)
        return text


# ---------------------------------------------------------------------------
# PatternRecognizer
# ---------------------------------------------------------------------------

_DEFAULT_REGEX_FLAGS = re.DOTALL | re.MULTILINE | re.IGNORECASE

_CONTEXT_BOOST: float = 0.35
_MIN_SCORE_WITH_CONTEXT: float = 0.40
_CONTEXT_WINDOW_CHARS: int = 100


class PatternRecognizer(EntityRecognizer):
    """
    Concrete PII recognizer driven by regular expressions and/or deny-lists.

    Context word boosting is applied directly in analyze(): if any of the
    recognizer's context words appears within a character window around the
    match, the score is raised to at least ``SCORE_PROFILES[entity].with_context``
    (capped at ``MAX_SCORE``).  For custom entities without a profile the legacy
    additive fallback (+``_CONTEXT_BOOST``) is used instead.
    DutchContextEnhancer's ``only_if_below`` guards prevent double-boosting for
    entities it also covers.

    :param supported_entity: the single entity type label this recognizer detects
    :param patterns: list of Pattern objects to match against text
    :param deny_list: list of exact strings to match (auto-converted to regex)
    :param context: list of context words for confidence score boosting
    :param deny_list_score: score for deny-list matches (default 1.0)
    :param global_regex_flags: flags for re.compile() (default DOTALL|MULTILINE|IGNORECASE)
    :param name: optional human-readable recognizer name
    :param supported_language: ISO-639-1 language code (default "nl")
    :param version: recognizer version string
    """

    def __init__(
        self,
        supported_entity: str,
        patterns: Optional[List[Pattern]] = None,
        deny_list: Optional[List[str]] = None,
        context: Optional[List[str]] = None,
        deny_list_score: float = 1.0,
        global_regex_flags: Optional[int] = _DEFAULT_REGEX_FLAGS,
        name: Optional[str] = None,
        supported_language: str = "nl",
        version: str = "0.0.1",
    ):
        if not supported_entity:
            raise ValueError(
                "PatternRecognizer must be initialised with a supported_entity"
            )
        if not patterns and not deny_list:
            raise ValueError(
                "PatternRecognizer must be initialised with patterns or deny_list"
            )

        super().__init__(
            supported_entities=[supported_entity],
            name=name,
            supported_language=supported_language,
            version=version,
            context=context,
        )

        self.patterns = list(patterns) if patterns else []
        self.deny_list_score = deny_list_score
        self.global_regex_flags = global_regex_flags

        if deny_list:
            self.patterns.append(self._deny_list_to_regex(deny_list))
            self.deny_list = deny_list
        else:
            self.deny_list = []

    def load(self) -> None:  # noqa: D102
        pass

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional["InternalNlpArtifacts"] = None,
        regex_flags: Optional[int] = None,
    ) -> List[RecognizerResult]:
        """
        Analyze *text* using configured regex patterns then apply context boost.

        :param text: text to analyze
        :param entities: entity types to look for
        :param nlp_artifacts: unused; accepted for interface compatibility
        :param regex_flags: optional override of global_regex_flags
        :return: list of RecognizerResult
        """
        if not any(e in entities for e in self.supported_entities):
            return []

        results: List[RecognizerResult] = []
        if self.patterns:
            results.extend(self._analyze_patterns(text, regex_flags))

        if results and self.context:
            results = self._apply_context_boost(text, results)

        return results

    def _apply_context_boost(
        self,
        text: str,
        results: List[RecognizerResult],
    ) -> List[RecognizerResult]:
        """Boost score when a context word appears near the matched span.

        When a score profile is defined for the entity type, the target score
        is ``profile.with_context`` (score is raised to at least that value but
        never lowered).  For custom entities without a profile the legacy
        additive fallback (+``_CONTEXT_BOOST``) is used instead.
        """
        text_lower = text.lower()
        boosted: List[RecognizerResult] = []

        entity_type = self.supported_entities[0]
        profile = SCORE_PROFILES.get(entity_type)

        for result in results:
            already_boosted = (
                result.recognition_metadata
                and result.recognition_metadata.get(
                    RecognizerResult.IS_SCORE_ENHANCED_BY_CONTEXT_KEY
                )
            )
            if already_boosted:
                boosted.append(result)
                continue

            lo = max(0, result.start - _CONTEXT_WINDOW_CHARS)
            hi = min(len(text), result.end + _CONTEXT_WINDOW_CHARS)
            window = text_lower[lo:hi]

            supportive_word = next(
                (kw for kw in self.context if kw.lower() in window),
                None,
            )

            if supportive_word:
                r = _copy(result)
                if profile is not None:
                    new_score = min(self.MAX_SCORE, max(r.score, profile.with_context))
                else:
                    new_score = min(
                        self.MAX_SCORE,
                        max(_MIN_SCORE_WITH_CONTEXT, r.score + _CONTEXT_BOOST),
                    )
                if new_score > r.score:
                    r.score = new_score
                    if r.analysis_explanation:
                        r.analysis_explanation.set_supportive_context_word(
                            supportive_word
                        )
                        r.analysis_explanation.set_improved_score(new_score)
                boosted.append(r)
            else:
                boosted.append(result)

        return boosted

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        """Optional validation hook (e.g. checksum verification)."""
        return None

    def invalidate_result(self, pattern_text: str) -> Optional[bool]:
        """Optional invalidation hook (pruning logic)."""
        return None

    @staticmethod
    def build_regex_explanation(
        recognizer_name: str,
        pattern_name: str,
        pattern: str,
        original_score: float,
        validation_result: Optional[bool],
        regex_flags: int,
    ) -> AnalysisExplanation:
        """Build an AnalysisExplanation object for a regex-based detection."""
        textual_explanation = (
            f"Detected by `{recognizer_name}` using pattern `{pattern_name}`"
        )
        return AnalysisExplanation(
            recognizer=recognizer_name,
            original_score=original_score,
            pattern_name=pattern_name,
            pattern=pattern,
            validation_result=validation_result,
            regex_flags=regex_flags,
            textual_explanation=textual_explanation,
        )

    def _deny_list_to_regex(self, deny_list: List[str]) -> Pattern:
        """Convert a list of exact words into a single Pattern."""
        escaped = [re.escape(word) for word in deny_list]
        regex = r"(?:^|(?<=\W))(" + "|".join(escaped) + r")(?:(?=\W)|$)"
        return Pattern(
            name="deny_list",
            regex=regex,
            score=self.deny_list_score,
        )

    def _analyze_patterns(
        self,
        text: str,
        flags: Optional[int] = None,
    ) -> List[RecognizerResult]:
        """Run all configured patterns against *text* and return results."""
        flags = flags if flags is not None else self.global_regex_flags
        results: List[RecognizerResult] = []

        entity_type = self.supported_entities[0]
        profile = SCORE_PROFILES.get(entity_type)

        for pattern in self.patterns:
            match_start_time = datetime.datetime.now()

            if (
                pattern.compiled_regex is None
                or pattern.compiled_with_flags != flags
            ):
                pattern.compiled_with_flags = flags
                pattern.compiled_regex = re.compile(pattern.regex, flags=flags)

            matches = pattern.compiled_regex.finditer(text)
            elapsed = datetime.datetime.now() - match_start_time
            logger.debug(
                "--- match_time[%s]: %.6f seconds",
                pattern.name,
                elapsed.total_seconds(),
            )

            for match in matches:
                start, end = match.span()
                matched_text = text[start:end]
                if not matched_text:
                    continue

                score = pattern.score

                validation_result = self.validate_result(matched_text)
                explanation = self.build_regex_explanation(
                    recognizer_name=self.name,
                    pattern_name=pattern.name,
                    pattern=pattern.regex,
                    original_score=score,
                    validation_result=validation_result,
                    regex_flags=flags,
                )
                pattern_result = RecognizerResult(
                    entity_type=self.supported_entities[0],
                    start=start,
                    end=end,
                    score=score,
                    analysis_explanation=explanation,
                    recognition_metadata={
                        RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                        RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                    },
                )

                if validation_result is not None:
                    if validation_result:
                        pattern_result.score = (
                            profile.validated if profile is not None else self.MAX_SCORE
                        )
                    else:
                        pattern_result.score = self.MIN_SCORE

                invalidation_result = self.invalidate_result(matched_text)
                if invalidation_result is not None and invalidation_result:
                    pattern_result.score = self.MIN_SCORE

                if pattern_result.score > self.MIN_SCORE:
                    results.append(pattern_result)

                explanation.score = pattern_result.score

        return EntityRecognizer.remove_duplicates(results)

    def to_dict(self) -> Dict:
        """Serialize configuration to a dictionary."""
        return_dict = super().to_dict()
        return_dict["patterns"] = [p.to_dict() for p in self.patterns]
        return_dict["deny_list"] = self.deny_list
        return_dict["context"] = self.context
        return_dict["supported_entity"] = return_dict.pop("supported_entities")[0]
        return return_dict

    @classmethod
    def from_dict(cls, entity_recognizer_dict: Dict) -> "PatternRecognizer":
        """Create an instance from a serialised dictionary."""
        d = dict(entity_recognizer_dict)

        patterns = d.get("patterns")
        if patterns:
            d["patterns"] = [Pattern.from_dict(p) for p in patterns]

        if "supported_entity" in d and "supported_entities" in d:
            raise ValueError(
                "Both 'supported_entity' and 'supported_entities' present. "
                "Provide only one."
            )
        if "supported_entities" in d:
            entities = d.pop("supported_entities")
            if entities and "supported_entity" not in d:
                d["supported_entity"] = entities[0]

        return cls(**d)


# ---------------------------------------------------------------------------
# InternalNlpArtifacts
# ---------------------------------------------------------------------------

class InternalNlpArtifacts:
    """
    Lightweight NLP artifacts container consumed by BaseSpacyRecognizer.

    GuardAnalyzer builds one of these per request from the spaCy Doc, using
    _MappedSpan wrappers so that label remapping is transparent to the
    recognizer layer.

    :param entities: List of span-like objects exposing ``.label_``,
        ``.start_char``, and ``.end_char``.
    :param scores: Per-entity confidence scores (same length as entities).
    """

    __slots__ = ("entities", "scores")

    def __init__(self, entities: List, scores: List[float]):
        self.entities = entities
        self.scores = scores


# ---------------------------------------------------------------------------
# BaseSpacyRecognizer
# ---------------------------------------------------------------------------

class BaseSpacyRecognizer(EntityRecognizer):
    """
    Abstract base class for spaCy NER-based PII recognizers.

    Subclasses declare which entity labels they support and may override
    ``analyze()`` to add post-processing (e.g. false-positive filtering).

    GuardAnalyzer remaps raw Dutch spaCy labels to canonical names before
    building InternalNlpArtifacts, so subclasses receive ready-to-use labels
    (e.g. "PERSON", "LOCATION") without needing their own mapping.

    :param supported_entities: Canonical entity type labels to detect.
    :param ner_strength: Default confidence score (default 0.85).
    :param supported_language: ISO-639-1 language code (default "nl").
    :param name: Optional recognizer name (defaults to class name).
    :param version: Recognizer version string.
    """

    DEFAULT_EXPLANATION = (
        "Identified as {} by spaCy Named Entity Recognition"
    )

    def __init__(
        self,
        supported_entities: List[str],
        ner_strength: float = 0.85,
        supported_language: str = "nl",
        name: Optional[str] = None,
        version: str = "0.0.1",
    ):
        self.ner_strength = ner_strength
        super().__init__(
            supported_entities=supported_entities,
            name=name,
            supported_language=supported_language,
            version=version,
        )

    def load(self) -> None:  # noqa: D102
        pass

    def build_explanation(
        self,
        original_score: float,
        explanation_text: str,
    ) -> AnalysisExplanation:
        """Build an AnalysisExplanation for a NER detection."""
        return AnalysisExplanation(
            recognizer=self.name,
            original_score=original_score,
            textual_explanation=explanation_text,
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts: Optional[InternalNlpArtifacts] = None,
    ) -> List[RecognizerResult]:
        """
        Extract NER entities from *nlp_artifacts* and return RecognizerResults.

        Entities in nlp_artifacts have already been remapped to canonical
        labels (e.g. PER→PERSON) by GuardAnalyzer before this method is called.

        :param text: The original text (used for building result objects).
        :param entities: Entity types requested for this analysis pass.
        :param nlp_artifacts: InternalNlpArtifacts produced by GuardAnalyzer.
            If None, an empty list is returned.
        :return: List of RecognizerResult.
        """
        if not nlp_artifacts:
            logger.warning(
                "Skipping %s — nlp_artifacts not provided.", self.name
            )
            return []

        results: List[RecognizerResult] = []

        for ner_entity, ner_score in zip(
            nlp_artifacts.entities, nlp_artifacts.scores
        ):
            entity_label = ner_entity.label_

            if entity_label not in self.supported_entities:
                continue
            if entities and entity_label not in entities:
                continue

            explanation_text = self.DEFAULT_EXPLANATION.format(entity_label)
            explanation = self.build_explanation(ner_score, explanation_text)

            result = RecognizerResult(
                entity_type=entity_label,
                start=ner_entity.start_char,
                end=ner_entity.end_char,
                score=ner_score,
                analysis_explanation=explanation,
                recognition_metadata={
                    RecognizerResult.RECOGNIZER_NAME_KEY: self.name,
                    RecognizerResult.RECOGNIZER_IDENTIFIER_KEY: self.id,
                },
            )
            results.append(result)

        return results
