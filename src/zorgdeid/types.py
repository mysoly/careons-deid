"""
Core data-structure types for PII detection and anonymization.

Classes
-------
AnalysisExplanation  – tracing information for a PII detection decision
RecognizerResult     – a single PII finding (entity type, span, score)
Pattern              – a named regex pattern with a confidence score
OperatorConfig       – anonymization operator configuration
"""

from __future__ import annotations

import json
import logging
import math
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# AnalysisExplanation
# ---------------------------------------------------------------------------

class AnalysisExplanation:
    """
    Hold tracing information to explain why PII entities were identified as such.

    :param recognizer: name of recognizer that made the decision
    :param original_score: recognizer's confidence in result
    :param pattern_name: name of pattern
            (if decision was made by a PatternRecognizer)
    :param pattern: regex pattern that was applied (if PatternRecognizer)
    :param validation_result: result of a validation (e.g. checksum)
    :param textual_explanation: Free text for describing
            a decision of a logic or model
    :param regex_flags: regex flags used during matching
    """

    def __init__(
        self,
        recognizer: str,
        original_score: float,
        pattern_name: Optional[str] = None,
        pattern: Optional[str] = None,
        validation_result: Optional[float] = None,
        textual_explanation: Optional[str] = None,
        regex_flags: Optional[int] = None,
    ):
        self.recognizer = recognizer
        self.pattern_name = pattern_name
        self.pattern = pattern
        self.original_score = original_score
        self.score = original_score
        self.textual_explanation = textual_explanation
        self.score_context_improvement = 0
        self.supportive_context_word = ""
        self.validation_result = validation_result
        self.regex_flags = regex_flags

    def __repr__(self) -> str:
        return str(self.__dict__)

    def set_improved_score(self, score: float) -> None:
        """Update the score and calculate the difference from the original score."""
        self.score = score
        self.score_context_improvement = self.score - self.original_score

    def set_supportive_context_word(self, word: str) -> None:
        """Set the context word which helped increase the score."""
        self.supportive_context_word = word

    def append_textual_explanation_line(self, text: str) -> None:
        """Append a new line to textual_explanation field."""
        if self.textual_explanation is None:
            self.textual_explanation = text
        else:
            self.textual_explanation = f"{self.textual_explanation}\n{text}"

    def to_dict(self) -> Dict:
        """Serialize self to dictionary."""
        return self.__dict__


# ---------------------------------------------------------------------------
# RecognizerResult
# ---------------------------------------------------------------------------

class RecognizerResult:
    """
    Recognizer Result represents the findings of the detected entity.

    Result of a recognizer analyzing the text.

    :param entity_type: the type of the entity
    :param start: the start location of the detected entity
    :param end: the end location of the detected entity
    :param score: the score of the detection
    :param analysis_explanation: contains the explanation of why this
                                 entity was identified
    :param recognition_metadata: a dictionary of metadata to be used in
    recognizer specific cases, for example specific recognized context words
    and recognizer name
    """

    RECOGNIZER_NAME_KEY = "recognizer_name"
    RECOGNIZER_IDENTIFIER_KEY = "recognizer_identifier"

    IS_SCORE_ENHANCED_BY_CONTEXT_KEY = "is_score_enhanced_by_context"

    def __init__(
        self,
        entity_type: str,
        start: int,
        end: int,
        score: float,
        analysis_explanation: Optional[AnalysisExplanation] = None,
        recognition_metadata: Optional[Dict] = None,
    ):
        self.entity_type = entity_type
        self.start = start
        self.end = end
        self.score = score
        self.analysis_explanation = analysis_explanation

        if not recognition_metadata:
            logger.debug(
                "recognition_metadata should be passed, "
                "containing a recognizer_name value"
            )

        self.recognition_metadata = recognition_metadata

    def append_analysis_explanation_text(self, text: str) -> None:
        """Add text to the analysis explanation."""
        if self.analysis_explanation:
            self.analysis_explanation.append_textual_explanation_line(text)

    def to_dict(self) -> Dict:
        """Serialize self to dictionary."""
        return self.__dict__

    @classmethod
    def from_json(cls, data: Dict) -> "RecognizerResult":
        """
        Create RecognizerResult from json.

        :param data: e.g. {
            "start": 24,
            "end": 32,
            "score": 0.8,
            "entity_type": "NAME"
        }
        :return: RecognizerResult
        :raises ValueError: if any required key is missing or has wrong type
        """
        required = ("entity_type", "start", "end", "score")
        missing = [k for k in required if k not in data]
        if missing:
            raise ValueError(
                f"RecognizerResult.from_json missing required key(s): {missing}"
            )
        if not isinstance(data["start"], int) or not isinstance(data["end"], int):
            raise ValueError("'start' and 'end' must be integers")
        if not isinstance(data["score"], (int, float)):
            raise ValueError("'score' must be a number")
        return cls(
            entity_type=data["entity_type"],
            start=data["start"],
            end=data["end"],
            score=float(data["score"]),
        )

    def __repr__(self) -> str:
        return self.__str__()

    def intersects(self, other: "RecognizerResult") -> int:
        """
        Check if self intersects with a different RecognizerResult.

        :return: If intersecting, returns the number of
        intersecting characters.
        If not, returns 0
        """
        if self.end < other.start or other.end < self.start:
            return 0
        return min(self.end, other.end) - max(self.start, other.start)

    def contained_in(self, other: "RecognizerResult") -> bool:
        """Check if self is contained in a different RecognizerResult."""
        return self.start >= other.start and self.end <= other.end

    def contains(self, other: "RecognizerResult") -> bool:
        """Check if one result is contained or equal to another result."""
        return self.start <= other.start and self.end >= other.end

    def equal_indices(self, other: "RecognizerResult") -> bool:
        """Check if the indices are equal between two results."""
        return self.start == other.start and self.end == other.end

    def __gt__(self, other: "RecognizerResult") -> bool:
        if self.start == other.start:
            return self.end > other.end
        return self.start > other.start

    def __eq__(self, other: "RecognizerResult") -> bool:
        if not isinstance(other, RecognizerResult):
            return NotImplemented
        equal_type = self.entity_type == other.entity_type
        equal_score = math.isclose(self.score, other.score, rel_tol=1e-9)
        return self.equal_indices(other) and equal_type and equal_score

    def __hash__(self) -> int:
        return hash(
            f"{str(self.start)} {str(self.end)} {str(self.score)} {self.entity_type}"
        )

    def __str__(self) -> str:
        return (
            f"type: {self.entity_type}, "
            f"start: {self.start}, "
            f"end: {self.end}, "
            f"score: {self.score}"
        )

    def has_conflict(self, other: "RecognizerResult") -> bool:
        """
        Check if two recognizer results are conflicted or not.

        I have a conflict if:
        1. My indices are the same as the other and my score is lower.
        2. If my indices are contained in another.
        """
        if self.equal_indices(other):
            return self.score <= other.score
        return other.contains(self)


# ---------------------------------------------------------------------------
# Pattern
# ---------------------------------------------------------------------------

class Pattern:
    """
    A class that represents a regex pattern.

    :param name: the name of the pattern
    :param regex: the regex pattern to detect
    :param score: the pattern's strength (values varies 0-1)
    """

    def __init__(self, name: str, regex: str, score: float):
        self.name = name
        self.regex = regex
        self.score = score
        # Mutable cache fields set by the pattern-matching engine at runtime
        self.compiled_regex = None
        self.compiled_with_flags = None

        self.__validate_regex(self.regex)
        self.__validate_score(self.score)

    @staticmethod
    def __validate_regex(pattern: str) -> None:
        try:
            re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")

    @staticmethod
    def __validate_score(score: float) -> None:
        if score < 0 or score > 1:
            raise ValueError(
                f"Invalid score: {score}. Score should be between 0 and 1"
            )

    def to_dict(self) -> Dict:
        """Turn this instance into a dictionary."""
        return {"name": self.name, "score": self.score, "regex": self.regex}

    @classmethod
    def from_dict(cls, pattern_dict: Dict) -> "Pattern":
        """Load an instance from a dictionary."""
        return cls(**pattern_dict)

    def __repr__(self) -> str:
        return json.dumps(self.to_dict())

    def __str__(self) -> str:
        return json.dumps(self.to_dict())


# ---------------------------------------------------------------------------
# OperatorConfig
# ---------------------------------------------------------------------------

class OperatorConfig:
    """Hold the data of the required anonymization operator."""

    def __init__(self, operator_name: str, params: Optional[Dict] = None):
        """
        Create an operator config instance.

        :param operator_name: the name of the operator we want to work with
        :param params: the parameters the operator needs in order to work
        """
        if not operator_name:
            raise ValueError(
                "operator config requires a non-empty operator_name"
            )
        self.operator_name = operator_name
        self.params = params if params else {}

    def __repr__(self) -> str:
        return f"operator_name: {self.operator_name}, params: {self.params}"

    @classmethod
    def from_json(cls, params: Dict) -> "OperatorConfig":
        """
        Create OperatorConfig from json.

        :param params: json e.g.: {"type": "mask", "masking_char": "*", ...}
        :return: OperatorConfig
        """
        operator_name = params.get("type")
        if operator_name:
            params = dict(params)
            params.pop("type")
        return cls(operator_name, params)

    def __eq__(self, other: "OperatorConfig") -> bool:
        if not isinstance(other, OperatorConfig):
            return NotImplemented
        return self.operator_name == other.operator_name and self.params == other.params

    def __hash__(self) -> int:
        return hash(self.operator_name)
