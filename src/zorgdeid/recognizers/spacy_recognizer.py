"""
Custom spaCy-based recognizer for standard NER (PERSON, LOCATION).
"""
import re
from typing import List

from zorgdeid.recognizers.base import BaseSpacyRecognizer
from zorgdeid.types import RecognizerResult


class NlNerRecognizer(BaseSpacyRecognizer):
    """
    Dutch NER recognizer using the nl_core_news_lg spaCy model.

    Entity label remapping (PER→PERSON, LOC/GPE→LOCATION) is handled
    upstream by GuardAnalyzer before InternalNlpArtifacts are passed here.

    False-positive filter: rejects spans that look like document IDs
    (e.g. NT7654321), label abbreviations (e.g. Rijbewijsnr.), digit-only
    strings, or time strings.
    """

    ENTITIES = ["PERSON", "LOCATION"]

    _ID_PATTERN    = re.compile(r'^[A-Z]{1,3}\d{5,}$', re.IGNORECASE)
    _LABEL_PATTERN = re.compile(r'(?i)^.*nrs?\.?$')
    _DIGITS_ONLY   = re.compile(r'^\d+$')
    _TIME_PATTERN  = re.compile(r'^\d{1,2}:\d{2}(?::\d{2})?$')

    def __init__(self):
        super().__init__(
            supported_entities=self.ENTITIES,
            supported_language="nl",
            ner_strength=0.85,
        )

    @classmethod
    def _is_false_positive(cls, span: str) -> bool:
        s = span.strip()
        return bool(
            cls._ID_PATTERN.match(s)
            or cls._LABEL_PATTERN.match(s)
            or cls._DIGITS_ONLY.match(s)
            or cls._TIME_PATTERN.match(s)
        )

    def analyze(
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None,
    ) -> List[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts)
        return [
            r for r in results
            if not self._is_false_positive(text[r.start: r.end])
        ]
