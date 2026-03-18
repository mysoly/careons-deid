"""FINANCIAL group recognizers: IBAN_CODE, CREDIT_CARD."""
import re
from typing import List, Tuple

from zorgdeid.recognizers.base import EntityRecognizer
from zorgdeid.types import RecognizerResult

from zorgdeid.config.scoring import SCORE_PROFILES, RECOGNIZER_WINDOW_CHARS
from zorgdeid.patterns.dutch_patterns import (
    IBAN_REGEX_NL,
    VISA_CREDIT_REGEX, MASTERCARD_REGEX,
    AMERICAN_EXPRESS_REGEX, DINERS_REGEX, DISCOVER_REGEX, JCB_REGEX,
)
from zorgdeid.recognizers._utils import luhn_check, validate_iban

_IB = SCORE_PROFILES["IBAN_CODE"]
_CC = SCORE_PROFILES["CREDIT_CARD"]


# ---------------------------------------------------------------------------
# IBAN — mod-97 validated
# ---------------------------------------------------------------------------

_IBAN_RE = re.compile(IBAN_REGEX_NL)


class NlIbanRecognizer(EntityRecognizer):
    """IBAN recognizer with ISO 13616 mod-97 checksum validation."""

    CONTEXT_WORDS = {
        "iban", "rekening", "bankrekeningnummer", "rekeningnummer",
        "bank", "bic", "swift", "giro", "gironummer", "betaalrekening",
    }

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    def __init__(self):
        super().__init__(supported_entities=["IBAN_CODE"], supported_language="nl")

    def load(self):
        pass

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "IBAN_CODE" not in entities:
            return []
        results = []
        for match in _IBAN_RE.finditer(text):
            raw = match.group(0)
            if not validate_iban(raw):
                continue
            lo = max(0, match.start() - self._WINDOW)
            hi = min(len(text), match.end() + self._WINDOW)
            window = text[lo:hi].lower()
            has_ctx = any(kw in window for kw in self.CONTEXT_WORDS)
            score = _IB.with_context if has_ctx else _IB.base
            results.append(
                RecognizerResult(
                    entity_type="IBAN_CODE",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                )
            )
        return results


# ---------------------------------------------------------------------------
# CREDIT CARD — Luhn-validated
# ---------------------------------------------------------------------------

_CC_SPECIFIC: List[Tuple[re.Pattern, str]] = [
    (re.compile(VISA_CREDIT_REGEX),        "Visa"),
    (re.compile(MASTERCARD_REGEX),         "Mastercard"),
    (re.compile(AMERICAN_EXPRESS_REGEX),   "Amex"),
    (re.compile(DINERS_REGEX),             "Diners"),
    (re.compile(DISCOVER_REGEX),           "Discover"),
    (re.compile(JCB_REGEX),                "JCB"),
]


class NlCreditCardRecognizer(EntityRecognizer):
    """
    Detects credit card numbers using network-specific regex patterns and
    validates each match with the Luhn algorithm.  Non-Luhn matches are discarded.
    """

    def __init__(self):
        super().__init__(
            supported_entities=["CREDIT_CARD"],
            supported_language="nl",
        )

    def load(self):
        pass

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "CREDIT_CARD" not in entities:
            return []

        results: List[RecognizerResult] = []
        covered: List[Tuple[int, int]] = []

        for pattern, _network in _CC_SPECIFIC:
            for match in pattern.finditer(text):
                ms, me = match.start(), match.end()
                if any(cs <= ms and me <= ce for cs, ce in covered):
                    continue

                digits = re.sub(r"[\s\-]", "", match.group(0))
                if luhn_check(digits):
                    results.append(
                        RecognizerResult(
                            entity_type="CREDIT_CARD",
                            start=ms,
                            end=me,
                            score=_CC.validated,
                        )
                    )
                    covered.append((ms, me))

        return results
