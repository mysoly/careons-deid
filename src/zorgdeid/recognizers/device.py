"""DEVICE_IDENTIFIER group recognizers: IP_ADDRESS, MAC_ADDRESS, IMEI."""
import re
from typing import List

from zorgdeid.recognizers.base import EntityRecognizer, PatternRecognizer
from zorgdeid.types import AnalysisExplanation, RecognizerResult

from zorgdeid.config.scoring import SCORE_PROFILES, RECOGNIZER_WINDOW_CHARS
from zorgdeid.patterns.dutch_patterns import IPV4_REGEX, IPV6_REGEX, MAC_REGEX, IMEI_REGEX
from zorgdeid.recognizers._helpers import _p
from zorgdeid.recognizers._utils import luhn_check

_IP = SCORE_PROFILES["IP_ADDRESS"]
_MA = SCORE_PROFILES["MAC_ADDRESS"]
_IM = SCORE_PROFILES["IMEI"]


class NlIpRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("ipv4", IPV4_REGEX, _IP.base),
        _p("ipv6", IPV6_REGEX, _IP.base),
    ]
    CONTEXT = [
        "ip", "ip-adres", "ip address", "ipv4",
        "ipv6", "netwerk", "host", "serveradres",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="IP_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlMacAddressRecognizer(PatternRecognizer):
    PATTERNS = [_p("mac", MAC_REGEX, _MA.base)]
    CONTEXT = [
        "mac", "mac-adres", "mac address",
        "bssid", "fysiek adres", "hardware adres",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="MAC_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlImeiRecognizer(EntityRecognizer):
    """
    IMEI recognizer with Luhn checksum validation.

    Context boosting is applied manually in analyze() by inspecting the
    surrounding character window.
    """

    _WINDOW = RECOGNIZER_WINDOW_CHARS

    _POSITIVE_CONTEXT = {
        "imei", "apparaat", "device", "telefoon", "serienummer",
        "sim", "telefoonidentiteit", "imei-nummer",
    }

    def __init__(self):
        super().__init__(supported_entities=["IMEI"], supported_language="nl")

    def load(self):
        pass

    def _window_lower(self, text: str, start: int, end: int) -> str:
        lo = max(0, start - self._WINDOW)
        hi = min(len(text), end + self._WINDOW)
        return text[lo:hi].lower()

    def analyze(
        self, text: str, entities: List[str], nlp_artifacts=None
    ) -> List[RecognizerResult]:
        if entities and "IMEI" not in entities:
            return []
        results = []
        for match in re.finditer(IMEI_REGEX, text):
            if not luhn_check(match.group(0)):
                continue
            window = self._window_lower(text, match.start(), match.end())
            score = (
                _IM.high_confidence
                if any(kw in window for kw in self._POSITIVE_CONTEXT)
                else _IM.validated
            )
            results.append(
                RecognizerResult(
                    entity_type="IMEI",
                    start=match.start(),
                    end=match.end(),
                    score=score,
                    analysis_explanation=AnalysisExplanation(
                        recognizer=self.__class__.__name__,
                        original_score=score,
                        pattern_name="imei_15digit_luhn",
                        pattern=IMEI_REGEX,
                        validation_result=True,
                    ),
                )
            )
        return results
