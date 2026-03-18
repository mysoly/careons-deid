"""VEHICLE_IDENTIFIER group recognizers: LICENCE_PLATE."""
from zorgdeid.recognizers.base import PatternRecognizer

from zorgdeid.config.scoring import SCORE_PROFILES
from zorgdeid.patterns.dutch_patterns import NL_PLATE_STRICT
from zorgdeid.recognizers._helpers import _p

_LP = SCORE_PROFILES["LICENCE_PLATE"]


class NlLicencePlateRecognizer(PatternRecognizer):
    PATTERNS = [_p("nl_plate_strict", NL_PLATE_STRICT, _LP.base)]
    CONTEXT = [
        "kenteken", "nummerplaat", "nummerbord", "voertuig",
        "auto", "kentekenplaat", "kentekenbewijs", "chassisnummer", "vin",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="LICENCE_PLATE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
