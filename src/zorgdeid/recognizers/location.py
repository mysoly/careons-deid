"""LOCATION group recognizers: ZIPCODE, GPS_COORDINATES."""
from zorgdeid.recognizers.base import PatternRecognizer

from zorgdeid.config.scoring import SCORE_PROFILES
from zorgdeid.patterns.dutch_patterns import ZIP_REGEX_NL, GPS_REGEX
from zorgdeid.recognizers._helpers import _p

_ZI = SCORE_PROFILES["ZIPCODE"]
_GP = SCORE_PROFILES["GPS_COORDINATES"]


class NlZipcodeRecognizer(PatternRecognizer):
    PATTERNS = [_p("nl_zip", ZIP_REGEX_NL, _ZI.base)]
    CONTEXT = ["postcode", "zip", "pc", "postadres", "huisnummer", "woonplaats"]

    def __init__(self):
        super().__init__(
            supported_entity="ZIPCODE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlGpsRecognizer(PatternRecognizer):
    PATTERNS = [_p("gps", GPS_REGEX, _GP.base)]
    CONTEXT = [
        "gps", "coördinaten", "locatie", "coordinates", "location",
        "lengtegraad", "breedtegraad", "lat", "lon", "latitude", "longitude",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="GPS_COORDINATES",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
