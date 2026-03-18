"""DATETIME group recognizers: DATE, TIME."""
from zorgdeid.recognizers.base import PatternRecognizer

from zorgdeid.config.scoring import SCORE_PROFILES
from zorgdeid.patterns.dutch_patterns import (
    DATE_WITHOUT_WORDS_NL, DATE_DD_MM_YY, DATE_YY_MM_DD,
    DATE_WITH_WORDS_NL, DATE_WORDS_FUZZY_NL,
    DATE_ISO_TIMESTAMP, DATE_EN_ORDINAL, DATE_EN_WORDS,
    TIME_REGEX,
)
from zorgdeid.recognizers._helpers import _p

_D = SCORE_PROFILES["DATE"]
_T = SCORE_PROFILES["TIME"]


class NlDateRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("date_iso_ts",      DATE_ISO_TIMESTAMP,    0.90),
        _p("date_en_ordinal",  DATE_EN_ORDINAL,       0.80),
        _p("date_en_words",    DATE_EN_WORDS,         0.75),
        _p("date_words_nl",    DATE_WITH_WORDS_NL,    _D.validated),
        _p("date_numeric",     DATE_WITHOUT_WORDS_NL, 0.60),
        _p("date_dd_mm_yy",    DATE_DD_MM_YY,         0.50),
        _p("date_yy_mm_dd",    DATE_YY_MM_DD,         0.50),
        _p("date_words_fuzzy", DATE_WORDS_FUZZY_NL,   _D.base),
    ]
    CONTEXT = [
        "datum", "geboortedatum", "date", "geboren", "overlijdensdatum",
        "dag", "maand", "jaar", "vervaldatum", "startdatum", "einddatum",
        "dagtekening", "verlopen", "exp", "expiry", "geldig",
        "birthday", "birth", "born",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="DATE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlTimeRecognizer(PatternRecognizer):
    PATTERNS = [_p("time_nl", TIME_REGEX, _T.base)]
    CONTEXT = [
        "tijd", "uur", "time", "om", "rond", "tijdstip",
        "minuut", "seconde", "aanvang", "eindtijd",
        "bijgewerkt", "geparkeerd", "inlog", "klokslag",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="TIME",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
