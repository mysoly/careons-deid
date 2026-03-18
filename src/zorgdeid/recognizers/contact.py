"""CONTACT group recognizers: PHONE_NUMBER, EMAIL_ADDRESS, URL."""
import re
from typing import Optional

from zorgdeid.recognizers.base import PatternRecognizer

from zorgdeid.config.scoring import SCORE_PROFILES
from zorgdeid.patterns.dutch_patterns import (
    EU_PHONES, PHONE_INTL, LOCAL_PHONES, PHONE_NL_MOBILE,
    EMAIL_REGEX, WEBSITE_REGEX, WEBSITE_REGEX_WWW,
)
from zorgdeid.recognizers._helpers import _p

_DATE_LIKE = re.compile(
    r"^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$"
    r"|^\d{1,2}[-/.]\d{4}$"
    r"|^\d{1,2}[-/.]\d{1,2}$",
)
_MIN_PHONE_DIGITS = 7  # real NL numbers always have ≥7 digits

_PH = SCORE_PROFILES["PHONE_NUMBER"]
_EM = SCORE_PROFILES["EMAIL_ADDRESS"]
_UR = SCORE_PROFILES["URL"]


class NlPhoneRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("nl_mobile",   PHONE_NL_MOBILE, 0.70),
        _p("eu_phone",    EU_PHONES,       0.40),
        _p("intl_phone",  PHONE_INTL,      0.35),
        _p("local_phone", LOCAL_PHONES,    _PH.base),
    ]
    CONTEXT = [
        "telefoon", "tel", "mobiel", "phone", "bel", "gsm",
        "nummer", "telefoonnummer", "06", "contactnummer",
        "werktelefoon", "whatsapp",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )

    def invalidate_result(self, pattern_text: str) -> Optional[bool]:
        text = pattern_text.strip()
        if _DATE_LIKE.match(text):
            return True
        if sum(c.isdigit() for c in text) < _MIN_PHONE_DIGITS:
            return True
        return None


class NlEmailRecognizer(PatternRecognizer):
    PATTERNS = [_p("email", EMAIL_REGEX, _EM.base)]
    CONTEXT = [
        "e-mail", "email", "mail", "e-mailadres",
        "emailadres", "mailadres", "contact",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="EMAIL_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )


class NlUrlRecognizer(PatternRecognizer):
    PATTERNS = [
        _p("url_schemed", WEBSITE_REGEX,     _UR.base),
        _p("url_www",     WEBSITE_REGEX_WWW, _UR.base),
    ]
    CONTEXT = [
        "website", "url", "link", "site",
        "webpagina", "webadres", "domein", "domeinnaam",
    ]

    def __init__(self):
        super().__init__(
            supported_entity="URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="nl",
        )
