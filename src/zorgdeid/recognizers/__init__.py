"""
Recognizer registry for zorgdeid.

Imports every domain recognizer and exports:
  - ALL_REGEX_RECOGNIZERS  – ordered list of recognizer *classes* (not instances)
    passed to GuardAnalyzer at engine initialisation.
  - Individual classes re-exported for direct import convenience.
"""

from zorgdeid.recognizers.datetime import NlDateRecognizer, NlTimeRecognizer
from zorgdeid.recognizers.contact import (
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlUrlRecognizer,
)
from zorgdeid.recognizers.location import NlZipcodeRecognizer, NlGpsRecognizer
from zorgdeid.recognizers.identifier import (
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlHealthIdentifierRecognizer,
)
from zorgdeid.recognizers.financial import (
    NlIbanRecognizer,
    NlCreditCardRecognizer,
)
from zorgdeid.recognizers.device import (
    NlIpRecognizer,
    NlMacAddressRecognizer,
    NlImeiRecognizer,
)
from zorgdeid.recognizers.vehicle import NlLicencePlateRecognizer
from zorgdeid.recognizers.spacy_recognizer import NlNerRecognizer

ALL_REGEX_RECOGNIZERS = [
    # ── DATETIME ─────────────────────────────────────────────────
    NlDateRecognizer,
    NlTimeRecognizer,
    # ── CONTACT ──────────────────────────────────────────────────
    NlPhoneRecognizer,
    NlEmailRecognizer,
    NlUrlRecognizer,
    # ── LOCATION ─────────────────────────────────────────────────
    NlZipcodeRecognizer,
    NlGpsRecognizer,
    # ── IDENTIFIER ───────────────────────────────────────────────
    NlBsnRecognizer,
    NlPassportRecognizer,
    NlHealthIdentifierRecognizer,
    # ── FINANCIAL ────────────────────────────────────────────────
    NlIbanRecognizer,
    NlCreditCardRecognizer,
    # ── DEVICE_IDENTIFIER ────────────────────────────────────────
    NlIpRecognizer,
    NlMacAddressRecognizer,
    NlImeiRecognizer,
    # ── VEHICLE_IDENTIFIER ───────────────────────────────────────
    NlLicencePlateRecognizer,
]

__all__ = [
    "ALL_REGEX_RECOGNIZERS",
    "NlNerRecognizer",
    "NlDateRecognizer",
    "NlTimeRecognizer",
    "NlPhoneRecognizer",
    "NlEmailRecognizer",
    "NlUrlRecognizer",
    "NlZipcodeRecognizer",
    "NlGpsRecognizer",
    "NlBsnRecognizer",
    "NlPassportRecognizer",
    "NlHealthIdentifierRecognizer",
    "NlIbanRecognizer",
    "NlCreditCardRecognizer",
    "NlIpRecognizer",
    "NlMacAddressRecognizer",
    "NlImeiRecognizer",
    "NlLicencePlateRecognizer",
]
