"""
Dutch-specific regex patterns for PII detection.
Covers dates, phones, emails, zip codes, financial data,
BSN, passport, IP, licence plates, MAC,
websites, IMEI, time, GPS, and health identifiers.
"""

from zorgdeid.patterns.dutch_keywords import DATE_MONTHS_NL, DATE_MONTHS_EN

# ──────────────────────────── DATES ────────────────────────────
DATE_WITHOUT_WORDS_NL = (
    r"\b(?:\d{4}[/-]\d{1,2}[/-]\d{1,2}"
    r"|\d{4}\.\d{1,2}\.\d{1,2}"
    r"|\d{1,2}[/-]\d{1,2}[/-]\d{4}"
    r"|\d{1,2}\.\d{1,2}\.\d{4}"
    r"|\d{1,2}\.\d{1,2}\.\d{2})\b"
)

DATE_DD_MM_YY = (
    r"\b(0?[1-9]|[12]\d|30|31)[^\w\d\r\n:]"
    r"(0?[1-9]|1[0-2])[^\w\d\r\n:](\d{4}|\d{2})\b"
)

DATE_YY_MM_DD = (
    r"\b(\d{2}|\d{4})[^\w\d\r\n:]"
    r"(0?[1-9]|1[0-2])[^\w\d\r\n:](0?[1-9]|[12]\d|30|31)\b"
)

DATE_WITH_WORDS_NL = (
    r"(?i)\b(\d{1,2})\s+"
    f"({DATE_MONTHS_NL})"
    r"(?:\s+\d{4})?\b"
)

DATE_WORDS_FUZZY_NL = (
    r"(?i)\b(\d{1,2})\s+([a-zA-Z]{3,10})\s+(\d{4})\b"
)

# ISO-8601 timestamp: 2024-03-15T13:45:00  (with optional fractional seconds)
DATE_ISO_TIMESTAMP = (
    r"\b\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?\b"
)

# English ordinal dates: "July 21st, 1998" / "21st July 1998" / "March 3rd, 1979"
_MONTHS_EN = DATE_MONTHS_EN
_ORDINAL   = r"\d{1,2}(?:st|nd|rd|th)"
DATE_EN_ORDINAL = (
    r"(?i)\b(?:"
    rf"(?:{_MONTHS_EN})\s+{_ORDINAL},?\s*\d{{4}}"
    rf"|{_ORDINAL}\s+(?:{_MONTHS_EN}),?\s*\d{{4}}"
    r")\b"
)

# English month + day + year (no ordinal): "July 4 1776" / "December 25, 2023"
DATE_EN_WORDS = (
    r"(?i)\b(?:"
    rf"(?:{_MONTHS_EN})\s+\d{{1,2}},?\s*\d{{4}}"
    rf"|\d{{1,2}}\s+(?:{_MONTHS_EN}),?\s*\d{{4}}"
    r")\b"
)

# ──────────────────────────── PHONE ────────────────────────────
# Structured EU/NL format: +CC [AAA] NNNN NNNN — space or dash or dot separators.
# (?<!\w) instead of \b so that +CC numbers preceded by space/punctuation are matched
# (a bare \b never fires before '+' when the preceding char is also non-word).
EU_PHONES = r"(?<!\w)(?:\+|00)\d{1,3}[\s.\-]?(?:\(?\d{2,3}\)?[\s.\-]?)?\d{3,4}[\s.\-]?\d{4}\b"

# Flexible international: +CC followed by 2–5 digit groups separated by space/dot/dash.
# Minimum 2 additional groups ensures total digits >= ~8, limiting false positives.
PHONE_INTL = r"\+\d{1,3}(?:[\s.\-]\d{1,6}){2,5}\b"

# Dutch local numbers starting with 0 or country-code prefix — space, dash, or dot.
LOCAL_PHONES = (
    r"\b(?:0\d{0,3}|00\d{1,3}|\+\d{1,3})"
    r"[\s.\-]?\d{1,4}(?:[\s.\-]?\d{2,4}){1,3}\b"
)

PHONE_NL_MOBILE = r"\+31[\s\-]?6[\s\-]?\d{1}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"

# ──────────────────────────── EMAIL ────────────────────────────
EMAIL_REGEX = (
    r"[a-zA-Z0-9._%+-]+@"
    r"(?:\[(?:\d{1,3}\.){3}\d{1,3}\]"
    r"|(?:[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})*|[a-zA-Z0-9-]+))"
)

# ──────────────────────────── ZIPCODE ──────────────────────────
ZIP_REGEX_NL = r"\b\d{4}\s?[A-Za-z]{2}\b"

# ──────────────────────────── FINANCIAL ────────────────────────
IBAN_REGEX_NL = r"\b[A-Z]{2}\d{2}\s?[A-Z]{4}\s?\d{4}\s?\d{4}\s?\d{2}\b"

VISA_CREDIT_REGEX        = r"\b4\d{3}(?:[\s\-]?\d{4}){3}\b"
MASTERCARD_REGEX         = r"\b5[1-5]\d{2}(?:[\s\-]?\d{4}){3}\b"
AMERICAN_EXPRESS_REGEX   = r"\b3[47]\d{2}[\s\-]?\d{6}[\s\-]?\d{5}\b"
DINERS_REGEX             = r"\b3(?:0[0-5]|[68]\d)\d[\s\-]?\d{6}[\s\-]?\d{4}\b"
DISCOVER_REGEX           = r"\b6(?:011|5\d{2})(?:[\s\-]?\d{4}){3}\b"
JCB_REGEX                = r"\b(?:2131|1800|35\d{2})(?:[\s\-]?\d{4}){3}\b"

# ──────────────────────────── BSN (Dutch SSN) ──────────────────
BSN_REGEX_NL = r"\b\d{9}\b"

# ──────────────────────────── PASSPORT / LICENCE ───────────────
PASSPORT_LICENCE_NL = r"(?i)\b[A-Z]{2}[A-Z0-9]{6}[0-9]\b"

# ──────────────────────────── IP ADDRESS ───────────────────────
IPV4_REGEX = r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"

# Full (8-group) and compressed (::) IPv6 forms.
# The compressed branch matches 0–7 leading groups, the :: separator, and
# 0–7 trailing groups — making "::1", "fe80::1", and all valid shortenings
# detectable.
IPV6_REGEX = (
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:)*::(?::[0-9a-fA-F]{1,4})*"
    r"|::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}"
    r"|::)"
    r"\b"
)

# ──────────────────────────── LICENCE PLATES (NL) ──────────────
# https://en.wikipedia.org/wiki/Vehicle_registration_plates_of_the_Netherlands
NL_PLATE_STRICT = r"""(?ix)
\b
(?:
    [A-Z]{2}(?:-|\ )\d{2}(?:-|\ )\d{2} |
    \d{2}(?:-|\ )\d{2}(?:-|\ )[A-Z]{2} |
    \d{2}(?:-|\ )[A-Z]{2}(?:-|\ )\d{2} |
    [A-Z]{2}(?:-|\ )\d{2}(?:-|\ )[A-Z]{2} |
    [A-Z]{2}(?:-|\ )[A-Z]{2}(?:-|\ )\d{2} |
    \d{2}(?:-|\ )[A-Z]{2}(?:-|\ )[A-Z]{2} |
    [A-Z](?:-|\ )\d{3}(?:-|\ )[A-Z]{2} |
    [A-Z]{2}(?:-|\ )\d{3}(?:-|\ )[A-Z] |
    \d{2}(?:-|\ )[A-Z]{3}(?:-|\ )[1-9] |
    [1-9](?:-|\ )[A-Z]{3}(?:-|\ )\d{2} |
    [A-Z]{3}(?:-|\ )\d{2}(?:-|\ )[A-Z] |
    [A-Z](?:-|\ )\d{2}(?:-|\ )[A-Z]{3} |
    [1-9](?:-|\ )[A-Z]{2}(?:-|\ )\d{3}
)
\b
"""

# ──────────────────────────── MAC ADDRESS ──────────────────────
MAC_REGEX = r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"

# ──────────────────────────── WEBSITE / URL ────────────────────
# Schemed URLs: http(s)://... or ftp://...  (any domain, high confidence)
# Path excludes bare '.' and ',' so sentence-ending punctuation is not swallowed.
WEBSITE_REGEX = (
    r"(?:https?|ftp)://(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
    r"(?::\d+)?(?:/[\w~;/\\?%&=#-]*)?"
)

# Schemeless www.* URLs: www.example.com[/path]
WEBSITE_REGEX_WWW = (
    r"\bwww\.(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"
    r"(?::\d+)?(?:/[\w~;/\\?%&=#-]*)?"
)

# ──────────────────────────── IMEI ─────────────────────────────
IMEI_REGEX = r"\b\d{15}\b"

# ──────────────────────────── TIME ─────────────────────────────
TIME_REGEX = (
    r"(?i)\b(?:"
    r"(?:1[0-2]|0?[1-9])[:\.][0-5]\d\s*(?:AM|PM|a\.m\.|p\.m\.)"
    r"|(?:[01]?\d|2[0-3])\s*(?:uur|u\.?)\s*(?:[0-5]\d)?"
    r"|(?:[01]?\d|2[0-3])[:\.][0-5]\d(?:[:\.][0-5]\d)?"
    r")\b"
)

# ──────────────────────────── GPS COORDINATES ──────────────────
GPS_REGEX = r"-?\d{1,3}\.\d{3,8}\s*[,;]\s*-?\d{1,3}\.\d{3,8}"

# ──────────────────────────── ZORGPOLIS NUMBER ─────────────────
# Numeric-only policy number (10–12 digits).
ZORGPOLIS_NUMERIC = r"\b\d{10,12}\b"
# Alphanumeric: 1–4 uppercase letters followed by 6–10 digits (e.g. Z123456789, ZP100200300, VGZ987654321).
ZORGPOLIS_ALPHA = r"\b[A-Z]{1,4}\d{6,10}\b"
# Grouped format: 4-4-2..4 digit blocks (e.g. 1234-5678-9012, 9876-5432-10).
ZORGPOLIS_GROUPED = r"\b\d{4}-\d{4}-\d{2,4}\b"
# Alpha-prefixed year-dash format: ZP-2022-045678, ZPN-1122-3344 (2+ letters + year group + digit group).
ZORGPOLIS_ALPHA_YEAR_DASH = r"\b[A-Z]{2,4}-\d{4}-\d{4,8}\b"
# Alpha-prefixed triple-grouped format: ZPN-1122-3344-55 (2+ letters + 3 digit groups).
ZORGPOLIS_ALPHA_GROUPED_DASH = r"\b[A-Z]{2,4}-\d{4}-\d{4}-\d{2,4}\b"
# Single-letter dash format: Z-987654321 (1–2 letters + dash + 8–12 digits).
ZORGPOLIS_ALPHA_SIMPLE_DASH = r"\b[A-Z]{1,2}-\d{8,12}\b"

# ──────────────────────────── UNKNOWN NUMBER (catch-all) ───────
# These patterns fire on any digit sequence not already claimed by a dedicated
# recognizer.  Score is kept below every other entity's base score so that
# resolve_overlaps always evicts UNK_NUMBER when a real entity overlaps.
UNK_NUMBER_COMPACT = r"\b\d{3,}\b"
UNK_NUMBER_GROUPED = r"\b\d{2,6}(?:[ \t]\d{2,6})+\b"
