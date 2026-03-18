"""
Dutch-specific keywords for PII detection.
Extracted from dutch_patterns.py for better maintainability.
"""

# DATE MONTHS
DATE_MONTHS_NL = (
    r"januari|jan|februari|feb|maart|mar|april|mei|juni|jun|juli|jul"
    r"|augustus|aug|september|sep|oktober|okt|november|nov|december|dec"
)

# English month names (for cross-lingual / ISO-locale datasets)
DATE_MONTHS_EN = (
    r"january|february|march|april|may|june|july"
    r"|august|september|october|november|december"
)
