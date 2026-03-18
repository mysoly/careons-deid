"""
Shared validation utilities used across multiple recognizer modules.
Centralised here to avoid code duplication.
"""

from __future__ import annotations


def luhn_check(digits: str) -> bool:
    """Return True if *digits* (only digit characters) satisfy the Luhn algorithm.

    Used by IMEI and credit-card recognizers.
    """
    total = 0
    for i, d in enumerate(reversed(digits)):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def validate_iban(raw: str) -> bool:
    """Validate an IBAN string using the ISO 13616 mod-97 algorithm.

    The input may contain spaces (e.g. "NL29 INGB 0123 4567 89").
    Returns True only when the check-digit equation holds.
    """
    iban = raw.replace(" ", "").upper()
    if len(iban) < 15:
        return False

    rearranged = iban[4:] + iban[:4]
    numeric = "".join(
        str(ord(ch) - ord("A") + 10) if ch.isalpha() else ch
        for ch in rearranged
    )
    return int(numeric) % 97 == 1
