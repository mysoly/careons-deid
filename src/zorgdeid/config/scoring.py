"""
Centralised score profiles for every supported Dutch PII entity type.

Each EntityScoreProfile encodes three canonical confidence tiers:

  base           – regex match alone, no surrounding context, no algorithmic
                   validation.  Used as the Pattern score inside PatternRecognizer
                   subclasses and as the starting score for custom EntityRecognizers.

  with_context   – score expected after PatternRecognizer's context-window boost
                   or after DutchContextEnhancer applies a ContextBoostRule.
                   For PatternRecognizer subclasses this is informational; for
                   EntityRecognizer subclasses that inspect context manually it
                   is used directly.

  validated      – score assigned when an algorithmic check passes (elfproef for
                   BSN, Luhn for IMEI / credit-card, format tiers for HEALTH_IDENTIFIER).
                   Always ≥ with_context.

  high_confidence – optional fourth tier for entities where both context AND
                    validation are satisfied simultaneously (e.g. BSN found next to
                    the word "BSN" AND passes elfproef).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


RECOGNIZER_WINDOW_CHARS: int = 120


@dataclass(frozen=True)
class EntityScoreProfile:
    base: float
    with_context: float
    validated: float
    high_confidence: Optional[float] = None


# ---------------------------------------------------------------------------
# Profiles — one entry per entity in ALL_NL_ENTITY_TYPES
# ---------------------------------------------------------------------------

SCORE_PROFILES: dict[str, EntityScoreProfile] = {
    # ── spaCy NER ────────────────────────────────────────────────────────────
    "PERSON":           EntityScoreProfile(base=0.85, with_context=0.90, validated=0.90),
    "LOCATION":         EntityScoreProfile(base=0.85, with_context=0.90, validated=0.90),

    # ── Temporal ─────────────────────────────────────────────────────────────
    "DATE":             EntityScoreProfile(base=0.30, with_context=0.65, validated=0.85),
    "TIME":             EntityScoreProfile(base=0.45, with_context=0.70, validated=0.70),

    # ── Contact ──────────────────────────────────────────────────────────────
    "PHONE_NUMBER":     EntityScoreProfile(base=0.30, with_context=0.60, validated=0.70),
    "EMAIL_ADDRESS":    EntityScoreProfile(base=0.90, with_context=0.95, validated=0.95),
    "ZIPCODE":          EntityScoreProfile(base=0.55, with_context=0.75, validated=0.75),
    "URL":              EntityScoreProfile(base=0.70, with_context=0.85, validated=0.85),

    # ── Financial ────────────────────────────────────────────────────────────
    "IBAN_CODE":        EntityScoreProfile(base=0.75, with_context=0.90, validated=0.90),
    "CREDIT_CARD":       EntityScoreProfile(base=0.30, with_context=0.65, validated=0.85, high_confidence=0.95),

    # ── Healthcare ───────────────────────────────────────────────────────────
    "HEALTH_IDENTIFIER": EntityScoreProfile(base=0.30, with_context=0.60, validated=0.85, high_confidence=0.90),

    # ── Identity ─────────────────────────────────────────────────────────────
    "BSN":              EntityScoreProfile(base=0.30, with_context=0.65, validated=0.85, high_confidence=0.95),
    "PASSPORT":         EntityScoreProfile(base=0.65, with_context=0.85, validated=0.85),
    "IMEI":             EntityScoreProfile(base=0.40, with_context=0.70, validated=0.85, high_confidence=0.95),
    "LICENCE_PLATE":    EntityScoreProfile(base=0.60, with_context=0.80, validated=0.80),

    # ── Network ──────────────────────────────────────────────────────────────
    "IP_ADDRESS":       EntityScoreProfile(base=0.60, with_context=0.80, validated=0.80),
    "MAC_ADDRESS":      EntityScoreProfile(base=0.60, with_context=0.80, validated=0.80),

    # ── Geo ──────────────────────────────────────────────────────────────────
    "GPS_COORDINATES":  EntityScoreProfile(base=0.65, with_context=0.85, validated=0.85),
}
