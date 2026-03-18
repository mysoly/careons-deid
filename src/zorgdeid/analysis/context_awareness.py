"""
Rule-based context-awareness engine for post-processing PII detection scores.

Architecture
------------
Each ContextBoostRule describes *for a single entity type* how to decide whether
surrounding text supports or contradicts a finding, and by how much to adjust
its score.

Look-up strategies
  match_in_span=True   – search the matched span itself for fuzzy vocabulary
                         (used for DATE: the span contains the month name)
  match_in_span=False  – search a character window around the span
                         (used for most other entity types)

Sentence-awareness
  sentence_aware=True  – further clip the character window to the sentence that
                         contains the entity, preventing cross-sentence context
                         leakage (ignored when match_in_span=True)

Vocabulary tiers
  vocabulary           – strong evidence: applies the full boost
  fuzzy_vocab          – strong evidence via fuzzy matching (SequenceMatcher)
  weak_vocabulary      – weak evidence: applies boost * weak_factor

Negative context
  negative_vocabulary  – contradicting evidence: subtracts penalty from score.
                         Negative matching always uses a surrounding window,
                         even when match_in_span=True.

Adding support for a new entity type requires only appending one or more
ContextBoostRule entries to CONTEXT_BOOST_RULES – no engine code changes.
"""

from __future__ import annotations

import difflib
import logging
from copy import copy
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from zorgdeid.types import AnalysisExplanation, RecognizerResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule definition
# ---------------------------------------------------------------------------

@dataclass
class ContextBoostRule:
    """
    Declarative rule that governs score adjustment for one entity type.

    Positive boost attributes
    -------------------------
    entity_type     : entity label this rule applies to (e.g. "DATE")
    vocabulary      : strong-evidence substrings; any hit triggers a full boost
    weak_vocabulary : weak-evidence substrings; any hit triggers a partial boost
    weak_factor     : fraction of ``boost`` applied for a weak-vocabulary hit
    fuzzy_vocab     : reference words for fuzzy matching (SequenceMatcher);
                      a hit is counted as strong evidence
    fuzzy_threshold : minimum similarity ratio to count as a fuzzy hit
    boost           : score delta for a full/fuzzy hit; capped at 1.0
    only_if_below   : skip positive boosting when current score already meets
                      or exceeds this value — prevents double-boosting

    Negative penalty attributes
    ---------------------------
    negative_vocabulary : contradicting substrings; any hit applies a penalty
    penalty             : score delta to subtract on a negative hit; floored
                          at 0.0
    only_if_above       : skip penalising when current score is at or below
                          this value — prevents penalising already-uncertain
                          results

    Search-area attributes
    ----------------------
    match_in_span   : True  → search inside the matched span (positive vocab)
                      False → search in a character window around the span
    window          : half-window size in characters (match_in_span=False only)
    sentence_aware  : True  → further clip the window to the sentence that
                      contains the entity, preventing cross-sentence leakage
                      (applies to both window-based positive and negative checks)
    """

    entity_type: str

    # Positive boost
    vocabulary: List[str] = field(default_factory=list)
    weak_vocabulary: List[str] = field(default_factory=list)
    weak_factor: float = 0.5
    fuzzy_vocab: List[str] = field(default_factory=list)
    fuzzy_threshold: float = 0.80
    boost: float = 0.35
    only_if_below: Optional[float] = None

    # Negative penalty
    negative_vocabulary: List[str] = field(default_factory=list)
    penalty: float = 0.0
    only_if_above: Optional[float] = None

    # Search area
    match_in_span: bool = True
    window: int = 80
    sentence_aware: bool = True


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

CONTEXT_BOOST_RULES: List[ContextBoostRule] = [

    # ── DATE ─────────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="DATE",
        fuzzy_vocab=[
            "januari", "jan", "februari", "feb", "maart", "mar",
            "april", "apr", "mei", "juni", "jun", "juli", "jul",
            "augustus", "aug", "september", "sep", "oktober", "okt",
            "november", "nov", "december", "dec",
        ],
        fuzzy_threshold=0.75,
        boost=0.45,
        only_if_below=0.50,
        match_in_span=True,
    ),

    # ── TIME ─────────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="TIME",
        vocabulary=["uur", "tijdstip", "aanvang", "eindtijd", "klokslag"],
        weak_vocabulary=["tijd", "om", "minuut", "klok"],
        boost=0.25,
        only_if_below=0.60,
        match_in_span=False,
        window=60,
        sentence_aware=True,
    ),

    # ── PHONE_NUMBER ─────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="PHONE_NUMBER",
        vocabulary=[
            "telefoonnummer", "telefoon", "mobiel", "gsm",
            "whatsapp", "contactnummer", "werktelefoon", "tel",
        ],
        weak_vocabulary=["bel", "06", "nummer"],
        boost=0.30,
        only_if_below=0.50,
        match_in_span=False,
        window=80,
        sentence_aware=True,
        negative_vocabulary=[
            "kamer", "factuurnummer", "ordernummer",
            "artikelnummer", "polisnummer", "klantnummer",
        ],
        penalty=0.15,
        only_if_above=0.30,
    ),

    # ── ZIPCODE ──────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="ZIPCODE",
        vocabulary=["postcode", "postadres", "zip"],
        weak_vocabulary=["adres", "straat", "huisnummer", "woonplaats"],
        boost=0.20,
        only_if_below=0.70,
        match_in_span=False,
        window=80,
        sentence_aware=True,
        negative_vocabulary=["kamer", "modelnummer", "artikelnummer", "typenummer"],
        penalty=0.10,
        only_if_above=0.40,
    ),

    # ── GPS_COORDINATES ──────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="GPS_COORDINATES",
        vocabulary=[
            "gps", "coördinaten", "coordinates",
            "lat", "lon", "latitude", "longitude",
            "lengtegraad", "breedtegraad",
        ],
        weak_vocabulary=["locatie", "location", "positie", "kaart"],
        boost=0.25,
        only_if_below=0.80,
        match_in_span=False,
        window=80,
        sentence_aware=True,
    ),

    # ── PERSON ───────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="PERSON",
        vocabulary=[
            "naam", "voornaam", "achternaam", "dhr", "mevr",
            "de heer", "mevrouw", "patiënt", "verzekerde",
            "ondergetekende",
        ],
        weak_vocabulary=[
            "persoon", "klant", "cliënt", "medewerker", "werknemer",
            "contactpersoon", "bewoner", "eigenaar", "verdachte", "betrokkene",
        ],
        boost=0.05,
        only_if_below=0.90,
        match_in_span=False,
        window=80,
        sentence_aware=True,
        negative_vocabulary=["bedrijf", "organisatie", "instelling", "instantie", "afdeling"],
        penalty=0.05,
        only_if_above=0.85,
    ),

    # ── LOCATION ─────────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="LOCATION",
        vocabulary=[
            "adres", "woonplaats", "woonadres", "gevestigd",
            "woonachtig", "vestigingsplaats", "verblijfplaats",
        ],
        weak_vocabulary=[
            "stad", "gemeente", "provincie", "straat", "wijk",
            "buurt", "regio", "locatie", "standplaats", "vestiging",
        ],
        boost=0.05,
        only_if_below=0.90,
        match_in_span=False,
        window=80,
        sentence_aware=True,
    ),

    # ── CREDIT_CARD ──────────────────────────────────────────────────────────
    ContextBoostRule(
        entity_type="CREDIT_CARD",
        vocabulary=[
            "creditcard", "credit card", "kaartnummer", "kaarthouder",
            "betalingsgegevens", "visa", "mastercard", "amex",
            "american express", "debetkaart", "kaartgegevens",
        ],
        weak_vocabulary=["betalen", "betaalkaart", "pinpas", "kaart"],
        boost=0.10,
        only_if_below=0.90,
        match_in_span=False,
        window=80,
        sentence_aware=True,
        negative_vocabulary=["test", "voorbeeld", "demo", "fictief", "testdata"],
        penalty=0.20,
        only_if_above=0.50,
    ),
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class DutchContextEnhancer:
    """
    Iterates over a list of RecognizerResults and applies every matching
    ContextBoostRule to raise or lower the score of uncertain findings.

    Custom rules can be injected at construction time; the default set is
    CONTEXT_BOOST_RULES defined above.
    """

    def __init__(self, rules: Optional[List[ContextBoostRule]] = None) -> None:
        self._rules_by_type: dict[str, list[ContextBoostRule]] = {}
        for rule in rules or CONTEXT_BOOST_RULES:
            self._rules_by_type.setdefault(rule.entity_type, []).append(rule)

    def enhance(
        self, text: str, results: List[RecognizerResult]
    ) -> List[RecognizerResult]:
        """
        Apply all matching boost / penalty rules to *results* and return the
        updated list.  Each adjusted result is shallow-copied before modification
        so the original RecognizerResult objects from the analyzer are never
        mutated.

        Execution order per result: all boost actions are applied first (using
        the original score for guard evaluation), then all penalty actions.
        """
        text_lower = text.lower()
        output: List[RecognizerResult] = []

        for res in results:
            rules = self._rules_by_type.get(res.entity_type, [])
            if not rules:
                output.append(res)
                continue

            boost_actions: List[Tuple[ContextBoostRule, float]] = []
            penalty_actions: List[ContextBoostRule] = []

            for rule in rules:
                # ── Positive boost ───────────────────────────────────────────
                can_boost = not (
                    rule.only_if_below is not None and res.score >= rule.only_if_below
                )
                if can_boost and (rule.vocabulary or rule.weak_vocabulary or rule.fuzzy_vocab):
                    factor = self._match_strength(text_lower, res, rule)
                    if factor > 0.0:
                        boost_actions.append((rule, factor))

                # ── Negative penalty ─────────────────────────────────────────
                can_penalise = (
                    bool(rule.negative_vocabulary)
                    and rule.penalty > 0.0
                    and not (
                        rule.only_if_above is not None and res.score <= rule.only_if_above
                    )
                )
                if can_penalise and self._has_negative(text_lower, res, rule):
                    penalty_actions.append(rule)

            if boost_actions or penalty_actions:
                res = copy(res)
                for rule, factor in boost_actions:
                    self._apply_boost(res, rule, factor)
                for rule in penalty_actions:
                    self._apply_penalty(res, rule)

            output.append(res)

        return output

    # ── Search-area helpers ─────────────────────────────────────────────────

    def _get_search_area(
        self, text_lower: str, res: RecognizerResult, rule: ContextBoostRule
    ) -> str:
        """Return the text fragment to search for positive-context vocabulary."""
        if rule.match_in_span:
            return text_lower[res.start : res.end]

        lo = max(0, res.start - rule.window)
        hi = min(len(text_lower), res.end + rule.window)
        if rule.sentence_aware:
            lo, hi = self._clip_to_sentence(text_lower, lo, hi, res.start, res.end)
        return text_lower[lo:hi]

    def _get_negative_area(
        self, text_lower: str, res: RecognizerResult, rule: ContextBoostRule
    ) -> str:
        """
        Return the window for negative-context checking.  Always uses a
        surrounding character window (never the span itself), with sentence
        clipping when sentence_aware is set.
        """
        lo = max(0, res.start - rule.window)
        hi = min(len(text_lower), res.end + rule.window)
        if rule.sentence_aware:
            lo, hi = self._clip_to_sentence(text_lower, lo, hi, res.start, res.end)
        return text_lower[lo:hi]

    @staticmethod
    def _clip_to_sentence(
        text_lower: str,
        lo: int,
        hi: int,
        entity_start: int,
        entity_end: int,
    ) -> Tuple[int, int]:
        """
        Clip [lo, hi] to the sentence containing [entity_start, entity_end].

        Sentence boundaries are approximated by the nearest ``.``, ``!``,
        ``?``, or newline character outside the entity span.  When no boundary
        is found within the original window, the window is returned unchanged.
        """

        sent_lo = lo
        for i in range(entity_start - 1, lo - 1, -1):
            if text_lower[i] in ".\n!?":
                sent_lo = i + 1

                while sent_lo < entity_start and text_lower[sent_lo] in " \t\r":
                    sent_lo += 1
                break


        sent_hi = hi
        for i in range(entity_end, hi):
            if text_lower[i] in ".\n!?":
                sent_hi = i + 1
                break

        return sent_lo, sent_hi

    # ── Match-strength ──────────────────────────────────────────────────────

    def _match_strength(
        self, text_lower: str, res: RecognizerResult, rule: ContextBoostRule
    ) -> float:
        """
        Return the match strength for positive-context vocabulary.

        Returns
        -------
        1.0              – strong vocabulary or fuzzy hit
        rule.weak_factor – weak vocabulary hit only
        0.0              – no match
        """
        search = self._get_search_area(text_lower, res, rule)

        if any(kw in search for kw in rule.vocabulary):
            return 1.0

        if rule.fuzzy_vocab:
            words = "".join(c if c.isalpha() else " " for c in search).split()
            for word in words:
                if len(word) < 3:
                    continue
                best_ratio = max(
                    (
                        difflib.SequenceMatcher(None, word, ref).ratio()
                        for ref in rule.fuzzy_vocab
                    ),
                    default=0.0,
                )
                if best_ratio >= rule.fuzzy_threshold:
                    logger.debug(
                        "ContextBoostRule(%s): fuzzy hit ratio=%.2f",
                        rule.entity_type,
                        best_ratio,
                    )
                    return 1.0

        if rule.weak_vocabulary and any(kw in search for kw in rule.weak_vocabulary):
            return rule.weak_factor

        return 0.0

    def _has_negative(
        self, text_lower: str, res: RecognizerResult, rule: ContextBoostRule
    ) -> bool:
        """Return True when any negative-context keyword is found in the window."""
        search = self._get_negative_area(text_lower, res, rule)
        return any(kw in search for kw in rule.negative_vocabulary)

    # ── Score adjusters ─────────────────────────────────────────────────────

    @staticmethod
    def _apply_boost(
        res: RecognizerResult, rule: ContextBoostRule, factor: float
    ) -> None:
        old = res.score
        effective_boost = rule.boost * factor
        res.score = min(1.0, old + effective_boost)

        expl = res.analysis_explanation
        if expl is None:
            expl = AnalysisExplanation(
                recognizer="DutchContextEnhancer",
                original_score=old,
            )
            res.analysis_explanation = expl

        strength = "strong" if factor >= 1.0 else f"weak ({factor:.2f}x)"
        expl.append_textual_explanation_line(
            f"ContextBoostRule({rule.entity_type}): "
            f"{old:.2f} → {res.score:.2f} (+{effective_boost:.2f}, {strength})"
        )

    @staticmethod
    def _apply_penalty(res: RecognizerResult, rule: ContextBoostRule) -> None:
        old = res.score
        res.score = max(0.0, old - rule.penalty)

        expl = res.analysis_explanation
        if expl is None:
            expl = AnalysisExplanation(
                recognizer="DutchContextEnhancer",
                original_score=old,
            )
            res.analysis_explanation = expl

        expl.append_textual_explanation_line(
            f"ContextPenaltyRule({rule.entity_type}): "
            f"{old:.2f} → {res.score:.2f} (-{rule.penalty:.2f})"
        )
