"""
tests/test_basic.py
-------------------
Smoke and functional tests for zorgdeid.

Covers:
    - Package-level imports and metadata
    - analyze.text()  — detection API, filters, thresholds
    - guard.text()    — all three guard modes (anonymize / tag / i_tag)
    - analyze.doc()   — .txt / .pdf / .docx files
    - guard.doc()     — document guarding
    - custom_pattern()— custom recognizer detection and anonymization
    - Config validation — unknown keys, bad score_threshold, bad mode
    - Error handling  — UnsupportedFormatError, FileNotFoundError
"""

import os

import pytest

import zorgdeid
from zorgdeid import (
    ALL_NL_ENTITY_TYPES,
    UnsupportedFormatError,
    analyze,
    custom_pattern,
    guard,
)

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

BSN_TEXT   = "Patiënt BSN: 999999990"
EMAIL_TEXT = "Stuur een mail naar jan.devries@umcg.nl voor meer informatie."
IBAN_TEXT  = "Rekeningnummer: NL91 ABNA 0417 1643 00"
PHONE_TEXT = "Bel ons op 020-5551234 voor een afspraak."
RICH_TEXT  = (
    "Patiënt: Jan de Vries, BSN 999999990. "
    "IBAN: NL91 ABNA 0417 1643 00. "
    "E-mail: jan.devries@umcg.nl. "
    "Telefoon: 06-12345678."
)

_FILES = os.path.join(os.path.dirname(__file__), "..", "examples", "files")
TXT_FILE  = os.path.normpath(os.path.join(_FILES, "medisch_verslag.txt"))
PDF_FILE  = os.path.normpath(os.path.join(_FILES, "medisch_verslag.pdf"))
DOCX_FILE = os.path.normpath(os.path.join(_FILES, "medisch_verslag.docx"))


# ===========================================================================
# 1 — Package metadata
# ===========================================================================

def test_version_exists():
    assert isinstance(zorgdeid.__version__, str)
    assert zorgdeid.__version__ != ""


def test_all_nl_entity_types_is_list():
    assert isinstance(ALL_NL_ENTITY_TYPES, list)
    assert len(ALL_NL_ENTITY_TYPES) > 0
    assert len(set(ALL_NL_ENTITY_TYPES)) == len(ALL_NL_ENTITY_TYPES)  # no duplicates
    assert "UNK_NUMBER" not in ALL_NL_ENTITY_TYPES  # internal entity must not be exposed


def test_all_nl_entity_types_contains_core_entities():
    required = {"PERSON", "BSN", "IBAN_CODE", "EMAIL_ADDRESS", "PHONE_NUMBER", "DATE"}
    assert required.issubset(set(ALL_NL_ENTITY_TYPES))


# ===========================================================================
# 2 — analyze.text()
# ===========================================================================

def test_analyze_text_returns_list():
    assert isinstance(analyze.text(BSN_TEXT), list)


def test_analyze_text_finding_structure():
    results = analyze.text(BSN_TEXT)
    assert len(results) > 0
    for r in results:
        assert set(r.keys()) >= {"type", "start", "end", "score"}
        assert isinstance(r["type"], str)
        assert isinstance(r["start"], int)
        assert isinstance(r["end"], int)
        assert isinstance(r["score"], float)
        assert r["start"] < r["end"]
        assert 0.0 <= r["score"] <= 1.0


def test_analyze_text_detects_bsn():
    types = [r["type"] for r in analyze.text(BSN_TEXT)]
    assert "BSN" in types


def test_analyze_text_detects_email():
    types = [r["type"] for r in analyze.text(EMAIL_TEXT)]
    assert "EMAIL_ADDRESS" in types


def test_analyze_text_detects_iban():
    types = [r["type"] for r in analyze.text(IBAN_TEXT)]
    assert "IBAN_CODE" in types


def test_analyze_text_detects_phone():
    types = [r["type"] for r in analyze.text(PHONE_TEXT)]
    assert "PHONE_NUMBER" in types


def test_analyze_text_empty_string():
    assert analyze.text("") == []


def test_analyze_text_no_pii_returns_list():
    assert isinstance(analyze.text("De zon schijnt vandaag prachtig."), list)


def test_analyze_text_score_threshold_filters():
    all_results  = analyze.text(RICH_TEXT, config={"score_threshold": 0.0})
    high_results = analyze.text(RICH_TEXT, config={"score_threshold": 0.9})
    assert len(high_results) <= len(all_results)


def test_analyze_text_keep_filter():
    results = analyze.text(RICH_TEXT, config={"set_entities": {"keep": ["BSN"]}})
    named_types = {r["type"] for r in results if r["type"] in set(ALL_NL_ENTITY_TYPES)}
    assert named_types.issubset({"BSN"})


def test_analyze_text_ignore_filter():
    results = analyze.text(RICH_TEXT, config={"set_entities": {"ignore": ["BSN"]}})
    assert "BSN" not in {r["type"] for r in results}


# ===========================================================================
# 3 — guard.text()
# ===========================================================================

def _assert_guard_shape(result: dict) -> None:
    assert isinstance(result, dict)
    assert "guarded_text" in result
    assert "findings" in result
    assert isinstance(result["guarded_text"], str)
    assert isinstance(result["findings"], list)
    for f in result["findings"]:
        assert set(f.keys()) >= {"type", "start", "end", "score", "original_text"}


def test_guard_text_default_is_anonymize():
    result = guard.text(BSN_TEXT)
    _assert_guard_shape(result)
    assert len(result["findings"]) > 0
    assert result["guarded_text"] != BSN_TEXT


def test_guard_text_anonymize_mode():
    result = guard.text(BSN_TEXT, config={"mode": "anonymize"})
    _assert_guard_shape(result)
    assert result["guarded_text"] != BSN_TEXT


def test_guard_text_tag_mode():
    result = guard.text(BSN_TEXT, config={"mode": "tag"})
    _assert_guard_shape(result)
    assert "[BSN]" in result["guarded_text"]


def test_guard_text_i_tag_mode():
    result = guard.text(BSN_TEXT, config={"mode": "i_tag"})
    _assert_guard_shape(result)
    assert "[BSN_1]" in result["guarded_text"]


def test_guard_text_findings_have_original_text():
    result = guard.text(RICH_TEXT)
    for f in result["findings"]:
        assert f["original_text"] != ""


def test_guard_text_empty_string():
    result = guard.text("")
    assert result["guarded_text"] == ""
    assert result["findings"] == []


# ===========================================================================
# 4 — analyze.doc() and guard.doc()
# ===========================================================================

@pytest.mark.skipif(not os.path.exists(TXT_FILE), reason="sample .txt not found")
def test_analyze_doc_txt():
    results = analyze.doc(TXT_FILE)
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.skipif(not os.path.exists(PDF_FILE), reason="sample .pdf not found")
def test_analyze_doc_pdf():
    results = analyze.doc(PDF_FILE)
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.skipif(not os.path.exists(DOCX_FILE), reason="sample .docx not found")
def test_analyze_doc_docx():
    results = analyze.doc(DOCX_FILE)
    assert isinstance(results, list)
    assert len(results) > 0


@pytest.mark.skipif(not os.path.exists(TXT_FILE), reason="sample .txt not found")
def test_guard_doc_txt_tag_mode():
    result = guard.doc(TXT_FILE, config={"mode": "tag"})
    _assert_guard_shape(result)
    assert len(result["guarded_text"]) > 0


# ===========================================================================
# 5 — custom_pattern()
# ===========================================================================

def test_custom_pattern_returns_dict():
    p = custom_pattern(name="EMPLOYEE_ID", regex=r"EMP-\d{4}")
    assert isinstance(p, dict)
    assert p["name"] == "EMPLOYEE_ID"
    assert p["regex"] == r"EMP-\d{4}"
    assert isinstance(p["score"], float)


def test_custom_pattern_detection():
    p = custom_pattern(name="EMPLOYEE_ID", regex=r"EMP-\d{4}", score=0.9)
    results = analyze.text(
        "Medewerker EMP-1234 heeft toegang.",
        config={"custom_patterns": [p]},
    )
    assert "EMPLOYEE_ID" in [r["type"] for r in results]


def test_custom_pattern_guard_tag_mode():
    p = custom_pattern(name="EMPLOYEE_ID", regex=r"EMP-\d{4}", score=0.9)
    result = guard.text(
        "Medewerker EMP-1234 heeft toegang.",
        config={"custom_patterns": [p], "mode": "tag"},
    )
    assert "[EMPLOYEE_ID]" in result["guarded_text"]


def test_custom_pattern_guard_anonymize_with_list():
    p = custom_pattern(
        name="EMPLOYEE_ID",
        regex=r"EMP-\d{4}",
        score=0.9,
        anonymize_list=["EMP-0000"],
    )
    result = guard.text(
        "Medewerker EMP-1234 heeft toegang.",
        config={"custom_patterns": [p], "mode": "anonymize"},
    )
    assert "EMP-1234" not in result["guarded_text"]


def test_custom_pattern_stores_context():
    p = custom_pattern(
        name="EMPLOYEE_ID",
        regex=r"\d{4}",
        score=0.5,
        context=["medewerker", "employee"],
    )
    assert p["context"] == ["medewerker", "employee"]


# ===========================================================================
# 6 — Error handling
# ===========================================================================

def test_unsupported_format_raised_before_file_exists():
    """Extension check must fire before the file-existence check."""
    with pytest.raises(UnsupportedFormatError):
        analyze.doc("/nonexistent/path/report.csv")


def test_file_not_found_for_supported_extension():
    with pytest.raises(FileNotFoundError):
        analyze.doc("/nonexistent/path/report.txt")


def test_unknown_config_key_analyze():
    with pytest.raises(ValueError, match="unknown config key"):
        analyze.text("test", config={"bogus_key": True})


def test_unknown_config_key_guard():
    with pytest.raises(ValueError, match="unknown config key"):
        guard.text("test", config={"bogus_key": True})


def test_invalid_score_threshold_type():
    with pytest.raises(TypeError):
        analyze.text("test", config={"score_threshold": "hoog"})


def test_invalid_score_threshold_above_one():
    with pytest.raises(ValueError):
        analyze.text("test", config={"score_threshold": 1.5})


def test_invalid_score_threshold_below_zero():
    with pytest.raises(ValueError):
        analyze.text("test", config={"score_threshold": -0.1})


def test_invalid_guard_mode():
    with pytest.raises(ValueError, match="Unknown guard mode"):
        guard.text("test", config={"mode": "verwijder"})


# ===========================================================================
# 7 — Grouped-labels system removed
# ===========================================================================

def test_label_groups_not_importable():
    assert not hasattr(zorgdeid, "LABEL_GROUPS")


def test_grouped_labels_key_raises_in_analyze():
    with pytest.raises(ValueError, match="unknown config key"):
        analyze.text(BSN_TEXT, config={"grouped_labels": True})


def test_grouped_labels_key_raises_in_guard():
    with pytest.raises(ValueError, match="unknown config key"):
        guard.text(BSN_TEXT, config={"grouped_labels": True})


def test_analyze_finding_has_no_sub_label():
    results = analyze.text(RICH_TEXT)
    for r in results:
        assert "sub_label" not in r


def test_guard_finding_has_no_sub_label():
    result = guard.text(RICH_TEXT)
    for f in result["findings"]:
        assert "sub_label" not in f


def test_tag_mode_uses_raw_entity_label():
    result = guard.text(IBAN_TEXT, config={"mode": "tag"})
    assert "[IBAN_CODE]" in result["guarded_text"]
    assert "[FINANCIAL]" not in result["guarded_text"]


def test_i_tag_mode_uses_raw_entity_label():
    result = guard.text(IBAN_TEXT, config={"mode": "i_tag"})
    assert "[IBAN_CODE_1]" in result["guarded_text"]
    assert "[FINANCIAL_1]" not in result["guarded_text"]
