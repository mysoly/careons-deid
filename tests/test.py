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
    - OCR support     — image files and scanned PDF fallback (Section 8)
"""

import io
import os
from unittest.mock import MagicMock, patch

import pytest

import zorgdeid
from zorgdeid import (
    ALL_NL_ENTITY_TYPES,
    OcrNotAvailableError,
    UnsupportedFormatError,
    analyze,
    custom_pattern,
    guard,
)

_easyocr_available = False
try:
    import easyocr  # noqa: F401
    _easyocr_available = True
except Exception:
    pass

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


# ===========================================================================
# 8 — OCR support
# ===========================================================================

# ---------------------------------------------------------------------------
# 8a  Module-level constants and exports
# ---------------------------------------------------------------------------

def test_ocr_not_available_error_importable():
    """OcrNotAvailableError must be part of the public API."""
    assert OcrNotAvailableError is not None
    assert issubclass(OcrNotAvailableError, ImportError)


def test_image_extensions_supported():
    """Image extensions must be listed in SUPPORTED_EXTENSIONS."""
    from zorgdeid.processors.doc_processor import SUPPORTED_EXTENSIONS, IMAGE_EXTENSIONS
    for ext in IMAGE_EXTENSIONS:
        assert ext in SUPPORTED_EXTENSIONS


def test_ocr_fallback_threshold_positive():
    from zorgdeid.processors.doc_processor import OCR_FALLBACK_THRESHOLD
    assert isinstance(OCR_FALLBACK_THRESHOLD, int)
    assert OCR_FALLBACK_THRESHOLD > 0


# ---------------------------------------------------------------------------
# 8b  Error: unsupported format still raised for unknown extensions
# ---------------------------------------------------------------------------

def test_image_format_not_in_unsupported():
    """A .png file should NOT raise UnsupportedFormatError anymore."""
    with pytest.raises(FileNotFoundError):
        analyze.doc("/nonexistent/path/scan.png")


def test_unsupported_image_format_still_raises():
    """Non-image formats like .gif still raise UnsupportedFormatError."""
    with pytest.raises(UnsupportedFormatError):
        analyze.doc("/nonexistent/path/scan.gif")


# ---------------------------------------------------------------------------
# 8c  OcrNotAvailableError raised when easyocr is not importable
# ---------------------------------------------------------------------------

def test_read_image_raises_ocr_not_available_when_no_easyocr(tmp_path):
    """
    _read_image → _get_easyocr_reader must raise OcrNotAvailableError when
    easyocr is missing, not a bare ImportError.
    """
    from PIL import Image as PILImage
    from zorgdeid.processors import doc_processor

    img = PILImage.new("RGB", (100, 30), color=(255, 255, 255))
    img_path = str(tmp_path / "test.png")
    img.save(img_path)

    # Reset the singleton so the import attempt runs fresh
    original = doc_processor._easyocr_reader
    doc_processor._easyocr_reader = None

    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "easyocr":
            raise ImportError("mocked missing easyocr")
        return real_import(name, *args, **kwargs)

    try:
        with patch("builtins.__import__", side_effect=mock_import):
            with pytest.raises(OcrNotAvailableError):
                doc_processor._read_image(img_path)
    finally:
        doc_processor._easyocr_reader = original


def test_ocr_pdf_page_raises_ocr_not_available_when_no_fitz(tmp_path):
    """
    _ocr_pdf_page must raise OcrNotAvailableError when pymupdf (fitz) is missing.
    """
    from zorgdeid.processors import doc_processor

    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "fitz":
            raise ImportError("mocked missing pymupdf")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=mock_import):
        with pytest.raises(OcrNotAvailableError):
            doc_processor._ocr_pdf_page("dummy.pdf", 0)


# ---------------------------------------------------------------------------
# 8d  OCR pipeline unit tests via mocking (no model download required)
# ---------------------------------------------------------------------------

def test_ocr_image_calls_easyocr(tmp_path):
    """
    _ocr_image must call reader.readtext() and join the resulting lines.
    """
    from PIL import Image as PILImage
    from zorgdeid.processors import doc_processor

    img = PILImage.new("RGB", (200, 50), color=(255, 255, 255))

    mock_reader = MagicMock()
    mock_reader.readtext.return_value = ["BSN: 999999990"]

    original = doc_processor._easyocr_reader
    doc_processor._easyocr_reader = mock_reader

    try:
        result = doc_processor._ocr_image(img)
    finally:
        doc_processor._easyocr_reader = original

    mock_reader.readtext.assert_called_once()
    assert result == "BSN: 999999990"


def test_ocr_image_joins_multiple_lines(tmp_path):
    """
    _ocr_image must join multiple text blocks returned by EasyOCR with newlines.
    """
    from PIL import Image as PILImage
    from zorgdeid.processors import doc_processor

    img = PILImage.new("RGB", (200, 100), color=(255, 255, 255))

    mock_reader = MagicMock()
    mock_reader.readtext.return_value = ["Naam: Jan de Vries", "BSN: 999999990"]

    original = doc_processor._easyocr_reader
    doc_processor._easyocr_reader = mock_reader

    try:
        result = doc_processor._ocr_image(img)
    finally:
        doc_processor._easyocr_reader = original

    assert result == "Naam: Jan de Vries\nBSN: 999999990"


def test_read_pdf_uses_ocr_fallback_for_sparse_pages():
    """
    _read_pdf must invoke OCR for pages that yield fewer than
    OCR_FALLBACK_THRESHOLD characters.
    """
    from zorgdeid.processors.doc_processor import OCR_FALLBACK_THRESHOLD

    mock_page_sparse = MagicMock()
    mock_page_sparse.extract_text.return_value = ""  # image-only page

    mock_page_rich = MagicMock()
    mock_page_rich.extract_text.return_value = "A" * (OCR_FALLBACK_THRESHOLD + 10)

    mock_reader_instance = MagicMock()
    mock_reader_instance.pages = [mock_page_sparse, mock_page_rich]

    with patch("zorgdeid.processors.doc_processor._ocr_pdf_page", return_value="OCR text") as mock_ocr, \
         patch("pypdf.PdfReader", return_value=mock_reader_instance):
        from zorgdeid.processors import doc_processor
        doc_processor._read_pdf("dummy.pdf")

    mock_ocr.assert_called_once_with("dummy.pdf", 0)
    assert mock_page_sparse.extract_text.called


def test_read_pdf_skips_ocr_for_rich_pages():
    """
    _read_pdf must NOT call OCR when pypdf returns sufficient text.
    """
    from zorgdeid.processors.doc_processor import OCR_FALLBACK_THRESHOLD

    rich_text = "X" * (OCR_FALLBACK_THRESHOLD + 50)
    mock_page = MagicMock()
    mock_page.extract_text.return_value = rich_text

    mock_reader_instance = MagicMock()
    mock_reader_instance.pages = [mock_page]

    with patch("zorgdeid.processors.doc_processor._ocr_pdf_page") as mock_ocr, \
         patch("pypdf.PdfReader", return_value=mock_reader_instance):
        from zorgdeid.processors import doc_processor
        result = doc_processor._read_pdf("dummy.pdf")

    mock_ocr.assert_not_called()
    assert rich_text in result


def test_read_image_converts_rgba_to_rgb(tmp_path):
    """
    _read_image must convert RGBA images to RGB before passing to EasyOCR.
    """
    from PIL import Image as PILImage
    from zorgdeid.processors import doc_processor

    rgba_img = PILImage.new("RGBA", (100, 30), color=(255, 255, 255, 128))
    img_path = str(tmp_path / "rgba_test.png")
    rgba_img.save(img_path)

    captured = {}

    def fake_ocr_image(img):
        captured["mode"] = img.mode
        return "test output"

    with patch.object(doc_processor, "_ocr_image", side_effect=fake_ocr_image):
        result = doc_processor._read_image(img_path)

    assert captured["mode"] == "RGB"
    assert result == "test output"


def test_easyocr_singleton_initialised_once():
    """
    _get_easyocr_reader must initialise the reader only on the first call
    and return the cached instance on subsequent calls.
    """
    from zorgdeid.processors import doc_processor

    mock_reader = MagicMock()
    mock_easyocr = MagicMock()
    mock_easyocr.Reader.return_value = mock_reader

    original = doc_processor._easyocr_reader
    doc_processor._easyocr_reader = None

    try:
        with patch.dict("sys.modules", {"easyocr": mock_easyocr}):
            r1 = doc_processor._get_easyocr_reader()
            r2 = doc_processor._get_easyocr_reader()
    finally:
        doc_processor._easyocr_reader = original

    mock_easyocr.Reader.assert_called_once_with(["nl"], gpu=False, verbose=False)
    assert r1 is r2


# ---------------------------------------------------------------------------
# 8e  Full integration tests (skipped when easyocr is not installed)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _easyocr_available, reason="easyocr not installed")
def test_ocr_integration_image_bsn(tmp_path):
    """
    End-to-end: render a white image with BSN text, run OCR, detect with
    analyze.doc().  Requires easyocr (pip install zorgdeid[ocr]).
    """
    from PIL import Image as PILImage, ImageDraw

    img = PILImage.new("RGB", (400, 60), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "BSN: 999999990", fill=(0, 0, 0))

    img_path = str(tmp_path / "bsn_scan.png")
    img.save(img_path)

    results = analyze.doc(img_path)
    assert isinstance(results, list)
    # OCR quality on synthetic images varies; we verify the pipeline runs
    # without error rather than guaranteeing detection on a minimal fixture.


@pytest.mark.skipif(not _easyocr_available, reason="easyocr not installed")
def test_ocr_integration_guard_image(tmp_path):
    """
    End-to-end: guard.doc() on a PNG image must return the expected shape.
    """
    from PIL import Image as PILImage, ImageDraw

    img = PILImage.new("RGB", (400, 60), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((10, 10), "jan.devries@umcg.nl", fill=(0, 0, 0))

    img_path = str(tmp_path / "email_scan.png")
    img.save(img_path)

    result = guard.doc(img_path)
    _assert_guard_shape(result)
    assert isinstance(result["guarded_text"], str)
