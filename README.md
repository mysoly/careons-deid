# ZorgDeID — Dutch PII Detection & Anonymization

> **Detect, mask, and anonymize Personally Identifiable Information (PII) in Dutch text and documents.**  
> Built for Dutch healthcare, GDPR / AVG compliance, and NEN 7510 data-protection pipelines.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## What is ZorgDeID?

**ZorgDeID** is a Python library that detects and anonymizes Dutch PII in plain text, documents (`.pdf`, `.docx`, `.txt`), and **scanned files** (`.jpg`, `.png`, `.tiff`, and image-based PDFs via OCR). It combines:

- **Custom Dutch regex recognizers** — hand-tuned patterns for Dutch identifiers (BSN, IBAN, Health Identifier, licence plates, …)
- **spaCy Dutch NER** (`nl_core_news_lg`) — neural named-entity recognition for persons and locations
- **Algorithmic validation** — elfproef for BSN, mod-97 for IBAN, Luhn for credit cards and IMEI
- **Context-aware scoring** — sentence-bounded keyword windows boost or penalize confidence before anonymization decisions

Use cases: de-identifying patient records, anonymizing clinical notes, sanitizing intake forms, GDPR / AVG data-minimization pipelines, NEN 7510 technical controls.

---

## Key Features

| Feature | Detail |
|---------|--------|
| **18 entity types** | Full Dutch PII coverage — from BSN and Health Identifier to GPS coordinates and IMEI |
| **3 guard modes** | `anonymize` (realistic Dutch fakes) · `tag` (`[PERSON]`) · `i_tag` (`[PERSON_1]`) |
| **Document support** | Reads `.pdf` (pypdf), `.docx` (python-docx), and `.txt` natively |
| **OCR support** | Scanned PDFs and image files (`.jpg`, `.png`, `.tiff`, `.bmp`, `.webp`) via EasyOCR — no system binary required |
| **PDF normalization** | Automatically repairs pypdf extraction artifacts; falls back to OCR for image-only pages |
| **Algorithmic validation** | BSN elfproef · IBAN mod-97 · Credit card & IMEI Luhn |
| **Context-aware scoring** | Sentence-bounded keyword windows boost or penalize confidence scores |
| **Vocabulary tiers** | Strong / weak keyword distinction — partial boosts for ambiguous context |
| **Negative context** | Contradicting keywords reduce score before thresholding |
| **Entity filtering** | `keep` allowlist or `ignore` denylist per call |
| **Custom patterns** | Plug in your own regex with optional context words and fake-value pools |
| **GDPR / AVG ready** | Designed for Dutch healthcare data pipelines and NEN 7510 technical controls |

---

## Installation

```bash
pip install zorgdeid
```

Download the Dutch spaCy model (required for `PERSON` and `LOCATION` detection):

```bash
python -m spacy download nl_core_news_lg
```

### Optional: OCR support

To process **scanned PDFs and image files** (`.jpg`, `.png`, `.tiff`, `.bmp`, `.webp`):

```bash
pip install zorgdeid[ocr]
```

This installs [EasyOCR](https://github.com/JaidedAI/EasyOCR) and [PyMuPDF](https://pymupdf.readthedocs.io/) — no system binaries (Tesseract, poppler) required. The Dutch neural model (~120 MB) is downloaded automatically on first use and cached in `~/.EasyOCR/`.

---

## Quick Start

```python
from zorgdeid import analyze, guard

text = "Mijn naam is Jan de Vries en ik woon in Amsterdam. Mijn BSN is 123456782."

# ── Detect PII ────────────────────────────────────────────────────
findings = analyze.text(text)
for f in findings:
    print(f"[{f['type']}] {text[f['start']:f['end']]} (score: {f['score']})")
# [PERSON]   Jan de Vries  (score: 0.85)
# [LOCATION] Amsterdam     (score: 0.85)
# [BSN]      123456782     (score: 0.85)

# ── Anonymize (default mode) ──────────────────────────────────────
result = guard.text(text)
print(result["guarded_text"])
# "Mijn naam is Maria Janssen en ik woon in Utrecht. Mijn BSN is 111222333."

# ── Tag mode ──────────────────────────────────────────────────────
print(guard.text(text, config={"mode": "tag"})["guarded_text"])
# "Mijn naam is [PERSON] en ik woon in [LOCATION]. Mijn BSN is [BSN]."

# ── Indexed tag mode ──────────────────────────────────────────────
print(guard.text(text, config={"mode": "i_tag"})["guarded_text"])
# "Mijn naam is [PERSON_1] en ik woon in [LOCATION_1]. Mijn BSN is [BSN_1]."
```

---

## Document Processing

Process files directly — text extraction and PII analysis in one call:

```python
from zorgdeid import analyze, guard

# Analyze a file
findings = analyze.doc("patient_report.pdf")
findings = analyze.doc("intake_form.docx")
findings = analyze.doc("clinical_note.txt")

# Anonymize a file
result = guard.doc("patient_report.pdf")
print(result["guarded_text"])   # clean, anonymized text
print(result["findings"])       # list of detected PII spans

# All config options work the same as with .text()
result = guard.doc("intake_form.docx", config={
    "mode": "tag",
    "score_threshold": 0.6,
    "set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]},
})
```

**Supported formats:**

| Format | Reader | Notes |
|--------|--------|-------|
| `.txt` | built-in `open()` | UTF-8 with cp1252 fallback |
| `.pdf` | `pypdf` | Digital PDFs extracted directly; image-only pages fall back to OCR automatically |
| `.docx` | `python-docx` | All paragraphs and table cells joined |
| `.jpg` `.jpeg` `.png` `.tiff` `.bmp` `.webp` | EasyOCR | Requires `pip install zorgdeid[ocr]` |

Any other extension raises `UnsupportedFormatError` before the file-existence check.

### OCR example

```python
from zorgdeid import analyze, guard
from zorgdeid.processors.doc_processor import read as doc_read

# Extract text via OCR
text = doc_read("intake_scan.png")
print(text)

# Detect PII
findings = analyze.doc("intake_scan.png")

# Anonymize
result = guard.doc("intake_scan.png", config={"mode": "tag"})
print(result["guarded_text"])

# Works identically for scanned PDFs
result = guard.doc("patient_record_scan.pdf", config={"mode": "anonymize"})
print(result["guarded_text"])
```

---

## Supported Entity Types

| Entity | Description | Validation |
|--------|-------------|------------|
| `PERSON` | Person names | spaCy NER |
| `LOCATION` | Cities, addresses, regions | spaCy NER |
| `DATE` | Dates (numeric & Dutch month names) | — |
| `TIME` | Times (12h / 24h / Dutch "uur") | — |
| `PHONE_NUMBER` | Dutch mobile & landline, EU format | — |
| `EMAIL_ADDRESS` | E-mail addresses | — |
| `URL` | HTTP/HTTPS/FTP links | — |
| `ZIPCODE` | Dutch postal codes (`1234 AB`) | — |
| `GPS_COORDINATES` | Latitude / longitude pairs | — |
| `IBAN_CODE` | Dutch & international IBANs | ✓ ISO 13616 mod-97 |
| `CREDIT_CARD` | Visa, Mastercard, Amex, Diners, Discover, JCB | ✓ Luhn |
| `BSN` | Burgerservicenummer | ✓ Elfproef (11-proef) |
| `PASSPORT` | Dutch passport & driving licence numbers | — |
| `HEALTH_IDENTIFIER` | Dutch health insurance policy numbers | — |
| `IP_ADDRESS` | IPv4 and IPv6 addresses | — |
| `MAC_ADDRESS` | Ethernet MAC addresses | — |
| `IMEI` | Mobile device identifiers (15 digits) | ✓ Luhn |
| `LICENCE_PLATE` | Dutch vehicle licence plates | — |

---

## Guard Modes

| Mode | Behaviour | Output example |
|------|-----------|----------------|
| `anonymize` *(default)* | Replace each entity with a realistic Dutch synthetic value | `Jan Bakker`, `111222333`, `NL20 INGB 0001 2345 67` |
| `tag` | Replace with `[ENTITY_TYPE]` | `[PERSON]`, `[BSN]`, `[IBAN_CODE]` |
| `i_tag` | Replace with `[ENTITY_TYPE_N]` — same entity type gets the same index | `[PERSON_1]` … `[PERSON_2]` |

---

## Configuration

All options are passed via a single `config` dict:

```python
# Allowlist — only detect these entity types
config = {"set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]}}

# Denylist — detect everything except these
config = {"set_entities": {"ignore": ["DATE", "TIME"]}}

# Full config example
config = {
    "set_entities": {"keep": ["PERSON", "BSN", "IBAN_CODE"]},

    # Minimum confidence to include a finding
    "score_threshold": 0.5,

    # Guard mode
    "mode": "anonymize",   # "anonymize" | "tag" | "i_tag"

    # Custom patterns (see below)
    "custom_patterns": [...],
}
```

### Custom Patterns

```python
from zorgdeid import analyze, guard, custom_pattern

emp = custom_pattern(
    name="EMPLOYEE_ID",
    regex=r"EMP-\d{4}",
    score=0.9,
    context=["medewerker", "werknemer"],        # nearby words boost score
    anonymize_list=["EMP-9999", "EMP-8888"],    # fake pool for anonymize mode
)

findings = analyze.text("Medewerker EMP-1234 heeft toegang.", config={"custom_patterns": [emp]})
guarded  = guard.text("Medewerker EMP-1234 heeft toegang.",  config={"custom_patterns": [emp]})
print(guarded["guarded_text"])
# "Medewerker EMP-9999 heeft toegang."
```

---

## Scoring & Confidence

Every finding carries a `score` between 0 and 1. Scores are determined by a four-tier system:

| Tier | Condition | Example score |
|------|-----------|---------------|
| `base` | Regex match only, no additional evidence | 0.30 – 0.85 |
| `with_context` | A relevant keyword appears in the same sentence | up to 0.95 |
| `validated` | Algorithmic checksum passes (elfproef / mod-97 / Luhn) | 0.65 – 0.90 |
| `high_confidence` | Validation *and* context keyword present | 0.90 – 0.95 |

Context scoring is **sentence-aware** — context keywords from other sentences do not influence the score. Negative-context keywords (e.g. `factuurnummer` near a phone pattern) actively reduce confidence.

Use `score_threshold` to filter out low-confidence results before anonymization.

---

## Package Layout

```
zorgdeid/
├── types.py              — core data structures (RecognizerResult, Pattern, …)
├── analysis/
│   ├── analyzer.py       — PII analysis engine (GuardAnalyzer)
│   ├── context_awareness.py  — sentence-aware keyword scoring (DutchContextEnhancer)
│   └── overlap_resolver.py   — span deduplication & merging
├── anonymization/
│   ├── engine.py         — stateless anonymization dispatcher (GuardEngine)
│   └── fake_data.py      — synthetic Dutch PII pools
├── recognizers/
│   ├── base.py           — EntityRecognizer / PatternRecognizer base classes
│   ├── contact.py        — PHONE_NUMBER, EMAIL_ADDRESS, URL
│   ├── datetime.py       — DATE, TIME
│   ├── device.py         — IP_ADDRESS, MAC_ADDRESS, IMEI
│   ├── financial.py      — IBAN_CODE, CREDIT_CARD
│   ├── identifier.py     — BSN, PASSPORT, HEALTH_IDENTIFIER
│   ├── location.py       — ZIPCODE, GPS_COORDINATES
│   ├── spacy_recognizer.py  — NER recognizer (PERSON, LOCATION)
│   └── vehicle.py        — LICENCE_PLATE
├── processors/
│   ├── text_processor.py — analyze / guard pipelines for plain-text input
│   └── doc_processor.py  — file reading (.pdf / .docx / .txt / images) + OCR fallback
├── config/
│   ├── entities.py       — ALL_NL_ENTITY_TYPES list
│   └── scoring.py        — EntityScoreProfile per entity type
└── patterns/             — Dutch regex patterns & keyword lists
```

The public interface is exposed through `zorgdeid/__init__.py`:

```python
from zorgdeid import analyze, guard, custom_pattern, ALL_NL_ENTITY_TYPES
```

---

## Privacy & Compliance

| Standard | How this library helps |
|----------|----------------------|
| **GDPR / AVG** | De-identifies personal data before storage or transfer; supports data-minimization obligations |
| **NEN 7510** | Provides a technical control layer for pseudonymization of Dutch patient data |
| **Human-in-the-loop** | Automated detection is probabilistic — for critical clinical datasets, always include human review of anonymized output |

> This library is a **technical tool**, not a legal guarantee. Your full pipeline architecture, access controls, and data governance policies must meet the applicable regulatory requirements.

---

## Interactive Quickstart

The [examples/quickstart.ipynb](examples/quickstart.ipynb) notebook covers:

- Text and document analysis
- All three guard modes
- Dutch healthcare identifiers (BSN, HEALTH_IDENTIFIER)
- Custom patterns with anonymization pools
- Entity filtering and score thresholds
- Error handling for unsupported file formats
- OCR on image files and scanned PDFs

---

## License

MIT License — see [LICENSE](LICENSE) for details.
