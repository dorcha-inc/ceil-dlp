"""Adapter to integrate Presidio for standard PII detection."""

import logging
import os
from functools import lru_cache
from typing import cast

# Set transformers verbosity BEFORE importing anything that might use transformers
# This suppresses the "Some weights were not used" warning which is expected when loading
# BERT checkpoints for token classification (the warning itself says "This IS expected")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
# Disable advisory warnings (like the "Some weights were not used" message)
os.environ.setdefault("TRANSFORMERS_NO_ADVISORY_WARNINGS", "1")

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

from ceil_dlp.detectors.patterns import PatternMatch, PatternType

logger = logging.getLogger(__name__)

# Suppress expected Presidio warnings:
# - Language mismatch warnings: Presidio loads recognizers for multiple languages (es, it, pl, etc.)
#   but we only use English. These warnings are harmless but noisy.
# - Configuration warnings: Missing optional config parameters that use defaults.
presidio_logger = logging.getLogger("presidio-analyzer")
presidio_logger.setLevel(logging.ERROR)  # Only show ERROR and above, suppress WARNING


PRESIDIO_TO_PII_TYPE: dict[str, str] = {
    # Global entities
    "CREDIT_CARD": "credit_card",
    "CRYPTO": "crypto",
    "DATE_TIME": "date_time",
    "EMAIL_ADDRESS": "email",
    "IBAN_CODE": "iban_code",
    "IP_ADDRESS": "ip_address",
    "LOCATION": "location",
    "PERSON": "person",
    "PHONE_NUMBER": "phone",
    "MEDICAL_LICENSE": "medical_license",
    "URL": "url",
    "NRP": "nrp",
    # United States
    "US_BANK_NUMBER": "us_bank_number",
    "US_DRIVER_LICENSE": "us_driver_license",
    "US_ITIN": "us_itin",
    "US_PASSPORT": "us_passport",
    "US_SSN": "ssn",
    # United Kingdom
    "UK_NHS": "uk_nhs",
    "UK_NINO": "uk_nino",
    # Spain
    "ES_NIF": "es_nif",
    "ES_NIE": "es_nie",
    # Italy
    "IT_FISCAL_CODE": "it_fiscal_code",
    "IT_DRIVER_LICENSE": "it_driver_license",
    "IT_VAT_CODE": "it_vat_code",
    "IT_PASSPORT": "it_passport",
    "IT_IDENTITY_CARD": "it_identity_card",
    # Poland
    "PL_PESEL": "pl_pesel",
    # Singapore
    "SG_NRIC_FIN": "sg_nric_fin",
    "SG_UEN": "sg_uen",
    # Australia
    "AU_ABN": "au_abn",
    "AU_ACN": "au_acn",
    "AU_TFN": "au_tfn",
    "AU_MEDICARE": "au_medicare",
    # India
    "IN_PAN": "in_pan",
    "IN_AADHAAR": "in_aadhaar",
    "IN_VEHICLE_REGISTRATION": "in_vehicle_registration",
    "IN_VOTER": "in_voter",
    "IN_PASSPORT": "in_passport",
    "IN_GSTIN": "in_gstin",
    # Finland
    "FI_PERSONAL_IDENTITY_CODE": "fi_personal_identity_code",
    # Korea
    "KR_RRN": "kr_rrn",
    # Thailand
    "TH_TNIN": "th_tnin",
    # Custom secret types (mapped from PatternRecognizer entity names)
    "API_KEY": "api_key",
    "PEM_KEY": "pem_key",
    "JWT_TOKEN": "jwt_token",
    "DATABASE_URL": "database_url",
    "CLOUD_CREDENTIAL": "cloud_credential",
}


@lru_cache(maxsize=1)
def get_pii_type_to_entities() -> dict[str, list[str]]:
    """Get mapping of PII type to Presidio entity names."""
    return {v: [k] for k, v in PRESIDIO_TO_PII_TYPE.items()}


def _create_secret_recognizers() -> list[PatternRecognizer]:
    """
    Create Presidio PatternRecognizer objects for custom secrets (API keys, etc.).

    Returns:
        List of PatternRecognizer objects
    """
    from ceil_dlp.detectors.patterns import PATTERNS

    recognizers = []

    # Custom types that can be represented as regex patterns
    custom_types = {"api_key", "pem_key", "jwt_token", "database_url", "cloud_credential"}

    for pattern_type in custom_types:
        if pattern_type not in PATTERNS:
            continue

        patterns_list = PATTERNS[cast(PatternType, pattern_type)]
        presidio_patterns: list[Pattern] = []

        for regex_pattern in patterns_list:
            # Convert our regex pattern to Presidio Pattern
            presidio_pattern = Pattern(
                name=f"{pattern_type}_{len(presidio_patterns)}",
                regex=regex_pattern,
                score=0.8,  # Confidence score
            )
            presidio_patterns.append(presidio_pattern)

        if presidio_patterns:
            # Create PatternRecognizer for this secret type
            recognizer = PatternRecognizer(
                supported_entity=pattern_type.upper(),  # e.g., "API_KEY"
                patterns=presidio_patterns,
                supported_language="en",
            )
            recognizers.append(recognizer)

    return recognizers


@lru_cache(maxsize=3)  # Cache up to 3 analyzers (one per strength level: 1, 2, or 3)
def _get_analyzer_cached(ner_strength: int) -> AnalyzerEngine:
    """Internal cached function - ner_strength must be 1, 2, or 3."""
    # Create registry with built-in recognizers
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    # Add custom secret recognizers
    secret_recognizers = _create_secret_recognizers()
    for recognizer in secret_recognizers:
        registry.add_recognizer(recognizer)

    # Configure NLP engine based on strength
    if ner_strength == 1:
        # Use default (en_core_web_lg) - no special configuration needed
        return AnalyzerEngine(registry=registry)
    elif ner_strength == 3:
        try:
            from huggingface_hub.utils.tqdm import disable_progress_bars

            disable_progress_bars()
        except ImportError:
            logger.warning(
                "Failed to load HuggingFace Hub progress bars: Missing dependency. Install with: pip install huggingface_hub"
            )
        # Use GLiNER zero-shot NER model
        try:
            from presidio_analyzer.predefined_recognizers import GLiNERRecognizer

            # Map GLiNER entity types to Presidio entity types
            # GLiNER's PII model (urchade/gliner_multi_pii-v1) outputs fine-grained types
            # that we map to our standard Presidio types
            entity_mapping = {
                "person": "PERSON",
                "name": "PERSON",
                "organization": "ORGANIZATION",
                "org": "ORGANIZATION",
                "location": "LOCATION",
                "loc": "LOCATION",
                "email": "EMAIL_ADDRESS",
                "phone": "PHONE_NUMBER",
                "credit_card": "CREDIT_CARD",
                "ssn": "US_SSN",
                "ip_address": "IP_ADDRESS",
                "ip": "IP_ADDRESS",
                "url": "URL",
                "date": "DATE_TIME",
                "date_time": "DATE_TIME",
            }

            # Create GLiNER recognizer with PII-specific model
            gliner_recognizer = GLiNERRecognizer(
                model_name="urchade/gliner_multi_pii-v1",
                entity_mapping=entity_mapping,
                flat_ner=False,  # Keep nested entities
                multi_label=True,  # Allow multiple labels per span
                threshold=0.5,  # Confidence threshold
                map_location="cpu",  # Use CPU by default (can be "cuda" if GPU available)
            )

            # Register GLiNER recognizer
            registry.add_recognizer(gliner_recognizer)

            # Use default spaCy NLP engine (for tokenization, etc.)
            return AnalyzerEngine(registry=registry)
        except ImportError as e:
            logger.warning(
                f"Failed to load GLiNER (ner_strength=3): Missing dependency. "
                f"Install with: pip install gliner. Error: {e}"
            )
            raise
        except Exception as e:
            logger.warning(f"Failed to load GLiNER (ner_strength=3): {e}")
            raise
    else:  # ner_strength == 2
        # Use transformer-based NER model (best accuracy)
        try:
            # Set transformers verbosity to ERROR before importing/using transformers
            # This suppresses expected warnings like "Some weights were not used"
            try:
                from transformers.utils import logging as transformers_logging

                transformers_logging.set_verbosity_error()
            except ImportError:
                # If transformers logging utils aren't available, environment variables should handle it
                pass

            from presidio_analyzer.nlp_engine import NerModelConfiguration, TransformersNlpEngine

            model_config = [
                {
                    "lang_code": "en",
                    "model_name": {
                        "spacy": "en_core_web_sm",  # Small spaCy for tokenization, lemmatization
                        "transformers": "dslim/bert-base-NER",  # Transformer NER model
                    },
                }
            ]

            # Map transformer entity labels to Presidio entity names
            # Note: Model outputs labels with B-/I- prefixes (B-PER, I-PER), but mapping
            # should use labels without prefixes (PER, LOC, ORG, MISC)
            # The dslim/bert-base-NER model outputs: PER, LOC, ORG, MISC
            mapping = {
                "PER": "PERSON",
                "LOC": "LOCATION",
                "ORG": "ORGANIZATION",
                "MISC": "MISC",
                # Also include common variations
                "PERSON": "PERSON",
                "GPE": "LOCATION",  # Geopolitical entity
            }

            ner_config = NerModelConfiguration(
                model_to_presidio_entity_mapping=mapping,
                alignment_mode="expand",  # "strict", "contract", "expand"
                aggregation_strategy="max",  # "simple", "first", "average", "max"
                labels_to_ignore=["O"],  # Ignore "no entity" label
                stride=128,  # Increased window overlap for better coverage of long texts
                # Larger stride helps ensure entities near chunk boundaries aren't missed
            )

            tf_engine = TransformersNlpEngine(
                models=model_config, ner_model_configuration=ner_config
            )
            return AnalyzerEngine(
                registry=registry, nlp_engine=tf_engine, supported_languages=["en"]
            )
        except ImportError as e:
            logger.warning(
                f"Failed to load transformer NER model (ner_strength=2): Missing dependency. "
                f"Install with: pip install spacy-huggingface-pipelines transformers. "
                f"Falling back to default NER model. Error: {e}"
            )
            return AnalyzerEngine(registry=registry)
        except Exception as e:
            logger.warning(
                f"Failed to load transformer NER model (ner_strength=2), falling back to default: {e}"
            )
            return AnalyzerEngine(registry=registry)


def get_analyzer(ner_strength: int = 1) -> AnalyzerEngine:
    """Get cached AnalyzerEngine instance with custom secret recognizers.

    Args:
        ner_strength: NER model strength:
                     - 1: en_core_web_lg (spaCy)
                     - 2: transformer-based NER (dslim/bert-base-NER)
                     - 3: GLiNER zero-shot NER (best for long texts and hyphenated names)
                     Defaults to 1 for backward compatibility.

    Returns:
        AnalyzerEngine configured with the specified NER model strength.

    Raises:
        ValueError: If ner_strength is not 1, 2, or 3.
    """
    # Validate strength BEFORE caching to ensure cache key consistency
    # This prevents multiple cache entries for the same effective strength
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for transformer-based NER, or 3 for GLiNER."
        )
    return _get_analyzer_cached(ner_strength)


def _detect_with_presidio(text: str, ner_strength: int = 1) -> dict[str, list[PatternMatch]]:
    analyzer = get_analyzer(ner_strength=ner_strength)
    results = analyzer.analyze(text=text, language="en")
    detections: dict[str, list[PatternMatch]] = {}
    for result in results:
        entity_type = result.entity_type
        pii_type = PRESIDIO_TO_PII_TYPE.get(entity_type)
        if pii_type:
            matched_text = text[result.start : result.end]
            match = (matched_text, result.start, result.end)
            if pii_type not in detections:
                detections[pii_type] = []
            detections[pii_type].append(match)
    return detections


def detect_with_presidio_ensemble(
    text: str,
    ner_strength: int = 1,
    enabled_types: set[str] | frozenset[str] | None = None,
) -> dict[str, list[PatternMatch]]:
    """
    Detect PII using Presidio with optional ensemble approach (merging multiple NER models).

    - ner_strength=1: spaCy NER (en_core_web_lg) only
    - ner_strength=2: Ensemble of spaCy + transformer NER
    - ner_strength=3: Ensemble of spaCy + transformer + GLiNER NER (best coverage)

    Args:
        text: Input text to scan
        ner_strength: NER model strength:
                     - 1: en_core_web_lg only (fastest)
                     - 2: spaCy + transformer ensemble (balanced)
                     - 3: spaCy + transformer + GLiNER ensemble (best coverage, slower)
                     Defaults to 1 for backward compatibility.
        enabled_types: Optional set of PII types to filter results. If None, returns all detected types.

    Returns:
        Dictionary mapping PII type to list of matches.
        Each match is a tuple: (matched_text, start_pos, end_pos)
    """
    # Validate ner_strength
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for spaCy+transformer ensemble, "
            "or 3 for spaCy+transformer+GLiNER ensemble."
        )
    ner_strength_val = ner_strength

    # NER Ensemble: If strength 2 or 3, detect with multiple models and merge
    # NOTE: We detect with all models on the ORIGINAL text, then merge.
    # This is better than sequential (detect -> redact -> detect -> redact) because:
    # 1. All models see the original text (no information loss)
    # 2. Maximum coverage from all models
    # 3. Single redaction pass (more efficient)
    # 4. No risk of missing PII that one model would catch but another already redacted
    # Sequential approach works for images because OCR can still read surrounding text
    # after redaction, but for text, redaction replaces content making it undetectable.
    if ner_strength_val == 2:
        # Two-model ensemble: spaCy + transformer
        detections_spacy = _detect_with_presidio(text, ner_strength=1)
        detections_transformer = _detect_with_presidio(text, ner_strength=2)
        detections_list = [detections_spacy, detections_transformer]
    elif ner_strength_val == 3:
        # Three-model ensemble: spaCy + transformer + GLiNER
        detections_spacy = _detect_with_presidio(text, ner_strength=1)
        detections_transformer = _detect_with_presidio(text, ner_strength=2)
        detections_gliner = _detect_with_presidio(text, ner_strength=3)
        detections_list = [detections_spacy, detections_transformer, detections_gliner]
    else:
        # Single model detection
        detections = _detect_with_presidio(text, ner_strength=ner_strength_val)
        if enabled_types:
            detections = {k: v for k, v in detections.items() if k in enabled_types}
        return detections

    # Merge detections from all models
    # For overlapping matches, prefer the one with better coverage or keep both
    merged_detections: dict[str, list[PatternMatch]] = {}

    # Collect all matches
    all_matches: dict[
        tuple[int, int], tuple[str, PatternMatch]
    ] = {}  # (start, end) -> (pii_type, match)

    # Add detections from all models
    for detections in detections_list:
        for pii_type, matches in detections.items():
            if enabled_types and pii_type not in enabled_types:
                continue
            for match in matches:
                _text, start, end = match
                key = (start, end)
                # Add match (will overwrite if same span, which is fine - later models take precedence)
                all_matches[key] = (pii_type, match)

    # Convert back to detections format
    for (_start, _end), (pii_type, match) in all_matches.items():
        if pii_type not in merged_detections:
            merged_detections[pii_type] = []
        merged_detections[pii_type].append(match)

    return merged_detections


def detect_with_presidio(text: str, ner_strength: int = 1) -> dict[str, list[PatternMatch]]:
    """
    Detect standard PII using Presidio.

    Args:
        text: Input text to scan
        ner_strength: NER model strength:
                     - 1: en_core_web_lg only (fastest)
                     - 2: spaCy + transformer ensemble (balanced)
                     - 3: spaCy + transformer + GLiNER ensemble (best coverage, slower)
                     Defaults to 1 for backward compatibility.

    Returns:
        Dictionary mapping PII type to list of matches.
        Each match is a tuple: (matched_text, start_pos, end_pos)
    """
    try:
        return _detect_with_presidio(text, ner_strength=ner_strength)
    except Exception as e:
        raise RuntimeError("Failed to detect PII with Presidio") from e
