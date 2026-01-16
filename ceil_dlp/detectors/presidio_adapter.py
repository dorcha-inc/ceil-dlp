"""Adapter to integrate Presidio for standard PII detection."""

import logging
from functools import lru_cache
from typing import cast

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerRegistry

from ceil_dlp.detectors.patterns import PatternMatch, PatternType

logger = logging.getLogger(__name__)

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
    "INTERNATIONAL_PHONE_NUMBER": "phone",
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


@lru_cache(maxsize=1)
def get_analyzer() -> AnalyzerEngine:
    """Get cached AnalyzerEngine instance with custom secret recognizers.

    This is shared across all Presidio-based detection modules (text, image, redaction)
    to ensure we only create one analyzer instance per process.
    """
    # Create registry with built-in recognizers
    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()

    # Add custom secret recognizers
    secret_recognizers = _create_secret_recognizers()
    for recognizer in secret_recognizers:
        registry.add_recognizer(recognizer)

    return AnalyzerEngine(registry=registry)


def _detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    analyzer = get_analyzer()
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


def detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    """
    Detect standard PII using Presidio.

    Args:
        text: Input text to scan

    Returns:
        Dictionary mapping PII type to list of matches.
        Each match is a tuple: (matched_text, start_pos, end_pos)
    """
    try:
        return _detect_with_presidio(text)
    except Exception as e:
        raise RuntimeError("Failed to detect PII with Presidio") from e
