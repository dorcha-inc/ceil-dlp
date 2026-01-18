"""Main PII detection engine using Presidio PatternRecognizers."""

from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.presidio_adapter import (
    PRESIDIO_TO_PII_TYPE,
    detect_with_presidio_ensemble,
)

# All Presidio entity types supported by ceil-dlp
PRESIDIO_TYPES = frozenset(set(PRESIDIO_TO_PII_TYPE.values()))
CUSTOM_TYPES = frozenset(
    {
        "api_key",
        "pem_key",
        "jwt_token",
        "database_url",
        "cloud_credential",
    }
)
ENABLED_TYPES_DEFAULT = PRESIDIO_TYPES.union(CUSTOM_TYPES)


def detect_pii_in_text(
    text: str,
    enabled_types: set[str] | None = None,
    ner_strength: int = 3,
) -> dict[str, list[PatternMatch]]:
    """
    Detect PII in text using Presidio for standard PII and custom patterns for API keys.

    Args:
        text: Input text to scan
        enabled_types: Optional set of PII types to detect. If None, detects all types.
                      Includes all Presidio entity types (credit_card, ssn, email, phone,
                      person, location, ip_address, url, medical_license, crypto, date_time,
                      iban_code, nrp, and country-specific types like us_driver_license,
                      uk_nhs, es_nif, it_fiscal_code, etc.) plus custom types (api_key,
                      pem_key, jwt_token, database_url, cloud_credential).
        ner_strength: NER model strength:
                     - 1: en_core_web_lg only (fastest)
                     - 2: spaCy + transformer ensemble (balanced)
                     - 3: spaCy + transformer + GLiNER ensemble (best coverage, slower)
                     Defaults to 1 for backward compatibility.

    Returns:
        Dictionary mapping PII type to list of matches.
    """
    # Determine which types to detect
    types_to_detect = ENABLED_TYPES_DEFAULT if enabled_types is None else frozenset(enabled_types)

    all_types = types_to_detect.intersection(PRESIDIO_TYPES.union(CUSTOM_TYPES))

    if not all_types:
        return {}

    # Use ensemble detection (handles merging when ner_strength=2)
    # detect_with_presidio_ensemble already filters by enabled_types, including custom types
    return detect_with_presidio_ensemble(
        text, ner_strength=ner_strength, enabled_types=set(all_types)
    )
