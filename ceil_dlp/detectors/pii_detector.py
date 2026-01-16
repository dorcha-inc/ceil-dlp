"""Main PII detection engine using Presidio PatternRecognizers."""

from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.presidio_adapter import PRESIDIO_TO_PII_TYPE, detect_with_presidio


class PIIDetector:
    """
    Detects PII in text using Presidio for standard PII and custom patterns for API keys.
    """

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

    def __init__(self, enabled_types: set[str] | None = None) -> None:
        """
        Initialize PII detector.

        Args:
            enabled_types: Set of PII types to detect. If None, detects all types.
                          Includes all Presidio entity types (credit_card, ssn, email, phone,
                          person, location, ip_address, url, medical_license, crypto, date_time,
                          iban_code, nrp, and country-specific types like us_driver_license,
                          uk_nhs, es_nif, it_fiscal_code, etc.) plus custom types (api_key,
                          pem_key, jwt_token, database_url, cloud_credential).
        """
        if enabled_types is None:
            self.enabled_types = self.ENABLED_TYPES_DEFAULT
        else:
            self.enabled_types = frozenset(enabled_types)

    def detect(self, text: str) -> dict[str, list[PatternMatch]]:
        """
        Detect all PII in the given text.

        Args:
            text: Input text to scan

        Returns:
            Dictionary mapping PII type to list of matches.
        """
        results: dict[str, list[PatternMatch]] = {}

        all_types = self.enabled_types.intersection(self.PRESIDIO_TYPES.union(self.CUSTOM_TYPES))

        if all_types:
            presidio_results = detect_with_presidio(text)
            # Filter to only enabled types
            for pii_type in all_types:
                if pii_type in presidio_results:
                    results[pii_type] = presidio_results[pii_type]

        return results

    def has_pii(self, text: str) -> bool:
        """
        Quick check if text contains any PII.

        Args:
            text: Input text to scan

        Returns:
            True if any PII is detected, False otherwise
        """
        return len(self.detect(text)) > 0
