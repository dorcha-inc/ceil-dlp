"""Main PII detection engine with hybrid Presidio + custom patterns."""

from ceil_dlp.detectors.entropy import detect_high_entropy_tokens
from ceil_dlp.detectors.patterns import PatternMatch, detect_pattern
from ceil_dlp.detectors.presidio_adapter import detect_with_presidio


class PIIDetector:
    """
    Detects PII in text using Presidio for standard PII and custom patterns for API keys.
    """

    PRESIDIO_TYPES = frozenset({"credit_card", "ssn", "email", "phone"})
    CUSTOM_TYPES = frozenset({"api_key", "pem_key", "jwt_token", "high_entropy_token"})
    ENABLED_TYPES_DEFAULT = PRESIDIO_TYPES.union(CUSTOM_TYPES)

    def __init__(self, enabled_types: set[str] | None = None) -> None:
        """
        Initialize PII detector.

        Args:
            enabled_types: list of PII types to detect. If None, detects all types.
                          Options: credit_card, ssn, email, phone, api_key, pem_key,
                          jwt_token, high_entropy_token.
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

        presidio_types = self.enabled_types.intersection(self.PRESIDIO_TYPES)
        custom_types = self.enabled_types.intersection(self.CUSTOM_TYPES)

        if presidio_types:
            presidio_results = detect_with_presidio(text)
            # Filter to only enabled types
            for pii_type in presidio_types:
                if pii_type in presidio_results:
                    results[pii_type] = presidio_results[pii_type]

        # Use custom patterns for API keys and other custom types
        # Run regex patterns first, then entropy (to avoid duplicates)
        regex_types = custom_types - {"high_entropy_token"}
        for pii_type in regex_types:
            matches = detect_pattern(text, pii_type)  # type: ignore[arg-type]
            if matches:
                results[pii_type] = matches

        # High-entropy detection runs after regex patterns
        if "high_entropy_token" in custom_types:
            # Get all already-detected positions to avoid duplicates
            detected_positions: set[int] = set()
            for matches_list in results.values():
                for _text, start, end in matches_list:
                    detected_positions.update(range(start, end))

            # Find high-entropy tokens
            entropy_matches = detect_high_entropy_tokens(text)
            # Filter out matches that overlap with regex-detected patterns
            filtered_entropy = []
            for match_text, start, end in entropy_matches:
                # Check if this overlaps with any detected pattern
                overlap = any(pos in detected_positions for pos in range(start, end))
                if not overlap:
                    filtered_entropy.append((match_text, start, end))

            if filtered_entropy:
                results["high_entropy_token"] = filtered_entropy

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
