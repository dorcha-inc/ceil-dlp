"""whistledown transformation cache for conversational coherence.

Based on the whistledown paper: https://arxiv.org/pdf/2511.13319

This module implements consistent token mapping to preserve conversational coherence
while protecting PII. Instead of generic [REDACTED_*] tags, it uses consistent
identifiers like PERSON_1, PERSON_2, etc., and reverses them in responses.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


class WhistledownCache:
    """Manages consistent token mappings for whistledown transformations.

    Maintains bidirectional mappings between original sensitive values and their
    replacements (e.g., "John Doe" -> "PERSON_1"). This ensures that:
    1. Same value always maps to same token within a request/session
    2. Different values get different tokens (PERSON_1 vs PERSON_2)
    3. Tokens can be reversed in LLM responses back to originals
    """

    def __init__(self) -> None:
        """Initialize the whistledown cache."""
        # forward cache: request_id -> {original_value -> replacement_token}
        self.forward_cache: dict[str, dict[str, str]] = {}
        # reverse cache: request_id -> {replacement_token -> original_value}
        self.reverse_cache: dict[str, dict[str, str]] = {}
        # type counters: request_id -> {pii_type -> next_counter_value}
        self.type_counters: dict[str, dict[str, int]] = {}

    def get_or_create_replacement(self, request_id: str, original: str, pii_type: str) -> str:
        """Get existing replacement or create new one with consistent naming.

        Args:
            request_id: Unique identifier for the request/conversation
            original: Original sensitive value (e.g., "John Doe")
            pii_type: Type of PII (e.g., "person", "email", "api_key")

        Returns:
            Consistent replacement token (e.g., "PERSON_1", "EMAIL_2")
        """
        # Initialize cache for this request if needed
        if request_id not in self.forward_cache:
            self.forward_cache[request_id] = {}
            self.reverse_cache[request_id] = {}
            self.type_counters[request_id] = {}

        # Check if we've already seen this value
        if original in self.forward_cache[request_id]:
            return self.forward_cache[request_id][original]

        # Create new replacement token
        counter = self._get_next_counter(request_id, pii_type)
        replacement = f"{pii_type.upper()}_{counter}"

        # Store both directions
        self._store_mapping(request_id, original, replacement)

        logger.debug(
            f"created whistledown mapping for request_id={request_id}, "
            f"type={pii_type}, {original} -> {replacement}"
        )

        return replacement

    def reverse_transform(self, request_id: str, text: str) -> str:
        """Replace whistledown tokens back to original values.

        This is called on LLM responses to restore original values for the user.

        Args:
            request_id: Unique identifier for the request
            text: Text containing whistledown tokens (from LLM response)

        Returns:
            Text with tokens replaced back to original values
        """
        if request_id not in self.reverse_cache:
            logger.debug(f"no reverse cache found for request_id={request_id}")
            return text

        result = text
        for replacement, original in self.reverse_cache[request_id].items():
            if replacement in result:
                result = result.replace(replacement, original)
                logger.debug(f"reversed {replacement} -> {original} in response")

        return result

    def clear_request(self, request_id: str) -> None:
        """Clean up cache for completed request.

        Args:
            request_id: Unique identifier for the request to clear
        """
        removed = 0
        if request_id in self.forward_cache:
            removed = len(self.forward_cache[request_id])
            del self.forward_cache[request_id]
        if request_id in self.reverse_cache:
            del self.reverse_cache[request_id]
        if request_id in self.type_counters:
            del self.type_counters[request_id]

        if removed > 0:
            logger.debug(f"cleared {removed} whistledown mappings for request_id={request_id}")

    def get_stats(self, request_id: str | None = None) -> dict[str, Any]:
        """Get cache statistics for debugging/monitoring.

        Args:
            request_id: Optional request ID to get stats for specific request

        Returns:
            Dictionary with cache statistics
        """
        if request_id:
            return {
                "request_id": request_id,
                "mapping_count": len(self.forward_cache.get(request_id, {})),
                "mappings": self.forward_cache.get(request_id, {}),
            }

        return {
            "total_requests": len(self.forward_cache),
            "total_mappings": sum(len(mappings) for mappings in self.forward_cache.values()),
            "requests": list(self.forward_cache.keys()),
        }

    def _get_next_counter(self, request_id: str, pii_type: str) -> int:
        """Get next counter value for a PII type.

        Args:
            request_id: Unique identifier for the request
            pii_type: Type of PII

        Returns:
            Next counter value (1-based)
        """
        if request_id not in self.type_counters:
            self.type_counters[request_id] = {}

        if pii_type not in self.type_counters[request_id]:
            self.type_counters[request_id][pii_type] = 0

        self.type_counters[request_id][pii_type] += 1
        return self.type_counters[request_id][pii_type]

    def _store_mapping(self, request_id: str, original: str, replacement: str) -> None:
        """Store bidirectional mapping.

        Args:
            request_id: Unique identifier for the request
            original: Original sensitive value
            replacement: Replacement token
        """
        if request_id not in self.forward_cache:
            self.forward_cache[request_id] = {}
            self.reverse_cache[request_id] = {}

        self.forward_cache[request_id][original] = replacement
        self.reverse_cache[request_id][replacement] = original


def whistledown_transform_text(
    text: str,
    detections: dict[str, list[tuple[str, int, int]]],
    cache: "WhistledownCache",
    request_id: str,
) -> tuple[str, dict[str, list[str]]]:
    """
    Apply Whistledown transformation to text for conversational coherence.

    Unlike generic redaction, this uses consistent identifiers (PERSON_1, EMAIL_2, etc.)
    that can be reversed in LLM responses. Based on the Whistledown paper:
    https://arxiv.org/pdf/2511.13319

    Args:
        text: Original text to transform
        detections: Dictionary mapping PII type to list of matches
        cache: Whistledown cache for consistent token mapping
        request_id: Request identifier for cache isolation

    Returns:
        Tuple of (transformed_text, transformed_items) where transformed_items maps
        PII type to list of original values that were transformed
    """
    # Collect all matches with their types
    all_matches: list[tuple[str, tuple[str, int, int]]] = []  # (pii_type, (text, start, end))
    transformed_items: dict[str, list[str]] = {}

    for pii_type, matches in detections.items():
        if matches:
            # Extract matched texts for logging
            matched_texts = [match[0] for match in matches]
            transformed_items[pii_type] = matched_texts

            # Add all matches with their type
            for match in matches:
                all_matches.append((pii_type, match))

    # Sort by start position in reverse order (process from end to start)
    # This ensures positions remain valid as we replace text
    all_matches.sort(key=lambda x: x[1][1], reverse=True)

    # Apply all transformations in one pass
    transformed_text = text
    for pii_type, (matched_text, start, end) in all_matches:
        # Get or create consistent replacement token
        replacement = cache.get_or_create_replacement(request_id, matched_text, pii_type)
        transformed_text = transformed_text[:start] + replacement + transformed_text[end:]

    return transformed_text, transformed_items
