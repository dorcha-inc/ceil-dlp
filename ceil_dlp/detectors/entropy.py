"""High-entropy token detection using Shannon entropy calculation.

This module implements entropy-based detection to identify potential secrets
that don't match known patterns. Reference: gitleaks entropy implementation.
"""

import math
import re
from collections import Counter

from ceil_dlp.detectors.patterns import PatternMatch, _remove_overlaps


def calculate_shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy indicates more randomness, which is characteristic of secrets.
    Reference: gitleaks entropy calculation approach.

    Args:
        text: Input string to calculate entropy for

    Returns:
        Shannon entropy value (0.0 to log2(alphabet_size))
    """
    if not text:
        return 0.0

    # Count character frequencies
    char_counts = Counter(text)
    length = len(text)

    # Calculate entropy: -sum(p(x) * log2(p(x)))
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def detect_high_entropy_tokens(
    text: str,
    min_entropy: float = 4.5,
    min_length: int = 20,
    max_length: int = 200,
) -> list[PatternMatch]:
    """
    Detect high-entropy substrings in text that may be secrets.

    Uses sliding window approach to find substrings with high entropy.
    Reference: gitleaks entropy detection strategy.

    Args:
        text: Input text to scan
        min_entropy: Minimum entropy threshold (default 4.5 for base64-like)
        min_length: Minimum token length to consider
        max_length: Maximum token length to consider

    Returns:
        List of PatternMatch tuples: (matched_text, start_pos, end_pos)
    """
    matches: list[PatternMatch] = []

    # Skip if text is too short
    if len(text) < min_length:
        return matches

    # Find potential token boundaries (whitespace, punctuation, etc.)
    # Look for sequences of alphanumeric/base64-like characters
    # Pattern matches base64-like strings (A-Za-z0-9+/=) or hex (0-9a-fA-F)
    token_pattern = r"[A-Za-z0-9+/=_-]{20,}"

    for match in re.finditer(token_pattern, text):
        token = match.group(0)
        start = match.start()
        end = match.end()

        # Skip if too long
        if len(token) > max_length:
            continue

        # Calculate entropy
        entropy = calculate_shannon_entropy(token)

        # Check if entropy meets threshold
        if entropy >= min_entropy:
            matches.append((token, start, end))

    # Remove overlapping matches (keep longest)
    if matches:
        matches = _remove_overlaps(matches)

    return matches
