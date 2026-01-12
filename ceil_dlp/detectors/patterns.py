"""Custom regex patterns for API keys and other non-standard PII."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import Literal

logger = logging.getLogger(__name__)

PatternType = Literal["api_key", "pem_key", "jwt_token"]
PatternValidator = Callable[[str], bool] | None

# PatternMatch is a tuple of (matched_text, start_pos, end_pos)
PatternMatch = tuple[str, int, int]

# TODO(jadidbourbaki): add more patterns for other API keys and other non-standard PII.
PATTERNS: dict[PatternType, list[tuple[str, PatternValidator]]] = {
    "api_key": [
        # OpenAI API keys
        (r"\bsk-[a-zA-Z0-9]{32,}\b", None),
        # Anthropic API keys (sk-ant- prefix)
        (r"\bsk-ant-[a-zA-Z0-9\-_]{95,}\b", None),
        # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes, 36+ chars)
        (r"\bgh[opurs]_[A-Za-z0-9]{36,}\b", None),
        # Stripe keys (sk_live_, sk_test_, rk_live_, rk_test_ prefixes)
        (r"\b(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b", None),
        # Slack tokens (xoxb-, xoxa-, xoxp-, xoxe-, xoxs- prefixes)
        (r"\bxox[bapes]-\d+-[a-zA-Z0-9-]{27,}\b", None),
        # Google API keys
        (r"\bAIza[0-9A-Za-z_-]{35}\b", None),
        # Generic Bearer tokens
        (r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b", None),
        # AWS access keys
        (r"\bAKIA[0-9A-Z]{16}\b", None),
    ],
    "pem_key": [
        # RSA private keys
        (
            r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+RSA\s+PRIVATE\s+KEY-----",
            None,
        ),
        # EC private keys
        (
            r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----",
            None,
        ),
        # DSA private keys
        (
            r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+DSA\s+PRIVATE\s+KEY-----",
            None,
        ),
        # OPENSSH private keys
        (
            r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----",
            None,
        ),
        # Generic private keys
        (
            r"-----BEGIN\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+PRIVATE\s+KEY-----",
            None,
        ),
    ],
    "jwt_token": [
        # JWT tokens (eyJ... format, 3 parts separated by dots)
        (r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", None),
    ],
}


def detect_pattern(text: str, pattern_type: PatternType) -> list[PatternMatch]:
    """
    Detect custom PII patterns in text

    Args:
        text: Input text to scan
        pattern_type: Type of PII to detect

    Returns:
        list of tuples: (matched_text, start_pos, end_pos)
    """
    if pattern_type not in PATTERNS:
        raise ValueError(
            f"Unknown pattern type: {pattern_type}. Expected one of {list(PATTERNS.keys())}"
        )

    matches = []

    for pattern, validator in PATTERNS[pattern_type]:
        for match in re.finditer(pattern, text, re.IGNORECASE):
            matched_text = match.group(0)
            # Apply validator if present
            if validator and not validator(matched_text):
                continue

            matches.append((matched_text, match.start(), match.end()))

    # Remove overlapping matches (keep the longest)
    if matches:
        matches = _remove_overlaps(matches)

    return matches


def _remove_overlaps(matches: list[PatternMatch]) -> list[PatternMatch]:
    """Remove overlapping matches, keeping the longest ones."""
    if not matches:
        return []

    # Sort by start position
    sorted_matches = sorted(matches, key=lambda x: (x[1], -(x[2] - x[1])))
    non_overlapping: list[PatternMatch] = []

    for match in sorted_matches:
        text, start, end = match
        # Check if this match overlaps with any existing match
        overlaps = False
        for existing_text, existing_start, existing_end in non_overlapping:
            if not (end <= existing_start or start >= existing_end):
                overlaps = True
                # If the current match is longer, replace the existing one
                if (end - start) > (existing_end - existing_start):
                    non_overlapping.remove((existing_text, existing_start, existing_end))
                    non_overlapping.append(match)
                break

        if not overlaps:
            non_overlapping.append(match)

    return non_overlapping
