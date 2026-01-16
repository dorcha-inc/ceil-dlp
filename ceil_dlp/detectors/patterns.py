"""Custom regex patterns for API keys and other non-standard PII.

Patterns are based on gitleaks default configuration with improvements for accuracy.
Reference: https://github.com/gitleaks/gitleaks
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from collections.abc import Callable
from typing import Literal

logger = logging.getLogger(__name__)

PatternType = Literal["api_key", "pem_key", "jwt_token", "database_url", "cloud_credential"]
PatternValidator = Callable[[str], bool] | None

# PatternMatch is a tuple of (matched_text, start_pos, end_pos)
PatternMatch = tuple[str, int, int]


def _calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (inline to avoid circular import)."""
    if not text:
        return 0.0
    char_counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def _validate_entropy(text: str, min_entropy: float = 3.5) -> bool:
    """Validate that text has sufficient entropy to be a secret."""
    return _calculate_shannon_entropy(text) >= min_entropy


# Patterns based on gitleaks default configuration
# Reference: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
PATTERNS: dict[PatternType, list[tuple[str, PatternValidator]]] = {
    "api_key": [
        # OpenAI API keys (sk- prefix, 32+ chars)
        (r"\bsk-[a-zA-Z0-9]{32,}\b", None),
        # Anthropic API keys (sk-ant-api03- prefix, 95+ chars)
        (r"\bsk-ant-api03-[a-zA-Z0-9\-_]{95,}\b", None),
        # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes, 36+ chars)
        (r"\bgh[opurs]_[A-Za-z0-9]{36,}\b", None),
        # GitLab Personal Access Token (glpat- prefix)
        (r"\bglpat-[a-zA-Z0-9\-_]{20,}\b", None),
        # Stripe keys (sk_live_, sk_test_, rk_live_, rk_test_ prefixes)
        (r"\b(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b", None),
        # Slack tokens (xoxb-, xoxa-, xoxp-, xoxe-, xoxs- prefixes)
        (r"\bxox[bapes]-\d+-[a-zA-Z0-9-]{27,}\b", None),
        # Google API keys (AIza prefix, exactly 39 chars)
        (r"\bAIza[0-9A-Za-z_-]{35}\b", None),
        # AWS access keys (AKIA prefix, exactly 20 chars)
        (r"\bAKIA[0-9A-Z]{16}\b", None),
        # AWS secret access keys (base64-like, 40 chars)
        (r"\b[A-Za-z0-9/+=]{40}\b", lambda m: len(m) == 40 and _validate_entropy(m, 4.0)),
        # Azure Storage Account keys (base64, 88 chars)
        (r"\b[A-Za-z0-9+/]{86}==\b", None),
        # Heroku API keys (8 hex chars, dash, 8 hex chars, dash, 8 hex chars, dash, 8 hex chars)
        (r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", None),
        # Mailgun API keys (key- prefix, 32 hex chars)
        (r"\bkey-[0-9a-f]{32}\b", None),
        # SendGrid API keys (SG. prefix, base64-like, 22+ chars)
        (r"\bSG\.[A-Za-z0-9_-]{22,}\b", None),
        # Twilio API keys (SK prefix, 32 hex chars)
        (r"\bSK[0-9a-f]{32}\b", None),
        # Square API keys (sq0atp- or sq0csp- prefix)
        (r"\bsq0[ac]sp-[0-9A-Za-z\-_]{32,}\b", None),
        # Square OAuth secrets (sq0csp- prefix)
        (r"\bsq0csp-[0-9A-Za-z\-_]{43,}\b", None),
        # PayPal client ID/secret (base64-like)
        (r"\b(?:access_token|client_id|client_secret)\s*[:=]\s*[A-Za-z0-9_-]{20,}\b", None),
        # Shopify API keys (shpat_ or shpca_ prefix)
        (r"\bsh(?:pat|pca)_[a-zA-Z0-9]{32,}\b", None),
        # Shopify shared secret (shpss_ prefix)
        (r"\bshpss_[a-zA-Z0-9]{32,}\b", None),
        # Shopify access token (shpat_ prefix, 32+ chars)
        (r"\bshpat_[a-zA-Z0-9]{32,}\b", None),
        # Twitter API keys (bearer tokens, 50+ chars)
        (r"\b(?:twitter|twilio)\s+[A-Za-z0-9_-]{50,}\b", None),
        # Facebook access tokens (EAAB prefix or base64-like)
        (r"\bEAAB[a-zA-Z0-9]{100,}\b", None),
        # LinkedIn API keys
        (r"\b(?:linkedin|li_at)\s*[:=]\s*[A-Za-z0-9_-]{20,}\b", None),
        # Discord bot tokens (base64-like, 59+ chars)
        (r"\b(?:discord|bot)[\s:=]+([A-Za-z0-9_-]{59,})\b", lambda m: _validate_entropy(m, 4.0)),
        # Generic Bearer tokens (improved pattern)
        (r"\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)\b", lambda m: _validate_entropy(m, 3.5)),
        # Generic API key pattern (api[_-]?key, apikey, etc.)
        (
            r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*([A-Za-z0-9\-_+/=]{20,})\b",
            lambda m: _validate_entropy(m, 3.5),
        ),
        # Generic secret pattern (secret, password, token keywords)
        (
            r"(?i)(?:secret|password|token|key)\s*[:=]\s*([A-Za-z0-9\-_+/=]{16,})\b",
            lambda m: _validate_entropy(m, 4.0),
        ),
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
        # PGP private keys
        (
            r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
            None,
        ),
    ],
    "jwt_token": [
        # JWT tokens (eyJ... format, 3 parts separated by dots, improved pattern)
        (r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b", None),
    ],
    "database_url": [
        # PostgreSQL connection strings
        (
            r"postgres(?:ql)?://[^\s]+",
            None,
        ),
        # MySQL connection strings
        (
            r"mysql://[^\s]+",
            None,
        ),
        # MongoDB connection strings
        (
            r"mongodb(?:\+srv)?://[^\s]+",
            None,
        ),
        # Redis connection strings
        (
            r"redis://[^\s]+",
            None,
        ),
        # Generic database URL pattern
        (
            r"(?:database|db|connection)[\s:=]+(?:url|uri|string)[\s:=]+([a-z]+://[^\s]+)",
            None,
        ),
    ],
    "cloud_credential": [
        # Google Cloud service account keys (JSON-like)
        (
            r'"type"\s*:\s*"service_account"[\s\S]{0,2000}?"private_key"\s*:\s*"-----BEGIN',
            None,
        ),
        # AWS credentials file format
        (
            r"\[default\]\s+aws_access_key_id\s*=\s*([A-Z0-9]{20})\s+aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})",
            None,
        ),
        # Azure connection strings
        (
            r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}==;?",
            None,
        ),
    ],
}


def detect_pattern(text: str, pattern_type: PatternType) -> list[PatternMatch]:
    """
    Detect custom PII patterns in text.

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
        for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
            # Extract the full match or the first capture group if available
            if match.lastindex and match.lastindex >= 1:
                # Use first capture group as the secret (common pattern in gitleaks)
                matched_text = match.group(1)
                # Adjust positions to the capture group
                start = match.start(1)
                end = match.end(1)
            else:
                matched_text = match.group(0)
                start = match.start()
                end = match.end()

            # Apply validator if present (validators receive the matched secret text)
            if validator and not validator(matched_text):
                continue

            matches.append((matched_text, start, end))

    # Remove overlapping matches (keep the longest)
    if matches:
        matches = _remove_overlaps(matches)

    return matches


def _remove_overlaps(matches: list[PatternMatch]) -> list[PatternMatch]:
    """Remove overlapping matches, keeping the longest ones.

    This is necessary because:
    1. Multiple patterns can match the same or overlapping text
    2. Generic patterns (e.g., "Bearer token") can overlap with specific ones (e.g., "sk-...")
    3. Prevents duplicate detections in the final results

    Args:
        matches: List of (text, start, end) tuples

    Returns:
        List of non-overlapping matches, with longer matches preferred
    """
    if not matches:
        return []

    # Sort by start position, then by length (longest first) for stable ordering
    sorted_matches = sorted(matches, key=lambda x: (x[1], -(x[2] - x[1])))
    non_overlapping: list[PatternMatch] = []

    for match in sorted_matches:
        text, start, end = match
        match_length = end - start

        # Check if this match overlaps with any existing match
        overlap_found = False
        to_remove = []

        for i, (_, existing_start, existing_end) in enumerate(non_overlapping):
            existing_length = existing_end - existing_start

            # Check for overlap
            if not (end <= existing_start or start >= existing_end):
                overlap_found = True
                # If current match is longer, mark existing for removal
                if match_length > existing_length:
                    to_remove.append(i)
                else:
                    # Current match is shorter or equal, skip it
                    break

        # Remove marked overlaps (in reverse order to maintain indices)
        for i in reversed(to_remove):
            non_overlapping.pop(i)

        # Add current match if no overlap or if it's longer than overlapping ones
        if not overlap_found or to_remove:
            non_overlapping.append(match)

    return non_overlapping
