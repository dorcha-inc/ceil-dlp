"""Custom regex patterns for API keys and other non-standard PII.

Patterns are based on gitleaks default configuration with improvements for accuracy.
Reference: https://github.com/gitleaks/gitleaks

These patterns are used to create Presidio PatternRecognizers for detection.
Note: Validators are not supported by Presidio, so patterns with validators
have been simplified to regex-only patterns.
"""

from __future__ import annotations

from typing import Literal

# PatternMatch is a tuple of (matched_text, start_pos, end_pos)
PatternMatch = tuple[str, int, int]

PatternType = Literal["api_key", "pem_key", "jwt_token", "database_url", "cloud_credential"]


# Patterns based on gitleaks default configuration
# Reference: https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
PATTERNS: dict[PatternType, list[str]] = {
    "api_key": [
        # OpenAI API keys (sk- prefix, 32+ chars)
        r"\bsk-[a-zA-Z0-9]{32,}\b",
        # Anthropic API keys (sk-ant-api03- prefix, 95+ chars)
        r"\bsk-ant-api03-[a-zA-Z0-9\-_]{95,}\b",
        # GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes, 36+ chars)
        r"\bgh[opurs]_[A-Za-z0-9]{36,}\b",
        # GitLab Personal Access Token (glpat- prefix)
        r"\bglpat-[a-zA-Z0-9\-_]{20,}\b",
        # Stripe keys (sk_live_, sk_test_, rk_live_, rk_test_ prefixes)
        r"\b(?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{24,}\b",
        # Slack tokens (xoxb-, xoxa-, xoxp-, xoxe-, xoxs- prefixes)
        r"\bxox[bapes]-\d+-[a-zA-Z0-9-]{27,}\b",
        # Google API keys (AIza prefix, exactly 39 chars)
        r"\bAIza[0-9A-Za-z_-]{35}\b",
        # OCR-tolerant Google API keys: allow character misreads and count variations
        r"\bAIza[0-9A-Za-z_\-/|]{33,37}\b",
        # AWS access keys (AKIA prefix, exactly 20 chars total)
        # Standard format with word boundaries
        r"\bAKIA[0-9A-Z]{16}\b",
        # OCR-tolerant AWS access keys: handles common OCR misreads
        # OCR may misread: 7→/, 0→O, I→1, etc. Allow 14-18 chars to handle count errors
        r"\bAKIA[0-9A-Z/|]{14,18}(?:\s*\([^)]+\))?\b",
        # AWS secret access keys (base64-like, exactly 40 chars with high entropy chars)
        r"\b[A-Za-z0-9/+=]{40}\b",
        # OCR-tolerant AWS secret access keys: allow character misreads and count variations
        r"\b[A-Za-z0-9/+=|]{38,42}\b",
        # Azure Storage Account keys (base64, 88 chars)
        r"\b[A-Za-z0-9+/]{86}==\b",
        # OCR-tolerant Azure Storage Account keys: allow character misreads and count variations
        r"\b[A-Za-z0-9+/|]{84,90}==\b",
        # Heroku API keys (UUID format)
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
        # OCR-tolerant Heroku API keys: allow hex misreads (0→O, 1→I) and slight count variations
        # Note: UUID structure is preserved, but allow character misreads within each segment
        r"\b[0-9a-f/|]{7,9}-[0-9a-f/|]{3,5}-[0-9a-f/|]{3,5}-[0-9a-f/|]{3,5}-[0-9a-f/|]{11,13}\b",
        # Mailgun API keys (key- prefix, 32 hex chars)
        r"\bkey-[0-9a-f]{32}\b",
        # OCR-tolerant Mailgun API keys: allow hex misreads (0→O, 1→I, etc.) and count variations
        r"\bkey-[0-9a-f/|]{30,34}\b",
        # SendGrid API keys (SG. prefix, base64-like, 22+ chars)
        r"\bSG\.[A-Za-z0-9_-]{22,}\b",
        # Twilio API keys (SK prefix, 32 hex chars)
        r"\bSK[0-9a-f]{32}\b",
        # OCR-tolerant Twilio API keys: allow hex misreads and count variations
        r"\bSK[0-9a-f/|]{30,34}\b",
        # Square API keys (sq0atp- or sq0csp- prefix)
        r"\bsq0[ac]sp-[0-9A-Za-z\-_]{32,}\b",
        # Square OAuth secrets (sq0csp- prefix)
        r"\bsq0csp-[0-9A-Za-z\-_]{43,}\b",
        # PayPal client ID/secret (base64-like)
        r"\b(?:access_token|client_id|client_secret)\s*[:=]\s*[A-Za-z0-9_-]{20,}\b",
        # Shopify API keys (shpat_ or shpca_ prefix)
        r"\bsh(?:pat|pca)_[a-zA-Z0-9]{32,}\b",
        # Shopify shared secret (shpss_ prefix)
        r"\bshpss_[a-zA-Z0-9]{32,}\b",
        # Shopify access token (shpat_ prefix, 32+ chars)
        r"\bshpat_[a-zA-Z0-9]{32,}\b",
        # Twitter API keys (bearer tokens, 50+ chars)
        r"\b(?:twitter|twilio)\s+[A-Za-z0-9_-]{50,}\b",
        # Facebook access tokens (EAAB prefix or base64-like)
        r"\bEAAB[a-zA-Z0-9]{100,}\b",
        # LinkedIn API keys
        r"\b(?:linkedin|li_at)\s*[:=]\s*[A-Za-z0-9_-]{20,}\b",
        # Discord bot tokens (base64-like, 59+ chars)
        r"\b(?:discord|bot)[\s:=]+[A-Za-z0-9_-]{59,}\b",
        # Generic Bearer tokens (improved pattern, 20+ chars)
        r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b",
        # Generic API key pattern (api[_-]?key, apikey, etc., 20+ chars)
        r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*[A-Za-z0-9\-_+/=]{20,}\b",
        # Generic secret pattern (secret, password, token keywords, 16+ chars)
        r"(?i)(?:secret|password|token|key)\s*[:=]\s*[A-Za-z0-9\-_+/=]{16,}\b",
    ],
    "pem_key": [
        # RSA private keys
        r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+RSA\s+PRIVATE\s+KEY-----",
        # EC private keys
        r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+EC\s+PRIVATE\s+KEY-----",
        # DSA private keys
        r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+DSA\s+PRIVATE\s+KEY-----",
        # OPENSSH private keys
        r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+OPENSSH\s+PRIVATE\s+KEY-----",
        # Generic private keys
        r"-----BEGIN\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+PRIVATE\s+KEY-----",
        # PGP private keys
        r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----[\s\S]*?-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----",
    ],
    "jwt_token": [
        # JWT tokens (eyJ... format, 3 parts separated by dots, improved pattern)
        r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b",
    ],
    "database_url": [
        # PostgreSQL connection strings
        r"postgres(?:ql)?://[^\s]+",
        # MySQL connection strings
        r"mysql://[^\s]+",
        # MongoDB connection strings
        r"mongodb(?:\+srv)?://[^\s]+",
        # Redis connection strings
        r"redis://[^\s]+",
        # Generic database URL pattern
        r"(?:database|db|connection)[\s:=]+(?:url|uri|string)[\s:=]+([a-z]+://[^\s]+)",
    ],
    "cloud_credential": [
        # Google Cloud service account keys (JSON-like)
        r'"type"\s*:\s*"service_account"[\s\S]{0,2000}?"private_key"\s*:\s*"-----BEGIN',
        # AWS credentials file format
        r"\[default\]\s+aws_access_key_id\s*=\s*([A-Z0-9]{20})\s+aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})",
        # Azure connection strings
        r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86}==;?",
    ],
}
