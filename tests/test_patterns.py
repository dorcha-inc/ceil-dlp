"""Tests for custom pattern detection."""

import pytest

from ceil_dlp.detectors.patterns import detect_pattern


def test_detect_pattern_api_key_openai():
    """Test OpenAI API key detection."""
    text = "My API key is sk-1234567890abcdef1234567890abcdef"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("sk-" in match[0] for match in matches)


def test_detect_pattern_api_key_google():
    """Test Google API key detection."""
    text = "API key: AIza12345678901234567890123456789012345"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("AIza" in match[0] for match in matches)


def test_detect_pattern_api_key_aws():
    """Test AWS access key detection."""
    # AWS access keys are exactly 20 characters: AKIA + 16 alphanumeric
    text = "Access key: AKIA1234567890ABCDEF"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("AKIA" in match[0] for match in matches)


def test_detect_pattern_api_key_bearer():
    """Test Bearer token detection."""
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("eyJ" in match[0] for match in matches)


def test_detect_pattern_unknown_type():
    """Test that unknown pattern type raises ValueError."""
    with pytest.raises(ValueError, match="Unknown pattern type"):
        detect_pattern("test", "unknown_type")  # type: ignore[arg-type]


def test_detect_pattern_no_matches():
    """Test detection with no matches."""
    text = "This is just normal text with no API keys"
    matches = detect_pattern(text, "api_key")
    assert len(matches) == 0


def test_detect_pattern_multiple_matches():
    """Test detection with multiple API keys."""
    text = "Key1: sk-1234567890abcdef1234567890abcdef Key2: AIza12345678901234567890123456789012345"
    matches = detect_pattern(text, "api_key")
    assert len(matches) >= 2


def test_detect_pattern_position_tracking():
    """Test that matches include correct positions."""
    text = "Start sk-1234567890abcdef1234567890abcdef end"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    match = matches[0]
    matched_text, start, end = match
    assert text[start:end] == matched_text
    assert matched_text in text


def test_detect_pattern_overlapping_matches():
    """Test that overlapping matches are handled correctly."""
    # Create a scenario with overlapping patterns
    # Bearer token might overlap with other patterns
    text = "Bearer sk-1234567890abcdef1234567890abcdef"
    matches = detect_pattern(text, "api_key")
    # Should handle overlaps and keep appropriate matches
    assert len(matches) > 0
    # Verify no overlapping positions
    for i, (_, start1, end1) in enumerate(matches):
        for j, (_, start2, end2) in enumerate(matches):
            if i != j:
                # Either completely separate or one contains the other
                assert (
                    end1 <= start2
                    or start1 >= end2
                    or (start1 <= start2 and end1 >= end2)
                    or (start2 <= start1 and end2 >= end1)
                )


def test_detect_pattern_with_validator():
    """Test pattern detection with validator that rejects matches."""
    from ceil_dlp.detectors.patterns import PATTERNS, detect_pattern

    # Create a validator that rejects all matches
    def validator(text: str) -> bool:
        return False  # Reject all matches

    # Temporarily replace the first pattern with one that has a validator
    original_patterns = PATTERNS["api_key"].copy()
    try:
        # Replace first pattern (OpenAI key) with one that has validator
        test_pattern = (r"\bsk-[a-zA-Z0-9]{32,}\b", validator)
        PATTERNS["api_key"][0] = test_pattern

        # Test that validator filters out matches from this pattern
        text = "My key is sk-1234567890abcdef1234567890abcdef"
        matches = detect_pattern(text, "api_key")
        assert len(matches) == 0
    finally:
        # Restore original patterns
        PATTERNS["api_key"] = original_patterns


def test_detect_pattern_api_key_anthropic():
    """Test Anthropic API key detection."""
    text = "Anthropic key: sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("sk-ant-" in match[0] for match in matches)


def test_detect_pattern_api_key_github():
    """Test GitHub token detection."""
    text = "GitHub token: ghp_1234567890abcdef1234567890abcdef123456"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("ghp_" in match[0] for match in matches)


def test_detect_pattern_api_key_stripe():
    """Test Stripe key detection."""
    text = "Stripe key: sk_test_FAKE1234567890abcdef123456"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("sk_live_" in match[0] or "sk_test_" in match[0] for match in matches)


def test_detect_pattern_api_key_slack():
    """Test Slack token detection."""
    # Using xoxa- prefix (app token) with clearly fake test data
    text = "Slack token: xoxa-0000000000-TESTFAKE1234567890abcdefghijklmnop"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("xox" in match[0] and "-" in match[0] for match in matches)


def test_detect_pattern_pem_key():
    """Test PEM key detection."""
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""
    matches = detect_pattern(text, "pem_key")
    assert len(matches) > 0
    assert any("BEGIN RSA PRIVATE KEY" in match[0] for match in matches)


def test_detect_pattern_jwt_token():
    """Test JWT token detection."""
    text = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = detect_pattern(text, "jwt_token")
    assert len(matches) > 0
    assert any("eyJ" in match[0] for match in matches)


def test_detect_pattern_api_key_gitlab():
    """Test GitLab token detection."""
    text = "GitLab token: glpat-1234567890abcdef1234567890"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("glpat-" in match[0] for match in matches)


def test_detect_pattern_api_key_mailgun():
    """Test Mailgun API key detection."""
    text = "Mailgun key: key-1234567890abcdef1234567890abcdef"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("key-" in match[0] and len(match[0]) == 36 for match in matches)


def test_detect_pattern_api_key_sendgrid():
    """Test SendGrid API key detection."""
    text = "SendGrid key: SG.1234567890abcdef1234567890abcdef"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any("SG." in match[0] for match in matches)


def test_detect_pattern_api_key_twilio():
    """Test Twilio API key detection."""
    # Using clearly fake test value (deadbeef pattern) to avoid triggering secret scanners
    # deadbeef is a well-known test pattern that won't be mistaken for a real key
    text = "Twilio key: SKdeadbeefdeadbeefdeadbeefdeadbeef"
    matches = detect_pattern(text, "api_key")
    assert len(matches) > 0
    assert any(match[0].startswith("SK") and len(match[0]) == 34 for match in matches)


def test_detect_pattern_database_url_postgres():
    """Test PostgreSQL database URL detection."""
    text = "Database: postgresql://user:pass@localhost:5432/dbname"
    matches = detect_pattern(text, "database_url")
    assert len(matches) > 0
    assert any("postgres" in match[0] for match in matches)


def test_detect_pattern_database_url_mongodb():
    """Test MongoDB database URL detection."""
    text = "MongoDB: mongodb+srv://user:pass@cluster.mongodb.net/dbname"
    matches = detect_pattern(text, "database_url")
    assert len(matches) > 0
    assert any("mongodb" in match[0] for match in matches)


def test_detect_pattern_cloud_credential_aws():
    """Test AWS credentials detection."""
    text = "[default]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    matches = detect_pattern(text, "cloud_credential")
    assert len(matches) > 0
