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
    assert any("Bearer" in match[0] for match in matches)


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


def test_remove_overlaps_empty_list():
    """Test _remove_overlaps with empty list."""
    from ceil_dlp.detectors.patterns import _remove_overlaps

    result = _remove_overlaps([])
    assert result == []


def test_remove_overlaps_replacement():
    """Test _remove_overlaps replacing shorter with longer match."""
    from ceil_dlp.detectors.patterns import _remove_overlaps

    # Create overlapping matches where one is longer
    # First add shorter, then longer - should replace
    matches = [
        ("short", 0, 5),  # 5 chars, added first
        ("much longer match", 0, 17),  # 17 chars, overlaps with first, should replace
    ]
    result = _remove_overlaps(matches)
    # Should keep the longer match
    assert len(result) == 1
    assert result[0][0] == "much longer match"

    # Test reverse order - longer first, then shorter
    matches2 = [
        ("much longer match", 0, 17),  # 17 chars, added first
        ("short", 0, 5),  # 5 chars, overlaps but shorter, should not replace
    ]
    result2 = _remove_overlaps(matches2)
    # Should keep the longer match (first one)
    assert len(result2) == 1
    assert result2[0][0] == "much longer match"


def test_remove_overlaps_replacement_longer_second():
    """Test _remove_overlaps when longer match comes second and replaces first."""
    from ceil_dlp.detectors.patterns import _remove_overlaps

    # Create scenario where shorter is added first, then longer overlaps and replaces it
    # This tests the removal and append logic (lines 85-86)
    matches = [
        ("abc", 0, 3),  # 3 chars, added first to non_overlapping
        ("abcdefghij", 0, 10),  # 10 chars, overlaps, longer, should replace first
    ]
    result = _remove_overlaps(matches)
    # Should have only the longer match
    assert len(result) == 1
    assert result[0][0] == "abcdefghij"
    assert result[0][1] == 0
    assert result[0][2] == 10


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
