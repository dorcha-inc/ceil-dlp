"""Tests for custom pattern detection via Presidio.

These tests verify that our custom patterns are correctly configured
in Presidio PatternRecognizers. We test a representative sample of patterns
since Presidio handles the actual detection.
"""

from ceil_dlp.detectors.pii_detector import PIIDetector


def test_api_key_detection():
    """Test API key detection with various providers."""
    detector = PIIDetector(enabled_types={"api_key"})

    # Test OpenAI key
    text1 = "My API key is sk-1234567890abcdef1234567890abcdef"
    results1 = detector.detect(text1)
    assert "api_key" in results1
    assert len(results1["api_key"]) > 0

    # Test AWS key
    text2 = "Access key: AKIA1234567890ABCDEF"
    results2 = detector.detect(text2)
    assert "api_key" in results2
    assert len(results2["api_key"]) > 0


def test_pem_key_detection():
    """Test PEM key detection."""
    detector = PIIDetector(enabled_types={"pem_key"})
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""
    results = detector.detect(text)
    assert "pem_key" in results
    assert len(results["pem_key"]) > 0


def test_jwt_token_detection():
    """Test JWT token detection."""
    detector = PIIDetector(enabled_types={"jwt_token"})
    text = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    results = detector.detect(text)
    assert "jwt_token" in results
    assert len(results["jwt_token"]) > 0


def test_database_url_detection():
    """Test database URL detection."""
    detector = PIIDetector(enabled_types={"database_url"})
    text = "Database: postgresql://user:pass@localhost:5432/dbname"
    results = detector.detect(text)
    assert "database_url" in results
    assert len(results["database_url"]) > 0


def test_cloud_credential_detection():
    """Test cloud credential detection."""
    detector = PIIDetector(enabled_types={"cloud_credential"})
    text = "[default]\naws_access_key_id = AKIA1234567890ABCDEF\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    results = detector.detect(text)
    assert "cloud_credential" in results
    assert len(results["cloud_credential"]) > 0


def test_no_matches():
    """Test detection with no matches."""
    detector = PIIDetector(enabled_types={"api_key"})
    text = "This is just normal text with no API keys"
    results = detector.detect(text)
    matches = results.get("api_key", [])
    assert len(matches) == 0


def test_position_tracking():
    """Test that matches include correct positions."""
    detector = PIIDetector(enabled_types={"api_key"})
    text = "Start sk-1234567890abcdef1234567890abcdef end"
    results = detector.detect(text)
    matches = results.get("api_key", [])
    assert len(matches) > 0
    match = matches[0]
    matched_text, start, end = match
    assert text[start:end] == matched_text
    assert matched_text in text
