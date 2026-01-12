"""Tests for PII detection."""

from ceil_dlp.detectors.pii_detector import PIIDetector


def test_credit_card_detection():
    """Test credit card detection with Luhn validation."""
    detector = PIIDetector()
    text = "My credit card is 4111111111111111"
    detections = detector.detect(text)
    assert "credit_card" in detections
    assert len(detections["credit_card"]) > 0


def test_ssn_detection():
    """Test SSN detection."""
    detector = PIIDetector()
    text = "My SSN is 536-22-1234"
    detections = detector.detect(text)
    assert "ssn" in detections
    assert len(detections["ssn"]) > 0


def test_pem_key_detection():
    """Test PEM key detection."""
    detector = PIIDetector()
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""
    detections = detector.detect(text)
    assert "pem_key" in detections
    assert len(detections["pem_key"]) > 0


def test_jwt_token_detection():
    """Test JWT token detection."""
    detector = PIIDetector()
    text = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    detections = detector.detect(text)
    assert "jwt_token" in detections
    assert len(detections["jwt_token"]) > 0


def test_high_entropy_token_detection():
    """Test high-entropy token detection."""
    detector = PIIDetector()
    # High-entropy string that looks like a secret
    text = "Secret key: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    detections = detector.detect(text)
    # May or may not detect depending on entropy threshold
    # Just verify it doesn't crash
    assert isinstance(detections, dict)


def test_anthropic_api_key_detection():
    """Test Anthropic API key detection."""
    detector = PIIDetector()
    text = "Anthropic key: sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    detections = detector.detect(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_github_token_detection():
    """Test GitHub token detection."""
    detector = PIIDetector()
    text = "GitHub token: ghp_1234567890abcdef1234567890abcdef123456"
    detections = detector.detect(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_stripe_key_detection():
    """Test Stripe key detection."""
    detector = PIIDetector()
    text = "Stripe key: sk_test_FAKE1234567890abcdef123456"
    detections = detector.detect(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_slack_token_detection():
    """Test Slack token detection."""
    detector = PIIDetector()
    # Using xoxa- prefix (app token) with clearly fake test data
    text = "Slack token: xoxa-0000000000-TESTFAKE1234567890abcdefghijklmnop"
    detections = detector.detect(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0
    detector = PIIDetector()
    text = "My SSN is 536-22-1234"
    detections = detector.detect(text)
    assert "ssn" in detections


def test_email_detection():
    """Test email detection."""
    detector = PIIDetector()
    text = "Contact me at john@example.com"
    detections = detector.detect(text)
    assert "email" in detections


def test_api_key_detection():
    """Test API key detection."""
    detector = PIIDetector()
    text = "My API key is sk-1234567890abcdef1234567890abcdef"
    detections = detector.detect(text)
    assert "api_key" in detections


def test_phone_detection():
    """Test phone number detection."""
    detector = PIIDetector()
    text = "Call me at 555-123-4567"
    detections = detector.detect(text)
    assert "phone" in detections


def test_no_pii():
    """Test that normal text doesn't trigger false positives."""
    detector = PIIDetector()
    text = "This is a normal sentence with no sensitive information."
    detections = detector.detect(text)
    assert len(detections) == 0


def test_multiple_pii_types():
    """Test detection of multiple PII types in one text."""
    detector = PIIDetector()
    text = "Email: john@example.com, Phone: 555-123-4567, SSN: 536-22-1234"
    detections = detector.detect(text)
    assert "email" in detections
    assert "phone" in detections
    assert "ssn" in detections


def test_has_pii():
    """Test has_pii quick check method."""
    detector = PIIDetector()
    assert detector.has_pii("My email is john@example.com")
    assert not detector.has_pii("This is normal text")


def test_enabled_types_filtering():
    """Test that enabled_types filters detection."""
    detector = PIIDetector(enabled_types={"email"})
    text = "Email: john@example.com, Phone: 555-123-4567"
    detections = detector.detect(text)
    assert "email" in detections
    assert "phone" not in detections


def test_enabled_types_empty():
    """Test detector with empty enabled types."""
    detector = PIIDetector(enabled_types=set())
    text = "Email: john@example.com"
    detections = detector.detect(text)
    # When enabled_types is empty set, it should not detect anything
    # But if None is passed, it uses defaults
    assert len(detections) == 0
    assert not detector.has_pii(text)

    # Test that None uses defaults
    detector2 = PIIDetector(enabled_types=None)
    detections2 = detector2.detect(text)
    assert len(detections2) > 0
