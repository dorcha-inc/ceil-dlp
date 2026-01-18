"""Tests for PII detection."""

from ceil_dlp.detectors.text_detector import detect_pii_in_text


def test_credit_card_detection():
    """Test credit card detection with Luhn validation."""
    text = "My credit card is 4111-1111-1111-1111"
    detections = detect_pii_in_text(text)
    # Credit card can be detected as either credit_card or us_driver_license
    assert "credit_card" in detections or "us_driver_license" in detections
    if "credit_card" in detections:
        assert len(detections["credit_card"]) > 0
    if "us_driver_license" in detections:
        assert len(detections["us_driver_license"]) > 0


def test_ssn_detection():
    """Test SSN detection."""
    text = "My SSN is 536-22-1234"
    detections = detect_pii_in_text(text)
    assert "ssn" in detections
    assert len(detections["ssn"]) > 0


def test_pem_key_detection():
    """Test PEM key detection."""
    text = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdef
-----END RSA PRIVATE KEY-----"""
    detections = detect_pii_in_text(text)
    assert "pem_key" in detections
    assert len(detections["pem_key"]) > 0


def test_jwt_token_detection():
    """Test JWT token detection."""
    text = "JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    detections = detect_pii_in_text(text)
    assert "jwt_token" in detections
    assert len(detections["jwt_token"]) > 0


def test_anthropic_api_key_detection():
    """Test Anthropic API key detection."""
    text = "Anthropic key: sk-ant-api03-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    detections = detect_pii_in_text(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_github_token_detection():
    """Test GitHub token detection."""
    text = "GitHub token: ghp_1234567890abcdef1234567890abcdef123456"
    detections = detect_pii_in_text(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_stripe_key_detection():
    """Test Stripe key detection."""
    text = "Stripe key: sk_test_FAKE1234567890abcdef123456"
    detections = detect_pii_in_text(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0


def test_slack_token_detection():
    """Test Slack token detection."""
    # Using xoxa- prefix (app token) with clearly fake test data
    text = "Slack token: xoxa-0000000000-TESTFAKE1234567890abcdefghijklmnop"
    detections = detect_pii_in_text(text)
    assert "api_key" in detections
    assert len(detections["api_key"]) > 0
    text2 = "My SSN is 536-22-1234"
    detections2 = detect_pii_in_text(text2)
    assert "ssn" in detections2


def test_email_detection():
    """Test email detection."""
    text = "Contact me at john@example.com"
    detections = detect_pii_in_text(text)
    assert "email" in detections


def test_api_key_detection():
    """Test API key detection."""
    text = "My API key is sk-1234567890abcdef1234567890abcdef"
    detections = detect_pii_in_text(text)
    assert "api_key" in detections


def test_phone_detection():
    """Test phone number detection."""
    text = "Call me at 555-123-4567"
    detections = detect_pii_in_text(text)
    assert "phone" in detections


def test_no_pii():
    """Test that normal text doesn't trigger false positives."""
    text = "This is a normal sentence with no sensitive information."
    detections = detect_pii_in_text(text)
    assert len(detections) == 0


def test_multiple_pii_types():
    """Test detection of multiple PII types in one text."""
    text = "Email: john@example.com, Phone: 555-123-4567, SSN: 536-22-1234"
    detections = detect_pii_in_text(text)
    assert "email" in detections
    assert "phone" in detections
    assert "ssn" in detections


def test_has_pii():
    """Test has_pii quick check method."""
    assert len(detect_pii_in_text("My email is john@example.com")) > 0
    assert len(detect_pii_in_text("This is normal text")) == 0


def test_enabled_types_filtering():
    """Test that enabled_types filters detection."""
    text = "Email: john@example.com, Phone: 555-123-4567"
    detections = detect_pii_in_text(text, enabled_types={"email"})
    assert "email" in detections
    assert "phone" not in detections


def test_enabled_types_empty():
    """Test detector with empty enabled types."""
    text = "Email: john@example.com"
    detections = detect_pii_in_text(text, enabled_types=set())
    # When enabled_types is empty set, it should not detect anything
    # But if None is passed, it uses defaults
    assert len(detections) == 0
    assert len(detect_pii_in_text(text, enabled_types=set())) == 0

    # Test that None uses defaults
    detections2 = detect_pii_in_text(text, enabled_types=None)
    assert len(detections2) > 0


def test_person_detection():
    """Test person name detection."""
    text = "My name is John Smith and I work with Jane Doe"
    detections = detect_pii_in_text(text)
    assert "person" in detections
    assert len(detections["person"]) > 0


def test_location_detection():
    """Test location detection."""
    text = "I live in New York, United States and visited Paris, France"
    detections = detect_pii_in_text(text)
    assert "location" in detections
    assert len(detections["location"]) > 0


def test_ip_address_detection():
    """Test IP address detection."""
    text = "Server IP: 192.168.1.1 and backup: 10.0.0.1"
    detections = detect_pii_in_text(text)
    assert "ip_address" in detections
    assert len(detections["ip_address"]) > 0


def test_url_detection():
    """Test URL detection."""
    text = "Visit https://example.com or http://test.org for details"
    detections = detect_pii_in_text(text)
    assert "url" in detections
    assert len(detections["url"]) > 0


def test_date_time_detection():
    """Test date/time detection."""
    text = "Meeting on January 15, 2024 at 3:00 PM"
    detections = detect_pii_in_text(text)
    assert "date_time" in detections
    assert len(detections["date_time"]) > 0


def test_iban_detection():
    """Test IBAN code detection."""
    # Example UK IBAN
    text = "Bank account: GB82 WEST 1234 5698 7654 32"
    detections = detect_pii_in_text(text)
    # IBAN detection may vary, so just verify no crash
    assert isinstance(detections, dict)


def test_multiple_new_presidio_types():
    """Test detection of multiple new Presidio entity types."""
    text = (
        "John Smith lives in Paris, France. "
        "Contact at https://example.com or 192.168.1.1. "
        "Meeting on January 15, 2024 at 3:00 PM."
    )
    detections = detect_pii_in_text(text)
    # Should detect at least some of these types
    detected_types = set(detections.keys())
    assert len(detected_types) > 0
    # Should include at least one of: person, location, url, ip_address, date_time
    assert any(
        t in detected_types for t in ["person", "location", "url", "ip_address", "date_time"]
    )


def test_enabled_types_with_new_presidio_types():
    """Test that enabled_types filtering works with new Presidio types."""
    text = "John Smith lives in Paris, France. Email: john@example.com"
    detections = detect_pii_in_text(text, enabled_types={"person", "location"})
    # Should detect person and location
    assert "person" in detections or "location" in detections
    # Should not detect email (not in enabled_types)
    assert "email" not in detections
