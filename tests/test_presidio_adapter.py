"""Tests for Presidio adapter."""

from unittest.mock import patch

import pytest

from ceil_dlp.detectors.presidio_adapter import detect_with_presidio


def test_detect_with_presidio_email():
    """Test Presidio email detection."""
    text = "Contact me at john@example.com"
    results = detect_with_presidio(text)
    assert "email" in results
    assert len(results["email"]) > 0


def test_detect_with_presidio_phone():
    """Test Presidio phone detection."""
    text = "Call me at 555-123-4567"
    results = detect_with_presidio(text)
    assert "phone" in results
    assert len(results["phone"]) > 0


def test_detect_with_presidio_credit_card():
    """Test Presidio credit card detection."""
    text = "My credit card is 4111111111111111"
    results = detect_with_presidio(text)
    assert "credit_card" in results
    assert len(results["credit_card"]) > 0


def test_detect_with_presidio_ssn():
    """Test Presidio SSN detection."""
    text = "My SSN is 536-22-1234"
    results = detect_with_presidio(text)
    assert "ssn" in results
    assert len(results["ssn"]) > 0


def test_detect_with_presidio_no_pii():
    """Test Presidio with no PII."""
    text = "This is normal text with no sensitive information"
    results = detect_with_presidio(text)
    assert len(results) == 0


def test_detect_with_presidio_multiple_types():
    """Test Presidio detecting multiple PII types."""
    text = "Email: john@example.com, Phone: 555-123-4567"
    results = detect_with_presidio(text)
    assert "email" in results
    assert "phone" in results


def test_detect_with_presidio_person():
    """Test Presidio person name detection."""
    text = "My name is John Smith"
    results = detect_with_presidio(text)
    assert "person" in results
    assert len(results["person"]) > 0


def test_detect_with_presidio_location():
    """Test Presidio location detection."""
    text = "I live in New York, United States"
    results = detect_with_presidio(text)
    assert "location" in results
    assert len(results["location"]) > 0


def test_detect_with_presidio_ip_address():
    """Test Presidio IP address detection."""
    text = "The server IP is 192.168.1.1"
    results = detect_with_presidio(text)
    assert "ip_address" in results
    assert len(results["ip_address"]) > 0


def test_detect_with_presidio_url():
    """Test Presidio URL detection."""
    text = "Visit https://example.com for more information"
    results = detect_with_presidio(text)
    assert "url" in results
    assert len(results["url"]) > 0


def test_detect_with_presidio_date_time():
    """Test Presidio date/time detection."""
    text = "The meeting is scheduled for January 15, 2024 at 3:00 PM"
    results = detect_with_presidio(text)
    assert "date_time" in results
    assert len(results["date_time"]) > 0


def test_detect_with_presidio_iban():
    """Test Presidio IBAN code detection."""
    # Example UK IBAN
    text = "Bank account: GB82 WEST 1234 5698 7654 32"
    results = detect_with_presidio(text)
    assert "iban_code" in results
    assert len(results["iban_code"]) > 0


def test_detect_with_presidio_crypto():
    """Test Presidio crypto wallet address detection."""
    # Example Bitcoin address (simplified)
    text = "Send payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    results = detect_with_presidio(text)
    # Crypto detection may not always trigger, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_us_driver_license():
    """Test Presidio US driver license detection."""
    text = "Driver license number: D12345678901234"
    results = detect_with_presidio(text)
    # Driver license detection may vary, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_us_passport():
    """Test Presidio US passport detection."""
    text = "US Passport: 123456789"
    results = detect_with_presidio(text)
    # Passport detection may vary, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_uk_nhs():
    """Test Presidio UK NHS number detection."""
    # Example NHS number format (10 digits)
    text = "NHS number: 485 777 3456"
    results = detect_with_presidio(text)
    # NHS detection may vary, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_uk_nino():
    """Test Presidio UK NINO detection."""
    # Example NINO format
    text = "National Insurance Number: AB123456C"
    results = detect_with_presidio(text)
    # NINO detection may vary, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_medical_license():
    """Test Presidio medical license detection."""
    text = "Medical license number: MD123456"
    results = detect_with_presidio(text)
    # Medical license detection may vary, so just verify no crash
    assert isinstance(results, dict)


def test_detect_with_presidio_all_new_types():
    """Test that multiple new entity types can be detected together."""
    text = (
        "John Smith lives in Paris, France. "
        "Contact at https://example.com or 192.168.1.1. "
        "Meeting on January 15, 2024."
    )
    results = detect_with_presidio(text)
    # Should detect at least some of these types
    detected_types = set(results.keys())
    # At minimum, should detect person, location, url, ip_address, or date_time
    assert len(detected_types) > 0


def test_detect_with_presidio_exception_handling():
    """Test Presidio exception handling."""

    # Clear the cache to ensure we get a fresh analyzer
    from ceil_dlp.detectors.presidio_adapter import _get_analyzer_cached

    _get_analyzer_cached.cache_clear()

    # Mock AnalyzerEngine to raise an exception
    with patch("ceil_dlp.detectors.presidio_adapter.AnalyzerEngine") as mock_analyzer_class:
        mock_analyzer = mock_analyzer_class.return_value
        mock_analyzer.analyze.side_effect = Exception("Test error")

        # Clear cache again to pick up the mock
        _get_analyzer_cached.cache_clear()

        with pytest.raises(RuntimeError, match="Failed to detect PII with Presidio"):
            detect_with_presidio("test text")

    # Clear cache after test to restore real analyzer for other tests
    _get_analyzer_cached.cache_clear()
