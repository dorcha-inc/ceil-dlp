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


def test_detect_with_presidio_exception_handling():
    """Test Presidio exception handling."""

    # Mock analyzer to raise an exception
    with patch("ceil_dlp.detectors.presidio_adapter.get_presidio_analyzer") as mock_get:
        mock_analyzer = mock_get.return_value
        mock_analyzer.analyze.side_effect = Exception("Test error")

        with pytest.raises(RuntimeError, match="Failed to detect PII with Presidio"):
            detect_with_presidio("test text")
