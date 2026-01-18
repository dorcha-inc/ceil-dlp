"""Tests for PDF PII detection."""

from ceil_dlp.detectors.pdf_detector import detect_pii_in_pdf
from ceil_dlp.utils import create_pdf_with_text


def test_detect_pii_in_pdf_no_pii():
    """Test PDF detection with no PII (should return empty)."""
    # Create a PDF with no PII
    pdf_bytes = create_pdf_with_text("This is just regular text with no PII")
    detections = detect_pii_in_pdf(pdf_bytes)
    # Should return empty dict (no PII in this text)
    assert detections == {}


def test_detect_pii_in_pdf_from_path(tmp_path):
    """Test PDF detection from file path."""
    pdf_bytes = create_pdf_with_text("Contact: john@example.com")
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_bytes(pdf_bytes)

    detections = detect_pii_in_pdf(pdf_path)
    assert isinstance(detections, dict)
    # Should detect email
    assert "email" in detections


def test_detect_pii_in_pdf_invalid_data():
    """Test PDF detection with invalid data."""
    invalid_data = b"not a pdf"
    detections = detect_pii_in_pdf(invalid_data)
    # Should return empty dict on error
    assert detections == {}


def test_detect_pii_in_pdf_invalid_type():
    """Test PDF detection with invalid pdf_data type."""
    # Should handle gracefully and return empty dict
    detections = detect_pii_in_pdf(123)  # type: ignore[arg-type]
    assert detections == {}


def test_detect_pii_in_pdf_with_enabled_types():
    """Test PDF detection with enabled types filter."""
    pdf_bytes = create_pdf_with_text("Contact: john@example.com or call 555-123-4567")
    enabled_types = {"email", "phone"}
    detections = detect_pii_in_pdf(pdf_bytes, enabled_types=enabled_types)
    assert isinstance(detections, dict)
    # Should detect email and/or phone
    assert len(detections) > 0
    # All detected types should be in enabled_types
    for pii_type in detections:
        assert pii_type in enabled_types
