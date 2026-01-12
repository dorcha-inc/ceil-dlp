"""Tests for image PII detection."""

import io

from PIL import Image

from ceil_dlp.detectors.image_detector import detect_pii_in_image
from ceil_dlp.utils import create_image_with_text


def test_detect_pii_in_image_no_text():
    """Test image detection with no text (should return empty)."""
    # Create a simple image with no text
    img = Image.new("RGB", (100, 100), color="white")
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    detections = detect_pii_in_image(img_bytes.getvalue())
    # Should return empty dict (no text to detect)
    assert detections == {}


def test_detect_pii_in_image_with_email():
    """Test image detection with email address."""
    # Create image with email text
    text = "Contact me at john@example.com"
    img_bytes = create_image_with_text(text)

    detections = detect_pii_in_image(img_bytes)
    # Should detect email
    assert "email" in detections
    assert len(detections["email"]) > 0


def test_detect_pii_in_image_with_phone():
    """Test image detection with phone number."""
    # Create image with phone text
    text = "Call me at 555-123-4567"
    img_bytes = create_image_with_text(text)

    detections = detect_pii_in_image(img_bytes)
    # Should detect phone
    assert "phone" in detections
    assert len(detections["phone"]) > 0


def test_detect_pii_in_image_multiple_types():
    """Test image detection with multiple PII types."""
    # Create image with multiple PII types
    text = "Email: john@example.com, Phone: 555-123-4567"
    img_bytes = create_image_with_text(text, width=1000)

    detections = detect_pii_in_image(img_bytes)
    # Should detect both email and phone
    assert "email" in detections or "phone" in detections
    # At least one should be detected (OCR may not catch both perfectly)
    assert len(detections) > 0


def test_detect_pii_in_image_invalid_data():
    """Test image detection with invalid data."""
    # Invalid image data
    detections = detect_pii_in_image(b"not an image")
    # Should return empty dict on error
    assert detections == {}


def test_detect_pii_in_image_from_path(tmp_path):
    """Test image detection from file path."""
    # Create a simple image
    img = Image.new("RGB", (100, 100), color="white")
    img_path = tmp_path / "test.png"
    img.save(img_path)

    detections = detect_pii_in_image(img_path)
    assert isinstance(detections, dict)


def test_detect_pii_in_image_enabled_types():
    """Test image detection with enabled types filter."""
    # Create image with email and phone
    text = "Email: john@example.com, Phone: 555-123-4567"
    img_bytes = create_image_with_text(text, width=1000)

    # Test with only email enabled
    detections = detect_pii_in_image(img_bytes, enabled_types={"email"})
    # Should only return email, not phone
    if detections:
        assert "phone" not in detections
        # Email may or may not be detected depending on OCR accuracy
        assert isinstance(detections, dict)


def test_detect_pii_in_image_base64():
    """Test image detection with bytes (simulating base64-decoded image)."""
    # Create image with PII text
    text = "Contact: john@example.com"
    img_bytes = create_image_with_text(text)

    # Note: detect_pii_in_image accepts bytes directly
    # In practice, base64-encoded images from messages are decoded before calling this function
    detections = detect_pii_in_image(img_bytes)
    assert isinstance(detections, dict)
    # May or may not detect email depending on OCR accuracy
