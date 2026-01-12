"""Tests for redaction and masking."""

import io

from PIL import Image

from ceil_dlp.detectors.pii_detector import PIIDetector
from ceil_dlp.redaction import apply_redaction, mask_text, redact_image
from ceil_dlp.utils import create_image_with_text


def test_email_masking():
    """Test email masking."""
    detector = PIIDetector()
    text = "Contact me at john@example.com"
    detections = detector.detect(text)
    redacted, items = apply_redaction(text, detections)
    assert "[REDACTED_EMAIL]" in redacted
    assert "john@example.com" not in redacted
    assert "email" in items


def test_multiple_redactions():
    """Test multiple PII types being redacted."""
    detector = PIIDetector()
    text = "Email: john@example.com, Phone: 555-123-4567"
    detections = detector.detect(text)
    redacted, items = apply_redaction(text, detections)
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "john@example.com" not in redacted
    assert "555-123-4567" not in redacted


def test_redaction_empty_matches():
    """Test redaction with empty matches."""
    text = "Normal text"
    result = mask_text(text, [], "email")
    assert result == text


def test_redaction_empty_detections():
    """Test apply_redaction with empty detections."""
    text = "Normal text"
    redacted, items = apply_redaction(text, {})
    assert redacted == text
    assert items == {}


def test_redact_image():
    """Test image redaction."""
    # Create a simple image
    img = Image.new("RGB", (100, 100), color="white")
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    # Redact the image
    redacted = redact_image(img_bytes.getvalue())
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_image_with_pii():
    """Test image redaction with actual PII content."""
    text = "Contact: john@example.com"
    img_bytes = create_image_with_text(text)

    # Redact the image
    redacted = redact_image(img_bytes)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0
    # Redacted image should be different from original (PII should be blacked out)
    assert redacted != img_bytes


def test_redact_image_from_path(tmp_path):
    """Test image redaction from file path."""
    # Create a simple image
    img = Image.new("RGB", (100, 100), color="white")
    img_path = tmp_path / "test.png"
    img.save(img_path)

    # Redact the image
    redacted = redact_image(img_path)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_image_invalid_data():
    """Test image redaction with invalid data."""
    # Invalid image data - should return original on error
    invalid_data = b"not an image"
    redacted = redact_image(invalid_data)
    assert redacted == invalid_data
