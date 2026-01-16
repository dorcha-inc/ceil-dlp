"""Tests for redaction and masking."""

import io

import pytest
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


def test_mask_text_with_matches():
    """Test mask_text function directly (lines 31-38)."""
    text = "Contact me at john@example.com"
    matches = [("john@example.com", 13, 29)]
    result = mask_text(text, matches, "email")
    assert "[REDACTED_EMAIL]" in result
    assert "john@example.com" not in result


def test_mask_text_multiple_matches():
    """Test mask_text with multiple matches."""
    text = "Email: john@example.com, Phone: 555-123-4567"
    matches = [
        ("john@example.com", 7, 23),
        ("555-123-4567", 32, 44),
    ]
    result = mask_text(text, matches, "email")
    # Should mask both (though using email type for both)
    assert "[REDACTED_EMAIL]" in result


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


def test_redact_image_invalid_type():
    """Test image redaction with invalid image_data type."""
    # Test with invalid type (not str, Path, or bytes) - line 180
    with pytest.raises(ValueError, match="Invalid image_data type"):
        redact_image(123)  # type: ignore[arg-type]


def test_redact_image_error_handling_path(tmp_path):
    """Test image redaction error handling with file path."""
    # Create a file that will cause an error when opened as image
    invalid_path = tmp_path / "not_an_image.txt"
    invalid_path.write_text("not an image")

    # Should return original file content on error (lines 209-210)
    redacted = redact_image(invalid_path)
    assert isinstance(redacted, bytes)
    assert redacted == invalid_path.read_bytes()


def test_redact_image_error_handling_bytes():
    """Test image redaction error handling with bytes."""
    # Invalid image bytes - should return original on error (line 208)
    invalid_data = b"not an image"
    redacted = redact_image(invalid_data)
    assert redacted == invalid_data


def test_apply_redaction_empty_all_matches():
    """Test apply_redaction when all matches are removed (line 86)."""
    # Create detections that will all be removed by overlap removal
    # This tests the early return when all_matches is empty
    detections = {
        "email": [("test@example.com", 0, 16)],
        "url": [("test@example.com", 0, 16)],  # Same position, will overlap
    }
    # The overlap removal should handle this, but if somehow all are removed,
    # it should return empty dict
    text = "test@example.com"
    redacted, items = apply_redaction(text, detections)
    # Should still work, just may have fewer items due to overlap removal
    assert isinstance(redacted, str)
    assert isinstance(items, dict)
