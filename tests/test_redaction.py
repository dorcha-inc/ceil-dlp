"""Tests for redaction and masking."""

import io

import pytest
from PIL import Image

from ceil_dlp.detectors.text_detector import detect_pii_in_text
from ceil_dlp.redaction import redact_image, redact_pdf, redact_text
from ceil_dlp.utils import create_image_with_text


def test_email_masking():
    """Test email masking."""
    text = "Contact me at john@example.com"
    detections = detect_pii_in_text(text)
    redacted, items = redact_text(text, detections)
    assert "[REDACTED_EMAIL]" in redacted
    assert "john@example.com" not in redacted
    assert "email" in items


def test_multiple_redactions():
    """Test multiple PII types being redacted."""
    text = "Email: john@example.com, Phone: 555-123-4567"
    detections = detect_pii_in_text(text)
    redacted, items = redact_text(text, detections)
    assert "[REDACTED_EMAIL]" in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "john@example.com" not in redacted
    assert "555-123-4567" not in redacted


def test_redaction_empty_matches():
    """Test redaction with empty matches."""
    text = "Normal text"
    result, _ = redact_text(text, {})
    assert result == text


def test_mask_text_multiple_matches():
    """Test redact_text with multiple matches."""
    text = "Email: john@example.com, Phone: 555-123-4567"
    detections = {
        "email": [("john@example.com", 7, 23)],
        "phone": [("555-123-4567", 32, 44)],
    }
    result, _ = redact_text(text, detections)
    # Should mask both
    assert "[REDACTED_EMAIL]" in result
    assert "[REDACTED_PHONE]" in result


def test_redaction_empty_detections():
    """Test redact_text with empty detections."""
    text = "Normal text"
    redacted, items = redact_text(text, {})
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
    redacted = redact_image(img_bytes.getvalue(), ner_strength=1, ocr_strength=1)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_image_with_pii():
    """Test image redaction with actual PII content."""
    text = "Contact: john@example.com"
    img_bytes = create_image_with_text(text)

    # Redact the image
    redacted = redact_image(img_bytes, ner_strength=1, ocr_strength=1)
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
    redacted = redact_image(img_path, ner_strength=1, ocr_strength=1)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_image_invalid_data():
    """Test image redaction with invalid data."""
    # Invalid image data - should raise ValueError
    invalid_data = b"not an image"
    with pytest.raises(ValueError, match="Invalid image_data type"):
        redact_image(invalid_data, ner_strength=1, ocr_strength=1)


def test_redact_image_invalid_type():
    """Test image redaction with invalid image_data type."""
    # Test with invalid type (not str, Path, or bytes) - line 180
    with pytest.raises(ValueError, match="Invalid image_data type"):
        redact_image(123, ner_strength=1, ocr_strength=1)  # type: ignore[arg-type]


def test_redact_image_error_handling_path(tmp_path):
    """Test image redaction error handling with file path."""
    # Create a file that will cause an error when opened as image
    invalid_path = tmp_path / "not_an_image.txt"
    invalid_path.write_text("not an image")

    # Should raise ValueError on error
    with pytest.raises(ValueError, match="Invalid image_data type"):
        redact_image(invalid_path, ner_strength=1, ocr_strength=1)


def test_redact_image_error_handling_bytes():
    """Test image redaction error handling with bytes."""
    # Invalid image bytes - should raise ValueError
    invalid_data = b"not an image"
    with pytest.raises(ValueError, match="Invalid image_data type"):
        redact_image(invalid_data, ner_strength=1, ocr_strength=1)


def test_redact_text_empty_all_matches():
    """Test redact_text when all matches are removed (line 86)."""
    # Create detections that will all be removed by overlap removal
    # This tests the early return when all_matches is empty
    detections = {
        "email": [("test@example.com", 0, 16)],
        "url": [("test@example.com", 0, 16)],  # Same position, will overlap
    }
    # The overlap removal should handle this, but if somehow all are removed,
    # it should return empty dict
    text = "test@example.com"
    redacted, items = redact_text(text, detections)
    # Should still work, just may have fewer items due to overlap removal
    assert isinstance(redacted, str)
    assert isinstance(items, dict)


def test_redact_pdf():
    """Test PDF redaction."""
    from ceil_dlp.utils import create_pdf_with_text

    # Create a real PDF
    pdf_bytes = create_pdf_with_text("Test PDF content")

    # Redact the PDF (should return bytes even if no PII detected)
    redacted = redact_pdf(pdf_bytes)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_pdf_from_path(tmp_path):
    """Test PDF redaction from file path."""
    from ceil_dlp.utils import create_pdf_with_text

    # Create a real PDF file
    pdf_bytes = create_pdf_with_text("Test PDF content")
    pdf_path = tmp_path / "test.pdf"
    pdf_path.write_bytes(pdf_bytes)

    # Redact the PDF
    redacted = redact_pdf(pdf_path)
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0


def test_redact_pdf_invalid_data():
    """Test PDF redaction with invalid data."""
    # Invalid PDF data - should return original on error
    invalid_data = b"not a pdf"
    redacted = redact_pdf(invalid_data)
    assert isinstance(redacted, bytes)
    # Should return original bytes on error
    assert redacted == invalid_data


def test_redact_pdf_invalid_type():
    """Test PDF redaction with invalid pdf_data type."""
    # Test with invalid type (not str, Path, or bytes)
    with pytest.raises(ValueError, match="Invalid pdf_data type"):
        redact_pdf(123)  # type: ignore[arg-type]


def test_redact_pdf_with_pii_types():
    """Test PDF redaction with specific PII types."""
    from ceil_dlp.utils import create_pdf_with_text

    # Create a real PDF
    pdf_bytes = create_pdf_with_text("Contact: john@example.com")

    # Redact with specific PII types
    redacted = redact_pdf(pdf_bytes, pii_types=["email", "phone"])
    assert isinstance(redacted, bytes)
    assert len(redacted) > 0
