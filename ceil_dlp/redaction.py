"""Redaction and masking logic."""

import io
import logging
from pathlib import Path

from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine, ImageRedactorEngine

from ceil_dlp.detectors.presidio_adapter import get_presidio_analyzer

logger = logging.getLogger(__name__)


def mask_text(text: str, matches: list[tuple[str, int, int]], pii_type: str) -> str:
    """
    Mask detected PII in text.

    Args:
        text: Original text
        matches: List of (matched_text, start_pos, end_pos) tuples
        pii_type: Type of PII being masked

    Returns:
        Text with PII masked
    """
    if not matches:
        return text

    # Sort matches by position (reverse order to maintain indices)
    sorted_matches = sorted(matches, key=lambda x: x[1], reverse=True)

    masked_text = text
    for _matched_text, start, end in sorted_matches:
        replacement = f"[REDACTED_{pii_type.upper()}]"
        masked_text = masked_text[:start] + replacement + masked_text[end:]

    return masked_text


def apply_redaction(
    text: str, detections: dict[str, list[tuple[str, int, int]]]
) -> tuple[str, dict[str, list[str]]]:
    """
    Apply redaction/masking to text based on detected PII.

    Args:
        text: Original text
        detections: Dictionary mapping PII type to list of matches

    Returns:
        Tuple of (redacted_text, redacted_items) where redacted_items maps
        PII type to list of redacted values
    """
    redacted_text = text
    redacted_items = {}

    # Process each PII type
    for pii_type, matches in detections.items():
        if matches:
            # Extract matched texts for logging
            matched_texts = [match[0] for match in matches]
            redacted_items[pii_type] = matched_texts

            # Apply masking
            redacted_text = mask_text(redacted_text, matches, pii_type)

    return redacted_text, redacted_items


def redact_image(image_data: bytes | str | Path, pii_types: list[str] | None = None) -> bytes:
    """
    Redact PII in an image using Presidio Image Redactor.

    Args:
        image_data: Image as bytes, file path (str), or Path object
        pii_types: Optional list of PII types to redact. If None, redacts all detected PII.

    Returns:
        Redacted image as bytes (same format as input)
    """
    try:
        # Load image
        if isinstance(image_data, (str, Path)):
            image = Image.open(image_data)
            original_format = image.format
        elif isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
            original_format = image.format
        else:
            raise ValueError(f"Invalid image_data type: {type(image_data)}")

        # Use Presidio Image Redactor with our configured analyzer (smaller model)
        analyzer = get_presidio_analyzer()
        image_analyzer = ImageAnalyzerEngine(analyzer_engine=analyzer)
        engine = ImageRedactorEngine(image_analyzer_engine=image_analyzer)

        # Redact the image
        # The redact method returns a redacted PIL Image
        # fill parameter expects RGB tuple or int (0-255 for grayscale)
        redacted_image_pil = engine.redact(image, fill=(0, 0, 0))  # Black fill

        # Convert back to bytes
        output = io.BytesIO()
        # Preserve original format if available, otherwise use PNG
        save_format = original_format or "PNG"
        # Type ignore: redact returns PIL.Image which has save method
        redacted_image_pil.save(output, format=save_format)  # type: ignore[attr-defined]
        return output.getvalue()

    except Exception as e:
        logger.error(f"Error redacting image: {e}", exc_info=True)

        # Return original image on error
        if isinstance(image_data, bytes):
            return image_data
        elif isinstance(image_data, (str, Path)):
            with open(image_data, "rb") as f:
                return f.read()
        else:
            raise ValueError(f"Invalid image_data type: {type(image_data)}") from e
