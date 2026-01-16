"""Redaction and masking logic."""

import io
import logging
from pathlib import Path

from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine, ImageRedactorEngine

from ceil_dlp.detectors.presidio_adapter import get_analyzer

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


def _remove_overlapping_detections(
    detections: dict[str, list[tuple[str, int, int]]],
) -> dict[str, list[tuple[str, int, int]]]:
    """
    Remove overlapping detections across all PII types.

    When the same text is detected as multiple types (e.g., email and URL),
    we keep the longer match or prefer certain types. This prevents issues
    when redacting sequentially.

    Uses the shared remove_overlapping_matches utility with type priority.

    Args:
        detections: Dictionary mapping PII type to list of matches

    Returns:
        Dictionary with overlapping detections removed
    """
    from ceil_dlp.utils.overlaps import PatternMatch, remove_overlapping_matches

    if not detections:
        return {}

    # Type priority: prefer more specific types over generic ones
    # Higher priority = keep when overlapping (similar to preferring longer matches)
    type_priority = {
        "email": 10,
        "phone": 10,
        "credit_card": 10,
        "ssn": 10,
        "url": 5,  # Lower priority - often overlaps with email
    }

    # Collect all matches as PatternMatch and track their types
    # Format: PatternMatch = (text, start, end)
    all_matches: list[PatternMatch] = []
    match_to_type: dict[PatternMatch, str] = {}

    for pii_type, matches in detections.items():
        for text, start, end in matches:
            match: PatternMatch = (text, start, end)
            all_matches.append(match)
            match_to_type[match] = pii_type

    if not all_matches:
        return {}

    # Create priority map: type priority * 1000 + length
    # This ensures type priority takes precedence, but length breaks ties
    priority_map: dict[PatternMatch, float] = {}
    for match in all_matches:
        pii_type = match_to_type[match]
        _text, start, end = match
        type_prio = type_priority.get(pii_type, 0)
        length = end - start
        # Use large multiplier so type priority dominates
        priority_map[match] = type_prio * 1000 + length

    # Use shared overlap removal with type priority
    non_overlapping = remove_overlapping_matches(all_matches, priority_map)

    # Group back by type
    result: dict[str, list[tuple[str, int, int]]] = {}
    for match in non_overlapping:
        pii_type = match_to_type[match]
        if pii_type not in result:
            result[pii_type] = []
        result[pii_type].append(match)

    return result


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
    # Remove overlapping detections before redacting
    # This prevents issues when the same text is detected as multiple types
    non_overlapping_detections = _remove_overlapping_detections(detections)

    # Collect all matches with their types, sorted by position (reverse order)
    # This allows us to process all matches at once, maintaining correct positions
    all_matches: list[tuple[str, tuple[str, int, int]]] = []  # (pii_type, (text, start, end))
    redacted_items: dict[str, list[str]] = {}

    for pii_type, matches in non_overlapping_detections.items():
        if matches:
            # Extract matched texts for logging
            matched_texts = [match[0] for match in matches]
            redacted_items[pii_type] = matched_texts

            # Add all matches with their type
            for match in matches:
                all_matches.append((pii_type, match))

    # Sort by start position in reverse order (process from end to start)
    # This ensures positions remain valid as we replace text
    all_matches.sort(key=lambda x: x[1][1], reverse=True)

    # Apply all redactions in one pass
    redacted_text = text
    for pii_type, (_matched_text, start, end) in all_matches:
        replacement = f"[REDACTED_{pii_type.upper()}]"
        redacted_text = redacted_text[:start] + replacement + redacted_text[end:]

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
        image: Image.Image
        if isinstance(image_data, (str, Path)):
            image = Image.open(image_data)
            original_format = image.format
        elif isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
            original_format = image.format
        else:
            raise ValueError(f"Invalid image_data type: {type(image_data)}")

        # Use Presidio Image Redactor with our configured analyzer (smaller model)
        # Cache analyzer to avoid expensive re-initialization
        analyzer = get_analyzer()
        image_analyzer = ImageAnalyzerEngine(analyzer_engine=analyzer)
        engine = ImageRedactorEngine(image_analyzer_engine=image_analyzer)

        # Redact the image
        # The redact method returns a redacted PIL Image
        # fill parameter expects RGB tuple or int (0-255 for grayscale)
        redacted_image_pil = engine.redact(
            image,  # pyright: ignore[reportArgumentType]
            fill=(0, 0, 0),
        )

        # Convert back to bytes
        output = io.BytesIO()
        # Preserve original format if available, otherwise use PNG
        save_format = original_format or "PNG"
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
