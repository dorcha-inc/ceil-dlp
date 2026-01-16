"""Image PII detection using Presidio Image Redactor."""

import io
import logging
from functools import lru_cache
from pathlib import Path

from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine

from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.presidio_adapter import PRESIDIO_TO_PII_TYPE, get_analyzer

logger = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_image_analyzer() -> ImageAnalyzerEngine:
    """Get cached ImageAnalyzerEngine instance to avoid expensive re-initialization."""
    analyzer = get_analyzer()
    return ImageAnalyzerEngine(analyzer_engine=analyzer)


def detect_pii_in_image(
    image_data: bytes | str | Path | Image.Image, enabled_types: set[str] | None = None
) -> dict[str, list[PatternMatch]]:
    """
    Detect PII in an image using Presidio Image Redactor and custom pattern detection.

    Uses Presidio Image Redactor's analyzer to perform OCR and PII detection for all
    Presidio entity types (credit cards, SSNs, emails, phones, person names, locations,
    IP addresses, URLs, medical licenses, and country-specific identifiers). Also extracts
    OCR text and runs custom pattern detection for API keys, secrets, and other custom types.

    Args:
        image_data: Image as bytes, file path (str), Path object, or PIL Image
        enabled_types: Optional set of PII types to detect. If None, detects all types.

    Returns:
        Dictionary mapping PII type to list of matches (same format as text detection).
        Returns empty dict if image processing fails.
    """
    try:
        # Load image
        if isinstance(image_data, Image.Image):
            # Already a PIL Image, use it directly
            image = image_data
        elif isinstance(image_data, (str, Path)):
            image = Image.open(image_data)
        elif isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
        else:
            logger.error(f"Invalid image_data type: {type(image_data)}")
            return {}

        # Use Presidio Image Redactor with our configured analyzer (smaller model)
        # This performs OCR and PII detection in one step
        # Use cached image analyzer to avoid expensive re-initialization
        image_analyzer = _get_image_analyzer()
        analyzer_results = image_analyzer.analyze(
            image=image,
            language="en",
        )

        # Convert Presidio results to our PatternMatch format
        results: dict[str, list[PatternMatch]] = {}

        # Process Presidio results (standard PII types + custom secrets via PatternRecognizers)
        if analyzer_results:
            for entity in analyzer_results:
                # Map Presidio entity type to our PII type
                # This includes both standard Presidio types and our custom secret types
                pii_type = PRESIDIO_TO_PII_TYPE.get(entity.entity_type, entity.entity_type.lower())

                # Filter by enabled types if specified
                if enabled_types and pii_type not in enabled_types:
                    continue

                # Note: entity.start and entity.end are positions in the OCR-extracted text,
                # not image coordinates. For image redaction, Presidio Image Redactor
                # handles the coordinate mapping internally.
                # We use a placeholder text since we don't have the actual OCR text here
                match_text = f"[{pii_type}_detected_in_image]"

                if pii_type not in results:
                    results[pii_type] = []
                results[pii_type].append((match_text, entity.start, entity.end))

        return results

    except Exception as e:
        logger.error(f"Error detecting PII in image: {e}", exc_info=True)
        return {}
