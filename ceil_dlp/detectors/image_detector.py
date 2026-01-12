"""Image PII detection using Presidio Image Redactor."""

import io
import logging
from pathlib import Path

from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine

from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.presidio_adapter import get_presidio_analyzer

logger = logging.getLogger(__name__)


# Map Presidio entity types to our PII types
PRESIDIO_TO_PII_TYPE: dict[str, str] = {
    "CREDIT_CARD": "credit_card",
    "US_SSN": "ssn",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "INTERNATIONAL_PHONE_NUMBER": "phone",
}


def detect_pii_in_image(
    image_data: bytes | str | Path, enabled_types: set[str] | None = None
) -> dict[str, list[PatternMatch]]:
    """
    Detect PII in an image using Presidio Image Redactor.

    Uses Presidio Image Redactor's analyzer to perform OCR and PII detection in one step.
    This provides both text extraction and PII detection with proper image coordinates.

    Args:
        image_data: Image as bytes, file path (str), or Path object
        enabled_types: Optional set of PII types to detect. If None, detects all types.

    Returns:
        Dictionary mapping PII type to list of matches (same format as text detection).
        Returns empty dict if image processing fails.
    """
    try:
        # Load image
        if isinstance(image_data, (str, Path)):
            image = Image.open(image_data)
        elif isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
        else:
            logger.error(f"Invalid image_data type: {type(image_data)}")
            return {}

        # Use Presidio Image Redactor with our configured analyzer (smaller model)
        # This performs OCR and PII detection in one step
        analyzer = get_presidio_analyzer()
        image_analyzer = ImageAnalyzerEngine(analyzer_engine=analyzer)
        analyzer_results = image_analyzer.analyze(
            image=image,
            language="en",
        )

        if not analyzer_results:
            logger.debug("No PII detected in image")
            return {}

        # Convert Presidio results to our PatternMatch format
        results: dict[str, list[PatternMatch]] = {}
        for entity in analyzer_results:
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
