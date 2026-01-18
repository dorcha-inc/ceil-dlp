"""Image PII detection using Presidio Image Redactor."""

import logging
from functools import lru_cache
from pathlib import Path

from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine

from ceil_dlp.detectors.doctr_ocr import get_doctr_heavy_ocr_engine, get_doctr_ocr_engine
from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.presidio_adapter import PRESIDIO_TO_PII_TYPE, get_analyzer
from ceil_dlp.utils import image_to_pil_image

logger = logging.getLogger(__name__)


@lru_cache(maxsize=3)  # Cache up to 3 analyzers (one per strength level: 1, 2, or 3)
def get_image_analyzer(ner_strength: int = 1) -> ImageAnalyzerEngine:
    """
    Get cached ImageAnalyzerEngine instance with docTR OCR engine.

    Uses lighter docTR models since we use ensemble with Tesseract.

    Args:
        ner_strength: NER model strength:
                     - 1: en_core_web_lg (spaCy)
                     - 2: transformer-based NER (dslim/bert-base-NER)
                     - 3: GLiNER zero-shot NER (best for long texts and hyphenated names)
                     Defaults to 1 for backward compatibility.

    Returns:
        ImageAnalyzerEngine configured with the specified NER model strength.

    Raises:
        ValueError: If ner_strength is not 1, 2, or 3.
    """
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for transformer-based NER, or 3 for GLiNER."
        )
    analyzer = get_analyzer(ner_strength=ner_strength)
    # Use docTR OCR engine (lighter model for ensemble approach)
    ocr_engine = get_doctr_ocr_engine()
    return ImageAnalyzerEngine(analyzer_engine=analyzer, ocr=ocr_engine)


@lru_cache(maxsize=3)  # Cache up to 3 analyzers (one per strength level: 1, 2, or 3)
def get_tesseract_image_analyzer(ner_strength: int = 1) -> ImageAnalyzerEngine:
    """
    Get cached ImageAnalyzerEngine instance with Tesseract OCR engine.

    Used for ensemble approach: Tesseract redaction on docTR-redacted images.

    Args:
        ner_strength: NER model strength:
                     - 1: en_core_web_lg (spaCy)
                     - 2: transformer-based NER (dslim/bert-base-NER)
                     - 3: GLiNER zero-shot NER (best for long texts and hyphenated names)
                     Defaults to 1 for backward compatibility.

    Returns:
        ImageAnalyzerEngine configured with the specified NER model strength.

    Raises:
        ValueError: If ner_strength is not 1, 2, or 3.
    """
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for transformer-based NER, or 3 for GLiNER."
        )
    analyzer = get_analyzer(ner_strength=ner_strength)
    # Use default Tesseract OCR (no custom OCR engine = uses Tesseract)
    return ImageAnalyzerEngine(analyzer_engine=analyzer)


@lru_cache(maxsize=3)  # Cache up to 3 analyzers (one per strength level: 1, 2, or 3)
def get_doctr_heavy_image_analyzer(ner_strength: int = 1) -> ImageAnalyzerEngine:
    """
    Get cached ImageAnalyzerEngine instance with heavy docTR OCR engine.

    Used for ensemble approach: Heavy docTR redaction as third pass for maximum accuracy.

    Args:
        ner_strength: NER model strength:
                     - 1: en_core_web_lg (spaCy)
                     - 2: transformer-based NER (dslim/bert-base-NER)
                     - 3: GLiNER zero-shot NER (best for long texts and hyphenated names)
                     Defaults to 1 for backward compatibility.

    Returns:
        ImageAnalyzerEngine configured with the specified NER model strength.

    Raises:
        ValueError: If ner_strength is not 1, 2, or 3.
    """
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for transformer-based NER, or 3 for GLiNER."
        )
    analyzer = get_analyzer(ner_strength=ner_strength)
    # Use heavier docTR OCR engine for third pass
    ocr_engine = get_doctr_heavy_ocr_engine()
    return ImageAnalyzerEngine(analyzer_engine=analyzer, ocr=ocr_engine)


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
        image = image_to_pil_image(image_data)

        # Use Presidio Image Redactor with our configured analyzer
        # This performs OCR and PII detection in one step
        image_analyzer = get_image_analyzer()

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
