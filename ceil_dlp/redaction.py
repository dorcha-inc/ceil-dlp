"""Redaction and masking logic."""

import io
import logging
from pathlib import Path
from typing import cast

import pypdfium2 as pdfium
from PIL import Image
from presidio_image_redactor import ImageRedactorEngine

from ceil_dlp.detectors.image_detector import (
    get_doctr_heavy_image_analyzer,
    get_image_analyzer,
    get_tesseract_image_analyzer,
)
from ceil_dlp.detectors.pdf_detector import detect_pii_in_pdf
from ceil_dlp.detectors.presidio_adapter import get_pii_type_to_entities
from ceil_dlp.utils import image_to_pil_image

logger = logging.getLogger(__name__)


def _redact_with_ocr_engine(
    image: Image.Image,
    ocr_type: int,
    ner_strength: int,
    entities_to_redact: list[str] | None,
) -> Image.Image:
    """Helper function to redact an image with a specific OCR engine and NER strength.

    Args:
        image: Image to redact
        ocr_type: OCR engine type (1=docTR, 2=tesseract, 3=heavy docTR)
        ner_strength: NER model strength (1, 2, or 3)
        entities_to_redact: List of Presidio entity types to redact

    Returns:
        Redacted image
    """
    if ocr_type == 1:
        analyzer = get_image_analyzer(ner_strength=ner_strength)
    elif ocr_type == 2:
        analyzer = get_tesseract_image_analyzer(ner_strength=ner_strength)
    elif ocr_type == 3:
        analyzer = get_doctr_heavy_image_analyzer(ner_strength=ner_strength)
    else:
        raise ValueError(f"Invalid ocr_type: {ocr_type}. Must be 1, 2, or 3.")

    engine = ImageRedactorEngine(image_analyzer_engine=analyzer)
    return cast(
        Image.Image,
        engine.redact(
            image,  # pyright: ignore[reportArgumentType]
            fill=(0, 0, 0),
            entities=entities_to_redact if entities_to_redact else None,
        ),
    )


def _apply_redaction_to_text(
    text: str, detections: dict[str, list[tuple[str, int, int]]]
) -> tuple[str, dict[str, list[str]]]:
    """
    Internal helper: Apply redaction/masking to text based on detected PII.

    Args:
        text: Original text
        detections: Dictionary mapping PII type to list of matches

    Returns:
        Tuple of (redacted_text, redacted_items) where redacted_items maps
        PII type to list of redacted values
    """
    # Collect all matches with their types, sorted by position (reverse order)
    # This allows us to process all matches at once, maintaining correct positions
    # Presidio handles overlap removal internally, so we don't need to do it here
    all_matches: list[tuple[str, tuple[str, int, int]]] = []  # (pii_type, (text, start, end))
    redacted_items: dict[str, list[str]] = {}

    for pii_type, matches in detections.items():
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


def redact_text(
    text: str,
    detections: dict[str, list[tuple[str, int, int]]] | None = None,
    ner_strength: int | None = None,
    enabled_types: set[str] | None = None,
) -> tuple[str, dict[str, list[str]]]:
    """
    Redact PII in text using NER ensemble approach if enabled.

    If detections are provided, uses them directly. Otherwise, detects PII first.
    If ner_strength=2 or 3, uses ensemble: detects with multiple NER models,
    then merges results for maximum coverage.

    Args:
        text: Original text to redact
        detections: Optional pre-detected PII. If None, will detect PII first.
        ner_strength: NER model strength:
                     - 1: en_core_web_lg only (fastest)
                     - 2: spaCy + transformer ensemble (balanced)
                     - 3: spaCy + transformer + GLiNER ensemble (best coverage, slower)
                     Defaults to 3 if not specified. Only used if detections is None.
        enabled_types: Optional set of PII types to detect. Only used if detections is None.

    Returns:
        Tuple of (redacted_text, redacted_items) where redacted_items maps
        PII type to list of redacted values
    """
    from ceil_dlp.detectors.presidio_adapter import detect_with_presidio_ensemble

    # If detections are provided, use them directly (backward compatibility)
    if detections is not None:
        return _apply_redaction_to_text(text, detections)

    # Otherwise, detect PII first using ensemble detection
    ner_strength_val = ner_strength if ner_strength is not None else 3
    detections = detect_with_presidio_ensemble(
        text, ner_strength=ner_strength_val, enabled_types=enabled_types
    )

    return _apply_redaction_to_text(text, detections)


def redact_image(
    image_data: bytes | str | Path | Image.Image,
    pii_types: list[str] | None = None,
    ocr_strength: int = 1,
    ner_strength: int = 1,
) -> bytes:
    """
    Redact PII in an image using ensemble approach for both OCR and NER.

    OCR Ensemble (sequential):
    1. Redact with docTR OCR (lighter model, good for complex documents)
    2. Redact again with Tesseract OCR on the docTR-redacted image
    3. Redact again with heavy docTR OCR (heavier model, maximum accuracy) on the result
    This catches PII that any single OCR engine might miss.

    NER Ensemble (if ner_strength=2):
    - First pass: Run all OCR passes with spaCy NER (strength 1)
    - Second pass: Run all OCR passes again with transformer NER (strength 2) on already-redacted image
    This catches names that either NER model might miss (e.g., "JANE MARIA" might be caught by spaCy but not transformer).

    Args:
        image_data: Image as bytes, file path (str), Path object, or PIL Image
        pii_types: Optional list of PII types to redact. If None, redacts all detected PII.
        ocr_strength: Number of OCR models to use (1=light docTR only, 2=light docTR+Tesseract, 3=all three).
                     Defaults to 3 if not specified.
        ner_strength: NER model strength:
                     - 1: en_core_web_lg only (fastest)
                     - 2: spaCy + transformer ensemble (balanced)
                     - 3: spaCy + transformer + GLiNER ensemble (best coverage, slower)
                     Defaults to 3 if not specified (uses full ensemble for best accuracy).

    Returns:
        Redacted image as bytes (same format as input)
    """
    if ner_strength not in (1, 2, 3):
        raise ValueError(
            f"ner_strength must be 1, 2, or 3, got {ner_strength}. "
            "Use 1 for en_core_web_lg, 2 for spaCy+transformer ensemble, "
            "or 3 for spaCy+transformer+GLiNER ensemble."
        )

    if ocr_strength not in (1, 2, 3):
        raise ValueError(
            f"ocr_strength must be 1, 2, or 3, got {ocr_strength}. "
            "Use 1 for light docTR only, 2 for light docTR+Tesseract, "
            "or 3 for all three including heavy docTR."
        )

    try:
        image: Image.Image = image_to_pil_image(image_data)
        original_format = image.format or "PNG"
    except Exception as e:
        logger.error(f"Error converting image to PIL Image: {e}", exc_info=True)
        raise ValueError(f"Invalid image_data type: {type(image_data)}") from e

    try:
        # Convert our PII type names to Presidio entity names
        # Create reverse mapping: pii_type -> list of Presidio entity names
        pii_type_to_entities = get_pii_type_to_entities()

        entities_to_redact: list[str] = []
        for pii_type in pii_types if pii_types else []:
            entities = pii_type_to_entities.get(pii_type)
            if entities is None:
                raise ValueError(f"PII type {pii_type} not found in mapping")
            entities_to_redact.extend(entities)

        # Ensemble approach: For each NER model, run all OCR passes
        # This catches PII that any single model or OCR engine might miss
        redacted_image_pil: Image.Image = image

        for ner_model in range(1, ner_strength + 1):
            for ocr_step in range(1, ocr_strength + 1):
                redacted_image_pil = _redact_with_ocr_engine(
                    redacted_image_pil,
                    ocr_type=ocr_step,
                    ner_strength=ner_model,
                    entities_to_redact=entities_to_redact,
                )

        final_redacted_image_pil: Image.Image = redacted_image_pil

        # Convert back to bytes
        output = io.BytesIO()
        # Preserve original format if available, otherwise use PNG
        save_format = original_format or "PNG"
        final_redacted_image_pil.save(output, format=save_format)
        return output.getvalue()

    except Exception as e:
        raise ValueError(f"Error redacting image: {e}") from e


def redact_pdf(
    pdf_data: bytes | str | Path,
    pii_types: list[str] | None = None,
    ocr_strength: int = 1,
    ner_strength: int = 1,
) -> bytes:
    """
    Redact PII in a PDF by overlaying black rectangles over detected PII areas.

    This function:
    1. Detects PII in the PDF (text and images)
    2. Renders each page to identify PII locations
    3. Overlays black rectangles to redact detected PII
    4. Returns the redacted PDF as bytes

    Args:
        pdf_data: PDF as bytes, file path (str), or Path object
        pii_types: Optional list of PII types to redact. If None, redacts all detected PII.
        ocr_strength: Number of OCR models to use (1=light docTR only, 2=light docTR+Tesseract, 3=all three).
                     Defaults to 3 if not specified.
        ner_strength: NER model strength (1=en_core_web_lg, 2=en_core_web_trf, 3=transformer-based).
                     Defaults to 1 if not specified.

    Returns:
        Redacted PDF as bytes
    """
    try:
        # Load PDF
        if isinstance(pdf_data, (str, Path)):
            pdf = pdfium.PdfDocument(pdf_data)
        elif isinstance(pdf_data, bytes):
            pdf = pdfium.PdfDocument(io.BytesIO(pdf_data))
        else:
            raise ValueError(f"Invalid pdf_data type: {type(pdf_data)}")

        # Detect PII in PDF
        enabled_types = set(pii_types) if pii_types else None
        detections = detect_pii_in_pdf(pdf_data, enabled_types=enabled_types)

        if not detections:
            # No PII detected, return original
            pdf.close()
            if isinstance(pdf_data, bytes):
                return pdf_data
            else:
                with open(pdf_data, "rb") as f:
                    return f.read()

        # NOTE(jadidbourbaki): Redaction approach is to: Render then Redact then Stitch
        # In other words, we render each page to an image,
        # then redact the PII in each rendered image,
        # then stitch the redacted images back together into a new PDF.
        # Trade-offs:
        # The good part is that it handles both text and image-based PII, works for scanned PDFs
        # The bad part is that it rasterizes PDF (loses text selectability, may increase file size)
        # and some PDF features may be lost (forms, annotations, etc.).

        redacted_pages: list[Image.Image] = []

        for page_num in range(len(pdf)):
            try:
                page = pdf[page_num]

                # Render page to image at high quality for redaction
                # Use higher scale for better quality (3x = ~216 DPI)
                bitmap = page.render(scale=3)
                pil_image = bitmap.to_pil()

                # Redact PII in the rendered page image using Presidio
                redacted_image_bytes = redact_image(
                    pil_image,
                    pii_types=pii_types,
                    ocr_strength=ocr_strength,
                    ner_strength=ner_strength,
                )
                redacted_image = Image.open(io.BytesIO(redacted_image_bytes))

                redacted_pages.append(redacted_image)

            except Exception as page_error:
                logger.warning(f"Error redacting PDF page {page_num}: {page_error}")
                # If redaction fails, try to render original page
                try:
                    bitmap = page.render(scale=3)
                    redacted_pages.append(bitmap.to_pil())
                except Exception:
                    # If rendering also fails, skip this page
                    logger.error(f"Could not process PDF page {page_num}, skipping")
                    continue

        pdf.close()

        if not redacted_pages:
            # No pages were successfully processed, return original
            logger.warning("No pages could be redacted, returning original PDF")
            if isinstance(pdf_data, bytes):
                return pdf_data
            else:
                with open(pdf_data, "rb") as f:
                    return f.read()

        # Create new PDF from redacted page images using PIL
        # PIL can directly create PDFs from images
        output_bytes = io.BytesIO()

        # Convert all images to RGB mode (PDF requires RGB, not RGBA)
        rgb_pages = []
        for img in redacted_pages:
            rgb_img = img.convert("RGB") if img.mode != "RGB" else img
            rgb_pages.append(rgb_img)

        # Save first image as PDF and append the rest
        if rgb_pages:
            rgb_pages[0].save(
                output_bytes,
                format="PDF",
                save_all=True,
                append_images=rgb_pages[1:] if len(rgb_pages) > 1 else [],
                resolution=216.0,  # Match our 3x scale rendering (~216 DPI)
            )

        return output_bytes.getvalue()

    except Exception as e:
        logger.error(f"Error redacting PDF: {e}", exc_info=True)

        # Return original PDF on error
        if isinstance(pdf_data, bytes):
            return pdf_data
        elif isinstance(pdf_data, (str, Path)):
            with open(pdf_data, "rb") as f:
                return f.read()
        else:
            raise ValueError(f"Invalid pdf_data type: {type(pdf_data)}") from e
