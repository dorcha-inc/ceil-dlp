"""Redaction and masking logic."""

import io
import logging
from pathlib import Path

import pypdfium2 as pdfium
from PIL import Image
from presidio_image_redactor import ImageAnalyzerEngine, ImageRedactorEngine

from ceil_dlp.detectors.pdf_detector import detect_pii_in_pdf
from ceil_dlp.detectors.presidio_adapter import get_analyzer

logger = logging.getLogger(__name__)


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


def redact_image(
    image_data: bytes | str | Path | Image.Image, pii_types: list[str] | None = None
) -> bytes:
    """
    Redact PII in an image using Presidio Image Redactor.

    Args:
        image_data: Image as bytes, file path (str), Path object, or PIL Image
        pii_types: Optional list of PII types to redact. If None, redacts all detected PII.

    Returns:
        Redacted image as bytes (same format as input)
    """
    try:
        # Load image
        image: Image.Image
        if isinstance(image_data, Image.Image):
            # Already a PIL Image, use it directly
            image = image_data
            original_format = image.format
        elif isinstance(image_data, (str, Path)):
            image = Image.open(image_data)
            original_format = image.format
        elif isinstance(image_data, bytes):
            image = Image.open(io.BytesIO(image_data))
            original_format = image.format
        else:
            raise ValueError(f"Invalid image_data type: {type(image_data)}")

        # Use Presidio Image Redactor with our configured analyzer
        # All custom secret recognizers are already registered in the analyzer,
        # so we don't need to pass them as ad_hoc_recognizers
        analyzer = get_analyzer()
        image_analyzer = ImageAnalyzerEngine(analyzer_engine=analyzer)
        engine = ImageRedactorEngine(image_analyzer_engine=image_analyzer)

        # Redact the image (handles both Presidio PII and custom secrets)
        # The redact method returns a redacted PIL Image
        # fill parameter expects RGB tuple or int (0-255 for grayscale)
        # Note: pii_types parameter is ignored - Presidio will detect all types
        # and filtering would need to happen at the detection stage, not redaction
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
        if isinstance(image_data, Image.Image):
            # Convert PIL Image to bytes
            output = io.BytesIO()
            original_format = image_data.format or "PNG"
            image_data.save(output, format=original_format)
            return output.getvalue()
        elif isinstance(image_data, bytes):
            return image_data
        elif isinstance(image_data, (str, Path)):
            with open(image_data, "rb") as f:
                return f.read()
        else:
            raise ValueError(f"Invalid image_data type: {type(image_data)}") from e


def redact_pdf(pdf_data: bytes | str | Path, pii_types: list[str] | None = None) -> bytes:
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
                redacted_image_bytes = redact_image(pil_image, pii_types=pii_types)
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
