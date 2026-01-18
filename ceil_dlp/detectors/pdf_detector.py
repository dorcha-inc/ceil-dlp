"""PDF PII detection using pypdfium2 for text/image extraction."""

import io
import logging
from pathlib import Path

import pypdfium2 as pdfium

from ceil_dlp.detectors.image_detector import detect_pii_in_image
from ceil_dlp.detectors.patterns import PatternMatch
from ceil_dlp.detectors.text_detector import detect_pii_in_text

logger = logging.getLogger(__name__)


def detect_pii_in_pdf(
    pdf_data: bytes | str | Path, enabled_types: set[str] | None = None
) -> dict[str, list[PatternMatch]]:
    """
    Detect PII in a PDF by extracting text and images, then running detection on both.

    Uses pypdfium2 to:
    1. Extract text from PDF pages (for text-based PDFs)
    2. Render pages to images for OCR-based detection (for scanned PDFs and image-based content)
    3. Run PII detection on all extracted content

    Args:
        pdf_data: PDF as bytes, file path (str), or Path object
        enabled_types: Optional set of PII types to detect. If None, detects all types.

    Returns:
        Dictionary mapping PII type to list of matches (same format as text detection).
        Returns empty dict if PDF processing fails.
    """
    try:
        # Load PDF
        if isinstance(pdf_data, (str, Path)):
            pdf = pdfium.PdfDocument(pdf_data)
        elif isinstance(pdf_data, bytes):
            pdf = pdfium.PdfDocument(io.BytesIO(pdf_data))
        else:
            logger.error(f"Invalid pdf_data type: {type(pdf_data)}")
            return {}

        results: dict[str, list[PatternMatch]] = {}

        # Process each page
        for page_num in range(len(pdf)):
            try:
                page = pdf[page_num]

                # First, extract text from page
                textpage = page.get_textpage()
                page_text = textpage.get_text_bounded()
                if page_text and page_text.strip():
                    # Detect PII in extracted text
                    text_detections = detect_pii_in_text(page_text, enabled_types=enabled_types)
                    # Merge results (use page offset to track positions if needed)
                    for pii_type, matches in text_detections.items():
                        if pii_type not in results:
                            results[pii_type] = []
                        # For PDFs, we track that these came from text extraction
                        # Position tracking is approximate since we're combining pages
                        results[pii_type].extend(matches)

                # Second, render page to image for OCR-based detection (handles scanned PDFs)
                try:
                    # Render page at reasonable DPI for OCR
                    bitmap = page.render(scale=2)  # 2x scale = ~144 DPI
                    pil_image = bitmap.to_pil()

                    # Detect PII in rendered page image
                    image_detections = detect_pii_in_image(pil_image, enabled_types=enabled_types)
                    # Merge image detection results with text detection results
                    for pii_type, matches in image_detections.items():
                        if pii_type not in results:
                            results[pii_type] = []
                        # Mark as detected in PDF image
                        pdf_image_matches = [
                            (f"[{pii_type}_detected_in_pdf_page_{page_num}]", start, end)
                            for _text, start, end in matches
                        ]
                        results[pii_type].extend(pdf_image_matches)

                except Exception as render_error:
                    logger.debug(f"Could not render page {page_num} to image: {render_error}")

            except Exception as page_error:
                logger.warning(f"Error processing PDF page {page_num}: {page_error}")
                continue

        pdf.close()
        return results

    except Exception as e:
        logger.error(f"Error detecting PII in PDF: {e}", exc_info=True)
        return {}
