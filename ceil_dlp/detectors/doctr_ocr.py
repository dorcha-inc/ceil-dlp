"""docTR OCR engine adapter for Presidio Image Redactor."""

import io
import logging
from functools import lru_cache
from typing import Any

from doctr.io import DocumentFile
from doctr.models import ocr_predictor
from PIL import Image
from presidio_image_redactor import OCR

from ceil_dlp.utils import image_to_pil_image

logger = logging.getLogger(__name__)


class DocTROCREngine(OCR):
    """OCR engine using docTR (Document Text Recognition) for better accuracy on complex documents."""

    def __init__(
        self,
        det_arch: str = "db_mobilenet_v3_large",
        reco_arch: str = "crnn_mobilenet_v3_small",
        model_name: str | None = None,
    ):
        """Initialize docTR OCR predictor with specified model architectures.

        Args:
            det_arch: Detection architecture (e.g., "db_mobilenet_v3_large", "db_resnet50", "fast_base")
            reco_arch: Recognition architecture (e.g., "crnn_mobilenet_v3_small", "vitstr_base", "parseq")
            model_name: Optional name for logging (defaults to "{det_arch} + {reco_arch}")
        """
        self._model: Any | None = None
        self.det_arch = det_arch
        self.reco_arch = reco_arch
        self.model_name = model_name or f"{det_arch} + {reco_arch}"

    @property
    def model(self):
        """Lazy-load the OCR model to avoid expensive initialization at import time."""
        if self._model is None:
            logger.info(
                f"initializing docTR OCR model ({self.model_name}) (this may take a moment on first use)..."
            )
            self._model = ocr_predictor(
                det_arch=self.det_arch,
                reco_arch=self.reco_arch,
                pretrained=True,
            )
            logger.info(f"docTR OCR model ({self.model_name}) initialized successfully")
        return self._model

    def perform_ocr(self, image: object, **_kwargs) -> dict:
        """Perform OCR on a given image using docTR.

        Converts docTR's nested structure (Pages → Blocks → Lines → Words) to
        Tesseract-compatible flat dictionary format expected by Presidio.

        :param image: PIL Image, numpy array, or file path (str) to be processed
        :param _kwargs: Additional parameters (currently unused, for API compatibility)

        :return: Dictionary in Tesseract format with keys: level, page_num, block_num,
                 par_num, line_num, word_num, left, top, width, height, conf, text
        """
        try:
            # Convert input to PIL Image if needed
            pil_image: Image.Image = image_to_pil_image(image)

            # Convert PIL Image to bytes for docTR
            # DocumentFile.from_images expects bytes, str (file path), or Path
            img_bytes = io.BytesIO()
            pil_image.save(img_bytes, format="PNG")
            img_bytes.seek(0)

            # Create DocumentFile from bytes
            # docTR expects a list of images (one per page)
            doc = DocumentFile.from_images([img_bytes.getvalue()])

            # Run OCR
            result = self.model(doc)

            # Get image dimensions for coordinate conversion
            img_width, img_height = pil_image.size

            # Convert docTR's nested structure to Tesseract-compatible flat format
            return self._convert_doctr_to_tesseract_format(result, img_width, img_height)

        except Exception as e:
            logger.error(f"Error performing OCR with docTR: {e}", exc_info=True)
            # Return empty structure on error
            return {
                "level": [],
                "page_num": [],
                "block_num": [],
                "par_num": [],
                "line_num": [],
                "word_num": [],
                "left": [],
                "top": [],
                "width": [],
                "height": [],
                "conf": [],
                "text": [],
            }

    def _convert_doctr_to_tesseract_format(
        self, doctr_result, img_width: int, img_height: int
    ) -> dict:
        """Convert docTR's nested document structure to Tesseract's flat dictionary format.

        docTR structure: Document → Pages → Blocks → Lines → Words
        Tesseract format: flat lists with hierarchy encoded in level/page_num/block_num/etc.

        :param doctr_result: docTR Document object
        :param img_width: Image width in pixels
        :param img_height: Image height in pixels

        :return: Dictionary with Tesseract-compatible structure
        """
        # Initialize lists for Tesseract format
        levels = []
        page_nums = []
        block_nums = []
        par_nums = []
        line_nums = []
        word_nums = []
        lefts = []
        tops = []
        widths = []
        heights = []
        confs = []
        texts = []

        # Process each page
        for page_idx, page in enumerate(doctr_result.pages, start=1):
            page_num = page_idx

            # Add page-level entry (level 1)
            levels.append(1)
            page_nums.append(page_num)
            block_nums.append(0)
            par_nums.append(0)
            line_nums.append(0)
            word_nums.append(0)
            lefts.append(0)
            tops.append(0)
            widths.append(img_width)
            heights.append(img_height)
            confs.append(-1)  # -1 for non-word levels
            texts.append("")

            # Process blocks (level 2)
            for block_idx, block in enumerate(page.blocks, start=1):
                block_num = block_idx

                # Get block bounding box (convert from relative 0-1 to absolute pixels)
                block_geom = block.geometry
                block_xmin = int(block_geom[0][0] * img_width)
                block_ymin = int(block_geom[0][1] * img_height)
                block_xmax = int(block_geom[1][0] * img_width)
                block_ymax = int(block_geom[1][1] * img_height)
                block_width = block_xmax - block_xmin
                block_height = block_ymax - block_ymin

                # Add block-level entry (level 2)
                levels.append(2)
                page_nums.append(page_num)
                block_nums.append(block_num)
                par_nums.append(0)
                line_nums.append(0)
                word_nums.append(0)
                lefts.append(block_xmin)
                tops.append(block_ymin)
                widths.append(block_width)
                heights.append(block_height)
                confs.append(-1)
                texts.append("")

                # Process lines (level 4, skip paragraph level 3 for simplicity)
                for line_idx, line in enumerate(block.lines, start=1):
                    line_num = line_idx

                    # Get line bounding box
                    line_geom = line.geometry
                    line_xmin = int(line_geom[0][0] * img_width)
                    line_ymin = int(line_geom[0][1] * img_height)
                    line_xmax = int(line_geom[1][0] * img_width)
                    line_ymax = int(line_geom[1][1] * img_height)
                    line_width = line_xmax - line_xmin
                    line_height = line_ymax - line_ymin

                    # Add line-level entry (level 4)
                    levels.append(4)
                    page_nums.append(page_num)
                    block_nums.append(block_num)
                    par_nums.append(0)
                    line_nums.append(line_num)
                    word_nums.append(0)
                    lefts.append(line_xmin)
                    tops.append(line_ymin)
                    widths.append(line_width)
                    heights.append(line_height)
                    confs.append(-1)
                    texts.append("")

                    # Process words (level 5)
                    for word_idx, word in enumerate(line.words, start=1):
                        word_num = word_idx

                        # Get word bounding box (convert from relative to absolute)
                        word_geom = word.geometry
                        word_xmin = int(word_geom[0][0] * img_width)
                        word_ymin = int(word_geom[0][1] * img_height)
                        word_xmax = int(word_geom[1][0] * img_width)
                        word_ymax = int(word_geom[1][1] * img_height)
                        word_width = word_xmax - word_xmin
                        word_height = word_ymax - word_ymin

                        # Get word text and confidence
                        word_text = word.value
                        # docTR confidence is typically 0-1, convert to 0-100 scale for Tesseract compatibility
                        word_conf = int(word.confidence * 100) if hasattr(word, "confidence") else 0

                        # Skip empty words to avoid position mismatches in text reconstruction
                        # Empty strings in OCR output cause Presidio's position calculations to be off
                        if not word_text or not word_text.strip():
                            continue

                        # Add word-level entry (level 5)
                        levels.append(5)
                        page_nums.append(page_num)
                        block_nums.append(block_num)
                        par_nums.append(0)
                        line_nums.append(line_num)
                        word_nums.append(word_num)
                        lefts.append(word_xmin)
                        tops.append(word_ymin)
                        widths.append(word_width)
                        heights.append(word_height)
                        confs.append(word_conf)
                        texts.append(word_text)

        # Filter to only word-level entries (level 5) to match Tesseract format
        # Presidio's get_text_from_ocr_dict includes ALL levels, which causes position
        # mismatches when non-word entries have empty strings. By filtering to only
        # word-level entries, we ensure text reconstruction matches analyzer positions.
        word_indices = [i for i, level in enumerate(levels) if level == 5]

        return {
            "level": [levels[i] for i in word_indices],
            "page_num": [page_nums[i] for i in word_indices],
            "block_num": [block_nums[i] for i in word_indices],
            "par_num": [par_nums[i] for i in word_indices],
            "line_num": [line_nums[i] for i in word_indices],
            "word_num": [word_nums[i] for i in word_indices],
            "left": [lefts[i] for i in word_indices],
            "top": [tops[i] for i in word_indices],
            "width": [widths[i] for i in word_indices],
            "height": [heights[i] for i in word_indices],
            "conf": [confs[i] for i in word_indices],
            "text": [texts[i] for i in word_indices],
        }


@lru_cache(maxsize=1)
def get_doctr_ocr_engine() -> DocTROCREngine:
    """Get cached docTR OCR engine instance (lighter model).

    Uses db_mobilenet_v3_large + crnn_mobilenet_v3_small for good speed/accuracy balance.
    """
    return DocTROCREngine(
        det_arch="db_mobilenet_v3_large",
        reco_arch="crnn_mobilenet_v3_small",
        model_name="db_mobilenet_v3_large + crnn_mobilenet_v3_small (light)",
    )


@lru_cache(maxsize=1)
def get_doctr_heavy_ocr_engine() -> DocTROCREngine:
    """Get cached heavy docTR OCR engine instance (heavier, more accurate model).

    Uses fast_base (different detection architecture) + parseq (highly accurate recognition)
    for maximum accuracy in ensemble approach. This provides architectural diversity from
    the light model (DBNet vs FAST) and better name detection with PARSeq.
    """
    return DocTROCREngine(
        det_arch="fast_base",
        reco_arch="parseq",
        model_name="fast_base + parseq (heavy)",
    )
