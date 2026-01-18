import io
from pathlib import Path
from typing import Any

from PIL import Image


def image_to_pil_image(image: Any) -> Image.Image:
    """Convert image to PIL Image.

    Args:
        image: Image as bytes, file path (str), Path object, or PIL Image

    Returns:
        PIL Image
    """
    if isinstance(image, Image.Image):
        return image
    elif isinstance(image, str | Path):
        return Image.open(image)
    elif isinstance(image, bytes):
        return Image.open(io.BytesIO(image))
    else:
        raise ValueError(f"Unsupported image type: {type(image)}")
