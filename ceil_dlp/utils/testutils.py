import io

from PIL import Image, ImageDraw, ImageFont


def create_image_with_text(text: str, width: int = 800, height: int = 200) -> bytes:
    """Helper to create an image with text for testing OCR."""
    # Create a white background image
    img = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(img)

    font = ImageFont.load_default()

    # Draw text in black on white background for good contrast
    # Position text in the center
    bbox = draw.textbbox((0, 0), text, font=font) if font else (0, 0, len(text) * 10, 20)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (width - text_width) // 2
    y = (height - text_height) // 2

    draw.text((x, y), text, fill="black", font=font)

    # Convert to bytes
    img_bytes = io.BytesIO()
    img.save(img_bytes, format="PNG")
    img_bytes.seek(0)
    return img_bytes.getvalue()


def create_pdf_with_text(text: str) -> bytes:
    """Helper to create a PDF with text for testing PDF detection and redaction.

    Uses PIL to create an image with text, then converts it to PDF format.
    This creates a real PDF that pypdfium2 can read and process.
    """
    # Create an image with text (same as create_image_with_text)
    img = Image.new("RGB", (800, 200), color="white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()

    # Position text in the center
    bbox = draw.textbbox((0, 0), text, font=font) if font else (0, 0, len(text) * 10, 20)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    x = (800 - text_width) // 2
    y = (200 - text_height) // 2

    draw.text((x, y), text, fill="black", font=font)

    # Convert image to PDF bytes
    pdf_bytes = io.BytesIO()
    img.save(pdf_bytes, format="PDF")
    pdf_bytes.seek(0)
    return pdf_bytes.getvalue()
