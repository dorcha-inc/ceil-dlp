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
