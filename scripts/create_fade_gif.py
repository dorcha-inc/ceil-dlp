#!/usr/bin/env python3
"""Create fade animation GIFs from original to redacted images.

This script creates animated GIFs that fade from the original image to the redacted version,
useful for README demonstrations.
"""

import argparse
import sys
from pathlib import Path

from PIL import Image


def create_fade_gif(
    original_path: Path,
    redacted_path: Path,
    output_path: Path,
    frames: int = 15,
    duration: int = 100,
    pause_frames: int = 5,
    max_width: int = 400,
    use_palette: bool = False,
    palette_colors: int = 128,
) -> None:
    """Create a fade animation GIF from original to redacted image.

    Args:
        original_path: Path to the original image
        redacted_path: Path to the redacted image
        output_path: Path where the GIF will be saved
        frames: Number of fade frames (default: 15)
        duration: Duration of each frame in milliseconds (default: 100)
        pause_frames: Number of frames to pause at each end (default: 5)
        max_width: Maximum width in pixels (resizes if larger, default: 800)
        use_palette: Whether to use palette mode for compression (default: False)
        palette_colors: Number of colors in palette if use_palette is True (default: 128)
    """
    # Load images
    original = Image.open(original_path).convert("RGB")
    redacted = Image.open(redacted_path).convert("RGB")

    # Resize if image is larger than max_width
    if max_width and original.size[0] > max_width:
        ratio = max_width / original.size[0]
        new_height = int(original.size[1] * ratio)
        new_size = (max_width, new_height)
        print(f"Resizing images to {new_size} (max_width={max_width})", file=sys.stderr)
        original = original.resize(new_size, Image.Resampling.LANCZOS)
        redacted = redacted.resize(new_size, Image.Resampling.LANCZOS)

    # Ensure both images are the same size
    if original.size != redacted.size:
        print(
            "Warning: Images have different sizes. Resizing redacted to match original.",
            file=sys.stderr,
        )
        redacted = redacted.resize(original.size, Image.Resampling.LANCZOS)

    # Create frames for the animation
    animation_frames = []

    # Pause at original (show original for a moment)
    for _ in range(pause_frames):
        animation_frames.append(original.copy())

    # Fade from original to redacted
    for i in range(frames):
        alpha = i / frames
        # Blend images
        blended = Image.blend(original, redacted, alpha)
        animation_frames.append(blended)

    # Pause at redacted (show redacted for a moment)
    for _ in range(pause_frames):
        animation_frames.append(redacted.copy())

    # Fade back from redacted to original (optional - creates a loop effect)
    for i in range(frames):
        alpha = (frames - i) / frames
        blended = Image.blend(original, redacted, alpha)
        animation_frames.append(blended)

    # Save as animated GIF with optimization
    if use_palette:
        # Use palette mode for better compression (smaller file size)
        # Convert frames to palette mode for smaller file size
        palette_frames = []
        for frame in animation_frames:
            # Convert to palette mode with reduced colors for better compression
            # Fewer colors = smaller file size (default: 128, can go as low as 16-32)
            palette_frame = frame.convert(
                "P", palette=Image.Palette.ADAPTIVE, colors=palette_colors
            )
            palette_frames.append(palette_frame)

        save_frames = palette_frames
    else:
        # Keep RGB mode for better quality (larger file size)
        save_frames = animation_frames

    save_frames[0].save(
        output_path,
        save_all=True,
        append_images=save_frames[1:],
        duration=duration,
        loop=0,  # Loop forever
        optimize=True,  # Enable optimization
    )

    print(f"Created fade GIF: {output_path}")
    print(f"  Frames: {len(animation_frames)}")
    print(f"  Duration per frame: {duration}ms")
    print(f"  Total animation time: ~{len(animation_frames) * duration / 1000:.1f}s")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Create fade animation GIFs from original to redacted images"
    )
    parser.add_argument(
        "original",
        type=Path,
        help="Path to the original image",
    )
    parser.add_argument(
        "redacted",
        type=Path,
        help="Path to the redacted image",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output GIF path (default: <original_name>_fade.gif)",
    )
    parser.add_argument(
        "-f",
        "--frames",
        type=int,
        default=15,
        help="Number of fade frames (default: 15)",
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=100,
        help="Duration of each frame in milliseconds (default: 100)",
    )
    parser.add_argument(
        "--pause",
        type=int,
        default=5,
        help="Number of frames to pause at each end (default: 5)",
    )
    parser.add_argument(
        "-w",
        "--max-width",
        type=int,
        default=800,
        help="Maximum width in pixels (resizes if larger, default: 800)",
    )
    parser.add_argument(
        "--palette",
        action="store_true",
        help="Use palette mode for compression (smaller file, lower quality)",
    )
    parser.add_argument(
        "-c",
        "--colors",
        type=int,
        default=128,
        help="Number of colors in palette if --palette is used (lower = smaller file, default: 128, min: 16)",
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.original.exists():
        print(f"Error: Original image not found: {args.original}", file=sys.stderr)
        sys.exit(1)

    if not args.redacted.exists():
        print(f"Error: Redacted image not found: {args.redacted}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    output_path = args.output or args.original.parent / f"{args.original.stem}_fade.gif"

    # Validate colors argument
    if args.colors < 16:
        print("Warning: Colors must be at least 16. Using 16.", file=sys.stderr)
        args.colors = 16
    elif args.colors > 256:
        print("Warning: Colors cannot exceed 256. Using 256.", file=sys.stderr)
        args.colors = 256

    # Create the fade GIF
    create_fade_gif(
        args.original,
        args.redacted,
        output_path,
        frames=args.frames,
        duration=args.duration,
        pause_frames=args.pause,
        max_width=args.max_width,
        use_palette=args.palette,
        palette_colors=args.colors,
    )


if __name__ == "__main__":
    main()
