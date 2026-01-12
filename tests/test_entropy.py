"""Tests for entropy-based detection."""

from ceil_dlp.detectors.entropy import (
    calculate_shannon_entropy,
    detect_high_entropy_tokens,
)


def test_calculate_shannon_entropy_low():
    """Test entropy calculation for low-entropy text."""
    text = "aaaa"
    entropy = calculate_shannon_entropy(text)
    assert entropy < 2.0  # Low entropy (repetitive)


def test_calculate_shannon_entropy_high():
    """Test entropy calculation for high-entropy text."""
    # High-entropy string (random-looking)
    text = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
    entropy = calculate_shannon_entropy(text)
    assert entropy > 4.0  # High entropy


def test_calculate_shannon_entropy_empty():
    """Test entropy calculation for empty string."""
    entropy = calculate_shannon_entropy("")
    assert entropy == 0.0


def test_detect_high_entropy_tokens():
    """Test high-entropy token detection."""
    # Text with high-entropy token (looks like a secret)
    text = "My secret key is a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
    matches = detect_high_entropy_tokens(text, min_entropy=4.0, min_length=20)
    assert len(matches) > 0


def test_detect_high_entropy_tokens_no_match():
    """Test that low-entropy text is not detected."""
    # Low-entropy text (repetitive)
    text = "This is normal text with no secrets aaaa bbbb cccc"
    matches = detect_high_entropy_tokens(text, min_entropy=4.5, min_length=20)
    assert len(matches) == 0


def test_detect_high_entropy_tokens_min_length():
    """Test that tokens below minimum length are not detected."""
    text = "Short secret: a1b2c3"  # Too short
    matches = detect_high_entropy_tokens(text, min_entropy=3.0, min_length=20)
    assert len(matches) == 0


def test_detect_high_entropy_tokens_position_tracking():
    """Test that entropy matches include correct positions."""
    text = "Start a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6 end"
    matches = detect_high_entropy_tokens(text, min_entropy=4.0, min_length=20)
    assert len(matches) > 0
    match = matches[0]
    matched_text, start, end = match
    assert text[start:end] == matched_text
    assert matched_text in text
