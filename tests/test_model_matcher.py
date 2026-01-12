"""Tests for model matching utility."""

from ceil_dlp.detectors.model_matcher import matches_model


def test_matches_model_exact_match():
    """Test exact model name matching."""
    assert matches_model("openai/gpt-4", "openai/gpt-4") is True
    assert matches_model("openai/gpt-4", "openai/gpt-3.5") is False
    assert matches_model("anthropic/claude", "anthropic/claude") is True


def test_matches_model_regex_pattern():
    """Test regex pattern matching."""
    # Wildcard pattern
    assert matches_model("openai/gpt-4", "openai/.*") is True
    assert matches_model("openai/gpt-3.5", "openai/.*") is True
    assert matches_model("anthropic/claude", "openai/.*") is False

    # Prefix pattern
    assert matches_model("self-hosted/llama2", "self-hosted/.*") is True
    assert matches_model("self-hosted/llama3", "self-hosted/.*") is True
    assert matches_model("local/ollama", "local/.*") is True


def test_matches_model_regex_special_chars():
    """Test that regex special characters are detected."""
    # Pattern with regex special chars should be treated as regex
    assert matches_model("openai/gpt-4", "openai/gpt-.*") is True
    assert matches_model("openai/gpt-3.5", "openai/gpt-.*") is True

    # Pattern with brackets
    assert matches_model("model-v1", "model-[a-z0-9]+") is True
    assert matches_model("model-V1", "model-[a-z0-9]+") is False  # V is uppercase


def test_matches_model_invalid_regex():
    """Test that invalid regex returns False."""
    # If pattern contains regex special chars, we treat it as regex
    assert matches_model("openai/gpt-4", "[invalid") is False  # Invalid regex
    # Pattern with regex chars that's invalid should return False
    assert (
        matches_model("[invalid", "[invalid") is False
    )  # Contains [ so treated as regex, invalid regex returns False
    # Pattern without regex chars uses exact match
    assert (
        matches_model("simple-model", "simple-model") is True
    )  # No regex chars, exact match works


def test_matches_model_no_regex_chars():
    """Test that patterns without regex chars use exact match."""
    # No regex special chars - should be exact match
    assert matches_model("openai/gpt-4", "openai-gpt-4") is False
    assert matches_model("simple-model", "simple-model") is True
    assert matches_model("simple-model", "different-model") is False
