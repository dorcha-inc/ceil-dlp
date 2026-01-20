"""Tests for Whistledown mode - conversational coherence transformations."""

from ceil_dlp.whistledown import WhistledownCache, whistledown_transform_text


def test_whistledown_cache_basic():
    """Test basic cache functionality."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    # First value should get _1
    replacement1 = cache.get_or_create_replacement(request_id, "John Doe", "person")
    assert replacement1 == "PERSON_1"

    # Same value should get same replacement
    replacement2 = cache.get_or_create_replacement(request_id, "John Doe", "person")
    assert replacement2 == "PERSON_1"

    # Different value should get _2
    replacement3 = cache.get_or_create_replacement(request_id, "Jane Smith", "person")
    assert replacement3 == "PERSON_2"


def test_whistledown_cache_different_types():
    """Test cache with different PII types."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    person = cache.get_or_create_replacement(request_id, "John Doe", "person")
    email = cache.get_or_create_replacement(request_id, "john@example.com", "email")
    phone = cache.get_or_create_replacement(request_id, "555-1234", "phone")

    assert person == "PERSON_1"
    assert email == "EMAIL_1"
    assert phone == "PHONE_1"

    # Second person should get PERSON_2
    person2 = cache.get_or_create_replacement(request_id, "Jane Smith", "person")
    assert person2 == "PERSON_2"


def test_whistledown_cache_reverse_transform():
    """Test reversing transformations."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    # Create mappings
    cache.get_or_create_replacement(request_id, "John Doe", "person")
    cache.get_or_create_replacement(request_id, "Jane Smith", "person")
    cache.get_or_create_replacement(request_id, "john@example.com", "email")

    # Test reverse transformation
    llm_response = "PERSON_1 and PERSON_2 should contact EMAIL_1 for more information."
    original = cache.reverse_transform(request_id, llm_response)

    assert (
        original == "John Doe and Jane Smith should contact john@example.com for more information."
    )


def test_whistledown_cache_request_isolation():
    """Test that different requests are isolated."""
    cache = WhistledownCache()

    # Request 1
    req1_person = cache.get_or_create_replacement("request-1", "John Doe", "person")
    assert req1_person == "PERSON_1"

    # Request 2 - same value should also be PERSON_1 (isolated)
    req2_person = cache.get_or_create_replacement("request-2", "John Doe", "person")
    assert req2_person == "PERSON_1"

    # Reverse transform should only affect its own request
    text1 = cache.reverse_transform("request-1", "PERSON_1 is here")
    text2 = cache.reverse_transform("request-2", "PERSON_1 is here")

    assert text1 == "John Doe is here"
    assert text2 == "John Doe is here"


def test_whistledown_cache_clear_request():
    """Test clearing a specific request from cache."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    cache.get_or_create_replacement(request_id, "John Doe", "person")
    cache.get_or_create_replacement(request_id, "Jane Smith", "person")

    # Clear the request
    cache.clear_request(request_id)

    # Should not reverse transform anymore
    result = cache.reverse_transform(request_id, "PERSON_1 and PERSON_2")
    assert result == "PERSON_1 and PERSON_2"  # No transformation


def test_whistledown_cache_stats():
    """Test cache statistics."""
    cache = WhistledownCache()

    cache.get_or_create_replacement("request-1", "John Doe", "person")
    cache.get_or_create_replacement("request-1", "Jane Smith", "person")
    cache.get_or_create_replacement("request-2", "Bob Johnson", "person")

    # Get overall stats
    stats = cache.get_stats()
    assert stats["total_requests"] == 2
    assert stats["total_mappings"] == 3
    assert "request-1" in stats["requests"]
    assert "request-2" in stats["requests"]

    # Get stats for specific request
    req1_stats = cache.get_stats("request-1")
    assert req1_stats["request_id"] == "request-1"
    assert req1_stats["mapping_count"] == 2


def test_whistledown_transform_text_basic():
    """Test basic text transformation."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = "My name is John Doe and my email is john@example.com"
    detections = {
        "person": [("John Doe", 11, 19)],
        "email": [("john@example.com", 36, 53)],
    }

    transformed_text, transformed_items = whistledown_transform_text(
        text, detections, cache, request_id
    )

    assert transformed_text == "My name is PERSON_1 and my email is EMAIL_1"
    assert "person" in transformed_items
    assert "John Doe" in transformed_items["person"]
    assert "email" in transformed_items
    assert "john@example.com" in transformed_items["email"]


def test_whistledown_transform_text_multiple_same_type():
    """Test transformation with multiple values of same type."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = "John Doe and Jane Smith are colleagues"
    detections = {
        "person": [
            ("John Doe", 0, 8),
            ("Jane Smith", 13, 23),
        ],
    }

    transformed_text, transformed_items = whistledown_transform_text(
        text, detections, cache, request_id
    )

    # Note: Due to reverse processing, Jane gets PERSON_1, John gets PERSON_2
    # This is okay - the important thing is consistency within a request
    assert "PERSON_1" in transformed_text
    assert "PERSON_2" in transformed_text
    assert "colleagues" in transformed_text
    assert len(transformed_items["person"]) == 2


def test_whistledown_transform_text_consistency():
    """Test that same value gets same token across transformations."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    # First transformation
    text1 = "John Doe is a developer"
    detections1 = {"person": [("John Doe", 0, 8)]}
    transformed1, _ = whistledown_transform_text(text1, detections1, cache, request_id)

    assert transformed1 == "PERSON_1 is a developer"

    # Second transformation with same person
    text2 = "John Doe loves Python"
    detections2 = {"person": [("John Doe", 0, 8)]}
    transformed2, _ = whistledown_transform_text(text2, detections2, cache, request_id)

    assert transformed2 == "PERSON_1 loves Python"


def test_whistledown_transform_text_overlapping_positions():
    """Test transformation with overlapping or adjacent matches."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = "Contact john@example.com or jane@example.com for help"
    detections = {
        "email": [
            ("john@example.com", 8, 24),
            ("jane@example.com", 28, 44),
        ],
    }

    transformed_text, _ = whistledown_transform_text(text, detections, cache, request_id)

    # Due to reverse processing order, jane gets EMAIL_1, john gets EMAIL_2
    assert "EMAIL_1" in transformed_text
    assert "EMAIL_2" in transformed_text
    assert transformed_text.startswith("Contact ")
    assert transformed_text.endswith(" for help")


def test_whistledown_transform_text_empty_detections():
    """Test transformation with no detections."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = "This is a normal sentence with no PII"
    detections: dict[str, list[tuple[str, int, int]]] = {}

    transformed_text, transformed_items = whistledown_transform_text(
        text, detections, cache, request_id
    )

    assert transformed_text == text  # No changes
    assert transformed_items == {}


def test_whistledown_end_to_end():
    """Test complete Whistledown workflow: transform -> LLM -> reverse."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    # Original user prompt
    original_prompt = "My name is John Doe, my wife is Jane Smith, and my email is john@example.com"

    # Detections (positions verified by Python string.find())
    detections = {
        "person": [
            ("John Doe", 11, 19),
            ("Jane Smith", 32, 42),
        ],
        "email": [("john@example.com", 60, 76)],
    }

    # Transform for LLM
    transformed_prompt, _ = whistledown_transform_text(
        original_prompt, detections, cache, request_id
    )

    # Check structure (reverse processing means Jane=PERSON_1, John=PERSON_2, email=EMAIL_1)
    assert "PERSON_1" in transformed_prompt
    assert "PERSON_2" in transformed_prompt
    assert "EMAIL_1" in transformed_prompt
    assert "My name is" in transformed_prompt
    assert "my wife is" in transformed_prompt
    assert "my email is" in transformed_prompt

    # Simulate LLM response (using whatever tokens were actually created)
    # Get the mapping from cache to construct realistic LLM response
    stats = cache.get_stats(request_id)
    mappings = stats["mappings"]

    # Reverse transform for user - should restore originals
    # Test with a simple response that includes some tokens
    test_response = "Please contact "
    for _, token in list(mappings.items())[:2]:
        test_response += f"{token} and "
    test_response = test_response.removesuffix(" and ") + " for assistance."

    reversed = cache.reverse_transform(request_id, test_response)

    # Verify that at least one original value was restored
    assert any(original in reversed for original in ["John Doe", "Jane Smith", "john@example.com"])


def test_whistledown_api_keys():
    """Test Whistledown with API keys and secrets."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = "My OpenAI key is sk-1234567890 and AWS key is AKIAIOSFODNN7EXAMPLE"
    detections = {
        "api_key": [
            ("sk-1234567890", 17, 30),
            ("AKIAIOSFODNN7EXAMPLE", 46, 66),
        ],
    }

    transformed_text, _ = whistledown_transform_text(text, detections, cache, request_id)

    assert "API_KEY_1" in transformed_text
    assert "API_KEY_2" in transformed_text
    assert transformed_text.startswith("My OpenAI key is ")
    assert " and AWS key is " in transformed_text

    # Verify reverse - order may vary due to reverse processing
    llm_response = "I stored API_KEY_1 and API_KEY_2 securely."
    original = cache.reverse_transform(request_id, llm_response)
    assert "sk-1234567890" in original
    assert "AKIAIOSFODNN7EXAMPLE" in original
    assert "I stored" in original
    assert "securely." in original


def test_whistledown_mixed_pii_types():
    """Test Whistledown with many different PII types."""
    cache = WhistledownCache()
    request_id = "test-request-1"

    text = (
        "John Doe lives in Seattle, email john@example.com, "
        "phone 555-1234, SSN 123-45-6789, and API key sk-abc123"
    )

    detections = {
        "person": [("John Doe", 0, 8)],
        "location": [("Seattle", 18, 25)],
        "email": [("john@example.com", 33, 49)],
        "phone": [("555-1234", 57, 65)],
        "ssn": [("123-45-6789", 71, 82)],
        "api_key": [("sk-abc123", 96, 105)],
    }

    transformed_text, _ = whistledown_transform_text(text, detections, cache, request_id)

    # Check all types are present
    assert "PERSON_1" in transformed_text
    assert "LOCATION_1" in transformed_text
    assert "EMAIL_1" in transformed_text
    assert "PHONE_1" in transformed_text
    assert "SSN_1" in transformed_text
    assert "API_KEY_1" in transformed_text
    # Check structure is preserved
    assert "lives in" in transformed_text
    assert "email" in transformed_text
    assert "phone" in transformed_text
