"""Tests for overlap removal utilities."""

from ceil_dlp.utils.overlaps import PatternMatch, remove_overlapping_matches


def test_empty_matches():
    """Test with empty list."""
    result = remove_overlapping_matches([])
    assert result == []


def test_no_overlaps():
    """Test with non-overlapping matches."""
    matches: list[PatternMatch] = [
        ("text1", 0, 5),
        ("text2", 10, 15),
        ("text3", 20, 25),
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 3
    assert set(result) == set(matches)


def test_simple_overlap_longer_wins():
    """Test that longer match wins when no priority_map provided."""
    matches: list[PatternMatch] = [
        ("short", 0, 5),  # length 5
        ("longer", 2, 10),  # length 8, overlaps with short
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 1
    assert result[0] == ("longer", 2, 10)


def test_simple_overlap_shorter_wins_when_earlier():
    """Test that when lengths are equal, earlier match wins."""
    matches: list[PatternMatch] = [
        ("text1", 0, 5),  # length 5, starts at 0
        ("text2", 3, 8),  # length 5, starts at 3, overlaps
    ]
    result = remove_overlapping_matches(matches)
    # When priorities are equal, the one with longer length wins
    # But if lengths are equal, the earlier one (sorted first) wins
    assert len(result) == 1
    assert result[0] == ("text1", 0, 5)


def test_multiple_overlaps():
    """Test multiple overlapping matches."""
    matches: list[PatternMatch] = [
        ("short", 0, 4),  # length 4
        ("medium", 2, 9),  # length 7, overlaps with short
        ("longest", 5, 15),  # length 10, overlaps with medium
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 1
    assert result[0] == ("longest", 5, 15)


def test_custom_priority_higher_wins():
    """Test that higher priority wins when priority_map is provided."""
    matches: list[PatternMatch] = [
        ("longer", 0, 10),  # length 10
        ("short", 2, 5),  # length 3, overlaps
    ]
    priority_map = {
        ("longer", 0, 10): 5.0,
        ("short", 2, 5): 10.0,  # Higher priority despite being shorter
    }
    result = remove_overlapping_matches(matches, priority_map)
    assert len(result) == 1
    assert result[0] == ("short", 2, 5)


def test_custom_priority_equal_priority_longer_wins():
    """Test that when priorities are equal, longer match wins."""
    matches: list[PatternMatch] = [
        ("short", 0, 5),  # length 5
        ("longer", 2, 10),  # length 8, overlaps
    ]
    priority_map = {
        ("short", 0, 5): 10.0,
        ("longer", 2, 10): 10.0,  # Same priority
    }
    result = remove_overlapping_matches(matches, priority_map)
    assert len(result) == 1
    assert result[0] == ("longer", 2, 10)


def test_adjacent_matches_no_overlap():
    """Test that adjacent matches (touching but not overlapping) are both kept."""
    matches: list[PatternMatch] = [
        ("text1", 0, 5),  # ends at 5
        ("text2", 5, 10),  # starts at 5, no overlap
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 2
    assert set(result) == set(matches)


def test_completely_contained_match():
    """Test when one match is completely contained within another."""
    matches: list[PatternMatch] = [
        ("outer", 0, 20),  # length 20
        ("inner", 5, 10),  # length 5, completely inside outer
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 1
    assert result[0] == ("outer", 0, 20)


def test_completely_contained_with_priority():
    """Test contained match wins when it has higher priority."""
    matches: list[PatternMatch] = [
        ("outer", 0, 20),  # length 20
        ("inner", 5, 10),  # length 5, completely inside outer
    ]
    priority_map = {
        ("outer", 0, 20): 5.0,
        ("inner", 5, 10): 15.0,  # Higher priority
    }
    result = remove_overlapping_matches(matches, priority_map)
    assert len(result) == 1
    assert result[0] == ("inner", 5, 10)


def test_multiple_non_overlapping_groups():
    """Test multiple groups of overlapping matches."""
    matches: list[PatternMatch] = [
        ("group1_short", 0, 5),  # length 5
        ("group1_long", 2, 10),  # length 8, overlaps with group1_short
        ("group2_short", 20, 25),  # length 5
        ("group2_long", 22, 30),  # length 8, overlaps with group2_short
    ]
    result = remove_overlapping_matches(matches)
    assert len(result) == 2
    assert ("group1_long", 2, 10) in result
    assert ("group2_long", 22, 30) in result


def test_priority_map_missing_key_uses_length():
    """Test that missing keys in priority_map fall back to length."""
    matches: list[PatternMatch] = [
        ("text1", 0, 5),  # length 5
        ("text2", 2, 12),  # length 10, overlaps
    ]
    priority_map = {
        ("text1", 0, 5): 20.0,  # High priority but missing text2
    }
    # text2 not in priority_map, so uses length (10) as priority
    # text1 has priority 20, so it should win
    result = remove_overlapping_matches(matches, priority_map)
    assert len(result) == 1
    assert result[0] == ("text1", 0, 5)


def test_three_way_overlap():
    """Test three matches all overlapping each other."""
    matches: list[PatternMatch] = [
        ("first", 0, 6),  # length 6
        ("second", 3, 9),  # length 6, overlaps first
        ("third", 5, 15),  # length 10, overlaps both first and second
    ]
    result = remove_overlapping_matches(matches)
    # Third is longest (10), should win
    assert len(result) == 1
    assert result[0] == ("third", 5, 15)


def test_priority_tie_same_length_earlier_wins():
    """Test that when priority and length are equal, earlier match wins."""
    matches: list[PatternMatch] = [
        ("first", 0, 5),  # length 5, starts at 0
        ("second", 3, 8),  # length 5, starts at 3, overlaps
    ]
    priority_map = {
        ("first", 0, 5): 10.0,
        ("second", 3, 8): 10.0,  # Same priority, same length
    }
    result = remove_overlapping_matches(matches, priority_map)
    # When priority and length are equal, earlier one (sorted first) wins
    assert len(result) == 1
    assert result[0] == ("first", 0, 5)


def test_complex_scenario():
    """Test a complex scenario with multiple overlaps and priorities."""
    matches: list[PatternMatch] = [
        ("a", 0, 3),  # length 3
        ("b", 2, 8),  # length 6, overlaps a
        ("c", 10, 15),  # length 5, no overlap
        ("d", 12, 20),  # length 8, overlaps c
        ("e", 25, 30),  # length 5, no overlap
    ]
    priority_map = {
        ("a", 0, 3): 15.0,  # High priority but short
        ("b", 2, 8): 5.0,  # Lower priority, longer
        ("c", 10, 15): 20.0,  # Highest priority
        ("d", 12, 20): 10.0,  # Medium priority, longer
        ("e", 25, 30): 1.0,  # Low priority
    }
    result = remove_overlapping_matches(matches, priority_map)
    # a wins over b (higher priority)
    # c wins over d (higher priority)
    # e is kept (no overlap)
    assert len(result) == 3
    assert ("a", 0, 3) in result
    assert ("c", 10, 15) in result
    assert ("e", 25, 30) in result
