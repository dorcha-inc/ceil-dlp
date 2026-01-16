"""Utility functions for removing overlapping matches."""

# PatternMatch is a tuple of (matched_text, start_pos, end_pos)
PatternMatch = tuple[str, int, int]


def remove_overlapping_matches(
    matches: list[PatternMatch],
    priority_map: dict[PatternMatch, float] | None = None,
) -> list[PatternMatch]:
    """
    Remove overlapping matches, keeping higher priority ones.

    This is a general-purpose function for removing overlapping PatternMatch tuples.
    When two matches overlap, the one with higher priority is kept.
    If no priority_map is provided, longer matches are preferred.

    Args:
        matches: List of PatternMatch tuples (text, start, end)
        priority_map: Optional dict mapping matches to priority values (higher = keep).
                     If None, uses match length as priority.

    Returns:
        List of non-overlapping matches

    Examples:
        # For simple case (longest match wins):
        matches = [("text", 0, 4), ("longer", 2, 8)]
        result = remove_overlapping_matches(matches)

        # With custom priority:
        matches = [("text", 0, 4), ("longer", 2, 8)]
        priority_map = {("text", 0, 4): 10, ("longer", 2, 8): 5}
        result = remove_overlapping_matches(matches, priority_map)
    """
    if not matches:
        return []

    # Calculate priority for each match
    priorities: list[tuple[float, PatternMatch]] = []
    for match in matches:
        _text, start, end = match
        length = end - start
        # Default: use length as priority if priority_map is None
        priority = length if priority_map is None else priority_map.get(match, length)
        priorities.append((priority, match))

    # Sort by start position, then by priority (higher first) for stable ordering
    sorted_matches = sorted(priorities, key=lambda x: (x[1][1], -x[0]))  # x[1][1] is start position

    non_overlapping: list[PatternMatch] = []

    for priority, match in sorted_matches:
        _text, start, end = match
        match_length = end - start
        overlap_found = False
        to_remove = []

        for i, existing_match in enumerate(non_overlapping):
            _existing_text, existing_start, existing_end = existing_match
            existing_length = existing_end - existing_start

            # Check for overlap: two ranges overlap if not (end <= existing_start or start >= existing_end)
            if not (end <= existing_start or start >= existing_end):
                overlap_found = True
                # Get priority of existing match
                existing_priority = (
                    existing_length
                    if priority_map is None
                    else priority_map.get(existing_match, existing_length)
                )

                # If current match has higher priority, mark existing for removal
                if priority > existing_priority or (
                    priority == existing_priority and match_length > existing_length
                ):
                    to_remove.append(i)
                else:
                    # Current match should be skipped
                    break

        # Remove marked overlaps (in reverse order to maintain indices)
        for i in reversed(to_remove):
            non_overlapping.pop(i)

        # Add current match if no overlap or if it replaced overlapping ones
        if not overlap_found or to_remove:
            non_overlapping.append(match)

    return non_overlapping
