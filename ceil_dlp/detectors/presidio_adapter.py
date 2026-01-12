"""Adapter to integrate Presidio for standard PII detection."""

import logging

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from ceil_dlp.detectors.patterns import PatternMatch

logger = logging.getLogger(__name__)

PRESIDIO_TO_PII_TYPE: dict[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "INTERNATIONAL_PHONE_NUMBER": "phone",
}


# Lazy initialization of analyzer to avoid import-time model loading
_analyzer: AnalyzerEngine | None = None


def get_presidio_analyzer() -> AnalyzerEngine:
    """
    Get or create AnalyzerEngine instance, using smaller spaCy model.

    This is a shared utility used by text detection, image detection, and image redaction.
    Uses en_core_web_sm (smaller, faster model) instead of the default en_core_web_lg.

    Returns:
        Configured AnalyzerEngine instance
    """
    global _analyzer
    if _analyzer is None:
        # Use en_core_web_sm (smaller, faster model)
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
        _analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    return _analyzer


def _detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    analyzer = get_presidio_analyzer()
    results = analyzer.analyze(text=text, language="en")
    detections: dict[str, list[PatternMatch]] = {}
    for result in results:
        entity_type = result.entity_type
        pii_type = PRESIDIO_TO_PII_TYPE.get(entity_type)
        if pii_type:
            matched_text = text[result.start : result.end]
            match = (matched_text, result.start, result.end)
            if pii_type not in detections:
                detections[pii_type] = []
            detections[pii_type].append(match)
    return detections


def detect_with_presidio(text: str) -> dict[str, list[PatternMatch]]:
    """
    Detect standard PII using Presidio.

    Args:
        text: Input text to scan

    Returns:
        Dictionary mapping PII type to list of matches.
        Each match is a tuple: (matched_text, start_pos, end_pos)
    """
    try:
        return _detect_with_presidio(text)
    except Exception as e:
        raise RuntimeError("Failed to detect PII with Presidio") from e
