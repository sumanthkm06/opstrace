"""
OpsTrace Collector — Log Classifier
Phase 6: Log Analysis & Intelligence

Deterministic, rule-based classification of log events into a small set of
well-known severity categories.

Design decisions:
  - Classification is based solely on the ``level`` field already carried by
    ``CollectedLogEvent`` (populated by the Phase 5 parser / normaliser).
  - If no usable level exists, the message text is scanned for common
    severity keywords as a best-effort fallback.
  - All logic is deterministic: same input → same output, always.
  - No machine learning, no external API calls.

Classification categories (superset of Phase 5 ``LogLevel``):
  DEBUG    → mapped to INFO for Phase 6 analysis purposes
  INFO     → INFO
  WARNING  → WARNING
  ERROR    → ERROR
  CRITICAL → CRITICAL
  UNKNOWN  → safe fallback when no level is determinable

Security:
  - Log message content is never executed or interpreted as code.
  - Pattern matching uses pre-compiled re patterns with bounded input.
"""

from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Analysis classification enum
# ---------------------------------------------------------------------------


class AnalysisClassification(str, Enum):
    """
    Severity classification used by the Phase 6 analysis engine.

    Differs slightly from ``LogLevel`` in Phase 5 by adding ``UNKNOWN``
    as an explicit category for unclassifiable logs.
    """

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Level string → classification mapping
# ---------------------------------------------------------------------------

# Ordered mapping from normalised level strings to AnalysisClassification.
# DEBUG is mapped to INFO because it carries no actionable severity signal.
_LEVEL_TO_CLASS: dict[str, AnalysisClassification] = {
    "debug": AnalysisClassification.INFO,
    "dbg": AnalysisClassification.INFO,
    "info": AnalysisClassification.INFO,
    "information": AnalysisClassification.INFO,
    "notice": AnalysisClassification.INFO,
    "warn": AnalysisClassification.WARNING,
    "warning": AnalysisClassification.WARNING,
    "err": AnalysisClassification.ERROR,
    "error": AnalysisClassification.ERROR,
    "crit": AnalysisClassification.CRITICAL,
    "critical": AnalysisClassification.CRITICAL,
    "fatal": AnalysisClassification.CRITICAL,
    "emerg": AnalysisClassification.CRITICAL,
    "alert": AnalysisClassification.CRITICAL,
}

# Fallback keyword scan patterns (applied to the message body when the level
# field alone is insufficient).  Patterns are checked in priority order.
_KEYWORD_PATTERNS: list[tuple[re.Pattern[str], AnalysisClassification]] = [
    (
        re.compile(
            r"\b(CRITICAL|FATAL|EMERG|EMERGENCY|ALERT)\b",
            re.IGNORECASE,
        ),
        AnalysisClassification.CRITICAL,
    ),
    (
        re.compile(
            r"\b(ERROR|ERR|EXCEPTION|TRACEBACK|STACK\s*TRACE)\b",
            re.IGNORECASE,
        ),
        AnalysisClassification.ERROR,
    ),
    (
        re.compile(
            r"\b(WARN(?:ING)?)\b",
            re.IGNORECASE,
        ),
        AnalysisClassification.WARNING,
    ),
    (
        re.compile(
            r"\b(INFO|INFORMATION|NOTICE|DEBUG)\b",
            re.IGNORECASE,
        ),
        AnalysisClassification.INFO,
    ),
]


# ---------------------------------------------------------------------------
# Public classifier class
# ---------------------------------------------------------------------------


class LogClassifier:
    """
    Deterministic rule-based log classifier.

    Classifies a log event into one of the ``AnalysisClassification`` values
    based on:

    1. The ``level`` field of the ``CollectedLogEvent`` (primary signal).
    2. Keyword scanning of the ``message`` text (fallback).
    3. ``UNKNOWN`` when no classification can be determined.

    The classifier is stateless; a single instance can be reused across
    many classification calls.

    Example::

        clf = LogClassifier()
        clf.classify_level("ERROR")       # → AnalysisClassification.ERROR
        clf.classify_message("WARN foo")  # → AnalysisClassification.WARNING
    """

    def classify_level(self, level: Optional[str]) -> AnalysisClassification:
        """
        Classify based on a level string (e.g. from ``CollectedLogEvent.level``).

        Args:
            level: A level string such as ``"INFO"``, ``"WARNING"``, ``"ERROR"``,
                   ``"CRITICAL"``, or any alias.  Case-insensitive.  None is safe.

        Returns:
            The matching ``AnalysisClassification`` value, or ``UNKNOWN`` if
            the string is absent, empty, or unrecognised.
        """
        if not level:
            return AnalysisClassification.UNKNOWN
        normalised = level.strip().lower()
        result = _LEVEL_TO_CLASS.get(normalised)
        if result is not None:
            return result
        logger.debug("classify_level: unrecognised level %r → UNKNOWN", level)
        return AnalysisClassification.UNKNOWN

    def classify_message(self, message: Optional[str]) -> AnalysisClassification:
        """
        Classify based on keywords found in the message text.

        This is the fallback path used when the ``level`` field is absent or
        ``UNKNOWN``.  Patterns are matched in priority order (CRITICAL first,
        then ERROR, WARNING, INFO).

        Args:
            message: Raw log message text.  None is safe.

        Returns:
            The first matching ``AnalysisClassification``, or ``UNKNOWN`` if
            no keyword is found.
        """
        if not message:
            return AnalysisClassification.UNKNOWN
        # Limit to first 500 chars to bound regex cost on very long lines.
        sample = message[:500]
        for pattern, classification in _KEYWORD_PATTERNS:
            if pattern.search(sample):
                return classification
        return AnalysisClassification.UNKNOWN

    def classify(
        self,
        level: Optional[str] = None,
        message: Optional[str] = None,
    ) -> AnalysisClassification:
        """
        Classify a log event using level (primary) then message (fallback).

        Args:
            level:   The ``level`` string from the log event.
            message: The ``message`` text from the log event.

        Returns:
            The best-matching ``AnalysisClassification``.  Always returns a
            value; never raises.
        """
        try:
            result = self.classify_level(level)
            if result != AnalysisClassification.UNKNOWN:
                return result
            return self.classify_message(message)
        except Exception as exc:  # pragma: no cover — defensive
            logger.error("LogClassifier.classify unexpected error: %s", exc)
            return AnalysisClassification.UNKNOWN
