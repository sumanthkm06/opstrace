"""
OpsTrace Collector — Log Analysis Engine
Phase 6: Log Analysis & Intelligence

The ``LogAnalyzer`` is the main orchestrator for Phase 6.

It coordinates all analysis sub-components and produces a single structured
``AnalysisResult`` from a sequence of ``CollectedLogEvent`` objects.

Pipeline::

    CollectedLogEvent list
        │
        ├─► LogClassifier        (classify each event → AnalysisClassification)
        │
        ├─► FingerprintGenerator (generate fingerprints for events lacking one)
        │
        ├─► LogGrouper           (group ERROR/CRITICAL events by fingerprint)
        │
        ├─► ErrorRateAnalyzer    (calculate errors/minute, errors/hour)
        │
        └─► AnalysisResult       (assembled structured output)

Design decisions:
  - Malformed or unexpected events do not crash the analyser; they are
    counted in ``analysis_warnings`` / ``analysis_errors``.
  - An empty event list is accepted and returns a zero-filled result.
  - Each sub-component is independently testable.
  - The analyser is stateless; it can be instantiated once and reused.
  - No database writes, no HTTP calls, no ML.

Security:
  - Log message content is never executed or interpreted as code.
  - Internal errors are logged; raw message content is never included
    in error log output.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import List, Optional, Sequence

from collector.app.collectors.log_models import CollectedLogEvent
from collector.app.analyzers.classifier import AnalysisClassification, LogClassifier
from collector.app.analyzers.error_rate import ErrorRateAnalyzer
from collector.app.analyzers.fingerprint import FingerprintGenerator
from collector.app.analyzers.grouping import LogGrouper
from collector.app.analyzers.models import AnalysisResult, ErrorGroupSummary

logger = logging.getLogger(__name__)

# Levels treated as "error-class" for grouping and rate calculation.
_ERROR_CLASS_LEVELS = {"ERROR", "CRITICAL", "FATAL"}


class LogAnalyzer:
    """
    Phase 6 log analysis engine.

    Orchestrates classification, fingerprinting, grouping, and error-rate
    analysis into a single ``AnalysisResult``.

    Example::

        analyzer = LogAnalyzer()
        result = analyzer.analyze(events)
        print(result.total_errors)
        print(result.error_rate_per_minute)
        for grp in result.error_groups:
            print(grp.fingerprint, grp.count, grp.sample_message)

    Args:
        window: Optional explicit time window for rate calculations.
                If None, the window is inferred from the event timestamps.
    """

    def __init__(self, window: Optional[timedelta] = None) -> None:
        self._window = window
        self._classifier = LogClassifier()
        self._fp_gen = FingerprintGenerator()
        self._grouper = LogGrouper()
        self._rate_analyser = ErrorRateAnalyzer()

    def analyze(
        self,
        events: Sequence[CollectedLogEvent],
    ) -> AnalysisResult:
        """
        Run the full Phase 6 analysis pipeline on a sequence of log events.

        Args:
            events: A sequence of ``CollectedLogEvent`` objects collected by
                    the Phase 5 collectors.  May be empty.

        Returns:
            An ``AnalysisResult`` with all fields populated.  Never raises.
        """
        result = AnalysisResult(total_logs_analyzed=len(events))

        if not events:
            logger.debug("LogAnalyzer.analyze called with empty event list.")
            return result

        # ----------------------------------------------------------------
        # Step 1: Classify and fingerprint each event
        # ----------------------------------------------------------------
        enriched: List[CollectedLogEvent] = []
        error_class_events: List[CollectedLogEvent] = []

        for idx, event in enumerate(events):
            try:
                event = self._enrich(event, result)
                enriched.append(event)

                classification = self._classifier.classify(
                    level=event.level.value if event.level else None,
                    message=event.message,
                )

                # Accumulate severity counts
                if classification == AnalysisClassification.INFO:
                    result.total_info += 1
                elif classification == AnalysisClassification.WARNING:
                    result.total_warnings += 1
                elif classification == AnalysisClassification.ERROR:
                    result.total_errors += 1
                    error_class_events.append(event)
                elif classification == AnalysisClassification.CRITICAL:
                    result.total_critical += 1
                    result.total_errors += 1  # critical is also an error
                    error_class_events.append(event)
                else:
                    result.total_unknown += 1

            except Exception as exc:
                logger.warning(
                    "LogAnalyzer: error processing event[%d]: %s", idx, exc
                )
                result.analysis_errors.append(
                    f"Event[{idx}] skipped: {type(exc).__name__}"
                )

        # ----------------------------------------------------------------
        # Step 2: Group error-class events by fingerprint
        # ----------------------------------------------------------------
        try:
            groups = self._grouper.group(error_class_events)
            summaries: List[ErrorGroupSummary] = []
            for fp, grp in groups.items():
                summaries.append(
                    ErrorGroupSummary(
                        fingerprint=grp.fingerprint,
                        count=grp.count,
                        first_seen=grp.first_seen,
                        last_seen=grp.last_seen,
                        sample_message=grp.sample_message,
                        level=grp.level,
                        source=grp.source,
                    )
                )
            # Sort by count descending (most frequent first)
            summaries.sort(key=lambda s: s.count, reverse=True)
            result.error_groups = summaries
            result.unique_error_fingerprints = len(summaries)
        except Exception as exc:
            logger.error("LogAnalyzer: grouping step failed: %s", exc)
            result.analysis_errors.append(f"Grouping failed: {type(exc).__name__}")

        # ----------------------------------------------------------------
        # Step 3: Error-rate analysis
        # ----------------------------------------------------------------
        try:
            rate = self._rate_analyser.calculate(enriched, window=self._window)
            result.error_rate_per_minute = rate.errors_per_minute
            result.error_rate_per_hour = rate.errors_per_hour
            result.analysis_window_seconds = rate.window_seconds
            result.window_start = rate.window_start
            result.window_end = rate.window_end
        except Exception as exc:
            logger.error("LogAnalyzer: error-rate step failed: %s", exc)
            result.analysis_errors.append(f"ErrorRate failed: {type(exc).__name__}")

        logger.debug(
            "LogAnalyzer.analyze complete: total=%d errors=%d critical=%d "
            "groups=%d rate=%.4f/min",
            result.total_logs_analyzed,
            result.total_errors,
            result.total_critical,
            result.unique_error_fingerprints,
            result.error_rate_per_minute,
        )

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _enrich(
        self,
        event: CollectedLogEvent,
        result: AnalysisResult,
    ) -> CollectedLogEvent:
        """
        Ensure the event has a fingerprint.

        If the event lacks a fingerprint, generate one using the
        ``FingerprintGenerator``.  The original event is not mutated;
        a new ``CollectedLogEvent`` is returned with the fingerprint set.

        Args:
            event:  Input log event.
            result: Analysis result (for recording warnings).

        Returns:
            A ``CollectedLogEvent`` guaranteed to have a ``fingerprint`` value.
        """
        if event.fingerprint and len(event.fingerprint) >= 8:
            return event  # already has a fingerprint

        try:
            fp = self._fp_gen.generate(
                message=event.message,
                level=event.level.value if event.level else None,
                source=event.source,
            )
            # Return a copy with fingerprint set (Pydantic v2: model_copy)
            return event.model_copy(update={"fingerprint": fp})
        except Exception as exc:
            logger.debug("_enrich: fingerprint generation failed: %s", exc)
            result.analysis_warnings.append("Fingerprint generation failed for one event.")
            return event
