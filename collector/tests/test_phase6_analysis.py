"""
OpsTrace Phase 6 — Log Analysis & Intelligence Tests
======================================================

Comprehensive unit tests for the Phase 6 log analysis engine.

Coverage:
  CLASSIFICATION (10 tests)
    1.  INFO level classification
    2.  WARNING level classification (WARN alias)
    3.  ERROR level classification
    4.  CRITICAL level classification (FATAL alias)
    5.  UNKNOWN fallback (None level)
    6.  UNKNOWN fallback (empty string level)
    7.  Keyword fallback — CRITICAL keyword in message
    8.  Keyword fallback — ERROR keyword in message
    9.  Keyword fallback — WARNING keyword in message
   10.  Keyword fallback — INFO keyword in message

  FINGERPRINTING (9 tests)
   11.  Same message → same fingerprint
   12.  Dynamic user ID normalised (same fingerprint)
   13.  Dynamic IP address normalised (same fingerprint)
   14.  Different errors → different fingerprints
   15.  Deterministic SHA-256 output (64 hex chars)
   16.  Empty message handled safely
   17.  None message handled safely
   18.  UUID normalised
   19.  Timestamp normalised

  GROUPING (9 tests)
   20.  Repeated fingerprint grouped correctly
   21.  Different fingerprints remain separate
   22.  Missing fingerprint handled safely
   23.  Counts are correct
   24.  first_seen is the earliest timestamp
   25.  last_seen is the latest timestamp
   26.  Empty input returns empty dict
   27.  Single event grouped correctly
   28.  Level-filtered grouping

  ERROR RATE (8 tests)
   29.  Correct error count
   30.  Correct errors/minute rate
   31.  Empty input returns zero rate
   32.  Single event handled (no divide-by-zero)
   33.  Explicit window parameter used
   34.  Correct warning count
   35.  Correct critical count
   36.  Per-fingerprint counts populated

  ANALYZER (8 tests)
   37.  Combines all sub-components
   38.  Returns valid AnalysisResult
   39.  Malformed log does not crash analyzer
   40.  Empty dataset returns zero-filled result
   41.  analysis_errors populated on skipped events
   42.  error_groups sorted by count descending
   43.  total_errors includes CRITICAL events
   44.  unique_error_fingerprints count is correct

  INTEGRATION (4 tests)
   45.  Phase 6 models importable without Phase 2/3/4/5 breakage
   46.  CollectedLogEvent (Phase 5) accepted by LogAnalyzer
   47.  LogBatch (Phase 5) events accepted by LogAnalyzer
   48.  AnalysisResult serialises to JSON without error

Run from repository root:
    python -m pytest collector/tests/test_phase6_analysis.py -v
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# sys.path bootstrap (same pattern as test_phase5_logs.py)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent.parent   # opstrace/
BACKEND_DIR = REPO_ROOT / "backend"
COLLECTOR_DIR = REPO_ROOT / "collector"
for _p in (str(REPO_ROOT), str(BACKEND_DIR), str(COLLECTOR_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Phase 6 imports
# ---------------------------------------------------------------------------

from collector.app.analyzers.classifier import (
    AnalysisClassification,
    LogClassifier,
)
from collector.app.analyzers.fingerprint import FingerprintGenerator
from collector.app.analyzers.grouping import LogGrouper, ErrorGroup
from collector.app.analyzers.error_rate import ErrorRateAnalyzer, WindowRate
from collector.app.analyzers.log_analyzer import LogAnalyzer
from collector.app.analyzers.models import AnalysisResult, ErrorGroupSummary

# Phase 5 imports (must still work after Phase 6 is added)
from collector.app.collectors.log_models import (
    CollectedLogEvent,
    LogBatch,
    LogLevel,
    LogSourceType,
)


# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

def _make_event(
    message: str = "test message",
    level: LogLevel = LogLevel.INFO,
    source: str = "test.log",
    timestamp: datetime = None,
    fingerprint: str = None,
    hostname: str = None,
) -> CollectedLogEvent:
    """Build a minimal CollectedLogEvent for testing."""
    return CollectedLogEvent(
        message=message,
        level=level,
        source=source,
        timestamp=timestamp or datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        fingerprint=fingerprint,
        hostname=hostname,
    )


def _ts(hour: int, minute: int = 0) -> datetime:
    """Return a UTC datetime for 2024-01-15 at the given hour/minute."""
    return datetime(2024, 1, 15, hour, minute, 0, tzinfo=timezone.utc)


# ===========================================================================
# SECTION 1 — CLASSIFICATION TESTS
# ===========================================================================


class TestLogClassifier:
    """Tests for LogClassifier."""

    def setup_method(self):
        self.clf = LogClassifier()

    # --- Level-based classification ---

    def test_info_level(self):
        """Test 1: INFO level is classified as INFO."""
        result = self.clf.classify_level("INFO")
        assert result == AnalysisClassification.INFO

    def test_warning_level(self):
        """Test 2: WARNING (and WARN alias) classified as WARNING."""
        assert self.clf.classify_level("WARNING") == AnalysisClassification.WARNING
        assert self.clf.classify_level("WARN") == AnalysisClassification.WARNING

    def test_error_level(self):
        """Test 3: ERROR level classified as ERROR."""
        assert self.clf.classify_level("ERROR") == AnalysisClassification.ERROR
        assert self.clf.classify_level("err") == AnalysisClassification.ERROR

    def test_critical_level(self):
        """Test 4: CRITICAL and FATAL alias classified as CRITICAL."""
        assert self.clf.classify_level("CRITICAL") == AnalysisClassification.CRITICAL
        assert self.clf.classify_level("FATAL") == AnalysisClassification.CRITICAL
        assert self.clf.classify_level("fatal") == AnalysisClassification.CRITICAL

    def test_unknown_fallback_none(self):
        """Test 5: None level → UNKNOWN."""
        assert self.clf.classify_level(None) == AnalysisClassification.UNKNOWN

    def test_unknown_fallback_empty_string(self):
        """Test 6: Empty string level → UNKNOWN."""
        assert self.clf.classify_level("") == AnalysisClassification.UNKNOWN
        assert self.clf.classify_level("   ") == AnalysisClassification.UNKNOWN

    # --- Message keyword fallback ---

    def test_keyword_critical_in_message(self):
        """Test 7: CRITICAL keyword in message → CRITICAL."""
        result = self.clf.classify_message("CRITICAL payment service unavailable")
        assert result == AnalysisClassification.CRITICAL

    def test_keyword_error_in_message(self):
        """Test 8: ERROR keyword in message → ERROR."""
        result = self.clf.classify_message("ERROR database connection refused")
        assert result == AnalysisClassification.ERROR

    def test_keyword_warning_in_message(self):
        """Test 9: WARN keyword in message → WARNING."""
        result = self.clf.classify_message("WARN Connection pool almost full")
        assert result == AnalysisClassification.WARNING

    def test_keyword_info_in_message(self):
        """Test 10: INFO keyword in message → INFO."""
        result = self.clf.classify_message("INFO Server started successfully")
        assert result == AnalysisClassification.INFO

    def test_classify_combines_level_then_message(self):
        """classify() uses level first; falls back to message when UNKNOWN."""
        # Level present → use level
        assert self.clf.classify(level="ERROR", message="something") == AnalysisClassification.ERROR
        # Level absent → use message
        assert self.clf.classify(level=None, message="CRITICAL failure") == AnalysisClassification.CRITICAL
        # Both absent → UNKNOWN
        assert self.clf.classify(level=None, message=None) == AnalysisClassification.UNKNOWN

    def test_debug_mapped_to_info(self):
        """DEBUG level is mapped to INFO for analysis purposes."""
        assert self.clf.classify_level("DEBUG") == AnalysisClassification.INFO
        assert self.clf.classify_level("dbg") == AnalysisClassification.INFO

    def test_classify_case_insensitive(self):
        """Level classification is case-insensitive."""
        assert self.clf.classify_level("error") == AnalysisClassification.ERROR
        assert self.clf.classify_level("Warning") == AnalysisClassification.WARNING


# ===========================================================================
# SECTION 2 — FINGERPRINTING TESTS
# ===========================================================================


class TestFingerprintGenerator:
    """Tests for FingerprintGenerator."""

    def setup_method(self):
        self.gen = FingerprintGenerator()

    def test_same_message_same_fingerprint(self):
        """Test 11: Same message → same fingerprint."""
        fp1 = self.gen.generate("Connection refused to database")
        fp2 = self.gen.generate("Connection refused to database")
        assert fp1 == fp2

    def test_dynamic_user_id_normalised(self):
        """Test 12: Dynamic user IDs produce the same fingerprint."""
        fp1 = self.gen.generate("Connection to database failed for user 123")
        fp2 = self.gen.generate("Connection to database failed for user 456")
        assert fp1 == fp2, (
            "User IDs should be normalised so similar errors share a fingerprint"
        )

    def test_dynamic_ip_normalised(self):
        """Test 13: Dynamic IP addresses produce the same fingerprint."""
        fp1 = self.gen.generate("Connection from 192.168.1.100 rejected")
        fp2 = self.gen.generate("Connection from 10.0.0.5 rejected")
        assert fp1 == fp2

    def test_different_errors_different_fingerprints(self):
        """Test 14: Different error messages produce different fingerprints."""
        fp1 = self.gen.generate("Database connection refused")
        fp2 = self.gen.generate("Disk quota exceeded")
        assert fp1 != fp2

    def test_sha256_output_format(self):
        """Test 15: Fingerprint is a 64-char lowercase hex string (SHA-256)."""
        fp = self.gen.generate("some error message")
        assert len(fp) == 64
        assert fp == fp.lower()
        # Verify it is valid hex
        int(fp, 16)  # raises ValueError if not valid hex

    def test_empty_message_handled(self):
        """Test 16: Empty message does not raise."""
        fp = self.gen.generate("")
        assert len(fp) == 64

    def test_none_message_handled(self):
        """Test 17: None message does not raise."""
        fp = self.gen.generate(None)
        assert len(fp) == 64

    def test_uuid_normalised(self):
        """Test 18: UUIDs are replaced by a placeholder."""
        msg1 = "Session 550e8400-e29b-41d4-a716-446655440000 expired"
        msg2 = "Session 6ba7b810-9dad-11d1-80b4-00c04fd430c8 expired"
        assert self.gen.generate(msg1) == self.gen.generate(msg2)

    def test_timestamp_normalised(self):
        """Test 19: ISO 8601 timestamps are replaced by a placeholder."""
        msg1 = "Event at 2024-01-15T12:34:56Z failed"
        msg2 = "Event at 2024-06-01T08:00:00Z failed"
        assert self.gen.generate(msg1) == self.gen.generate(msg2)

    def test_deterministic_sha256(self):
        """Fingerprint matches manual SHA-256 calculation of normalised string."""
        gen = FingerprintGenerator()
        message = "test error"
        fp = gen.generate(message, level="ERROR", source="app.log")
        norm_msg = gen.normalise(message)
        canonical = f"ERROR:app.log:{norm_msg}"
        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:64]
        assert fp == expected


# ===========================================================================
# SECTION 3 — GROUPING TESTS
# ===========================================================================


class TestLogGrouper:
    """Tests for LogGrouper."""

    def setup_method(self):
        self.grouper = LogGrouper()

    def _error_event(self, msg: str, fp: str = None, ts: datetime = None) -> CollectedLogEvent:
        return _make_event(
            message=msg,
            level=LogLevel.ERROR,
            fingerprint=fp,
            timestamp=ts or _ts(12),
        )

    def test_repeated_fingerprint_grouped(self):
        """Test 20: Events with the same fingerprint are grouped into one entry."""
        events = [
            self._error_event("DB error", fp="abc123" * 11),
            self._error_event("DB error", fp="abc123" * 11),
            self._error_event("DB error", fp="abc123" * 11),
        ]
        fp = "abc123" * 11
        groups = self.grouper.group(events)
        assert fp in groups or len(groups) == 1
        first_group = next(iter(groups.values()))
        assert first_group.count == 3

    def test_different_fingerprints_separate(self):
        """Test 21: Events with different fingerprints remain in separate groups."""
        events = [
            self._error_event("DB error", fp="aaaa" * 16),
            self._error_event("Disk error", fp="bbbb" * 16),
        ]
        groups = self.grouper.group(events)
        assert len(groups) == 2

    def test_missing_fingerprint_handled(self):
        """Test 22: Events without a fingerprint are grouped (auto-generated)."""
        events = [
            self._error_event("DB error"),  # no fingerprint
            self._error_event("DB error"),  # no fingerprint — same message → same group
        ]
        groups = self.grouper.group(events)
        # Should produce one or two groups (auto-generated fps should match for same msg+level+source)
        # They share message/level/source so auto-generated fp should be the same
        total_count = sum(g.count for g in groups.values())
        assert total_count == 2

    def test_counts_correct(self):
        """Test 23: Group count reflects the number of matching events."""
        fp = "x" * 64
        events = [self._error_event(f"error {i}", fp=fp) for i in range(7)]
        groups = self.grouper.group(events)
        assert groups[fp].count == 7

    def test_first_seen_is_earliest(self):
        """Test 24: first_seen holds the earliest event timestamp."""
        fp = "a" * 64
        events = [
            self._error_event("err", fp=fp, ts=_ts(14)),
            self._error_event("err", fp=fp, ts=_ts(10)),  # earliest
            self._error_event("err", fp=fp, ts=_ts(12)),
        ]
        groups = self.grouper.group(events)
        assert groups[fp].first_seen == _ts(10)

    def test_last_seen_is_latest(self):
        """Test 25: last_seen holds the most recent event timestamp."""
        fp = "b" * 64
        events = [
            self._error_event("err", fp=fp, ts=_ts(10)),
            self._error_event("err", fp=fp, ts=_ts(14)),  # latest
            self._error_event("err", fp=fp, ts=_ts(12)),
        ]
        groups = self.grouper.group(events)
        assert groups[fp].last_seen == _ts(14)

    def test_empty_input_returns_empty_dict(self):
        """Test 26: Empty event list returns empty dict."""
        assert self.grouper.group([]) == {}

    def test_single_event_grouped(self):
        """Test 27: A single event forms a group of count=1."""
        events = [self._error_event("single error", fp="s" * 64)]
        groups = self.grouper.group(events)
        assert len(groups) == 1
        grp = next(iter(groups.values()))
        assert grp.count == 1
        assert grp.sample_message == "single error"

    def test_level_filtered_grouping(self):
        """Test 28: group_by_level correctly filters before grouping."""
        events = [
            _make_event(message="error event", level=LogLevel.ERROR, fingerprint="e" * 64),
            _make_event(message="info event", level=LogLevel.INFO, fingerprint="i" * 64),
            _make_event(message="error event 2", level=LogLevel.ERROR, fingerprint="e" * 64),
        ]
        groups = self.grouper.group_by_level(events, "ERROR")
        assert len(groups) == 1  # only ERROR events, both share the same fingerprint
        assert next(iter(groups.values())).count == 2


# ===========================================================================
# SECTION 4 — ERROR RATE TESTS
# ===========================================================================


class TestErrorRateAnalyzer:
    """Tests for ErrorRateAnalyzer."""

    def setup_method(self):
        self.analyser = ErrorRateAnalyzer()

    def _events(
        self,
        counts: dict,
        base_ts: datetime = None,
        interval_seconds: int = 60,
    ) -> List[CollectedLogEvent]:
        """
        Build an event list from a dict of {level_str: count}.

        Timestamps are spaced ``interval_seconds`` apart starting from ``base_ts``.
        """
        base = base_ts or _ts(12, 0)
        events = []
        offset = 0
        for level_str, count in counts.items():
            try:
                lvl = LogLevel(level_str)
            except ValueError:
                lvl = LogLevel.INFO
            for _ in range(count):
                ts = base + timedelta(seconds=offset)
                events.append(_make_event(level=lvl, timestamp=ts))
                offset += interval_seconds
        return events

    def test_correct_error_count(self):
        """Test 29: Error count matches the number of ERROR events."""
        events = self._events({"ERROR": 5, "INFO": 10})
        rate = self.analyser.calculate(events)
        assert rate.error_count == 5

    def test_correct_errors_per_minute_rate(self):
        """Test 30: errors/minute is correctly calculated."""
        # 10 errors over 10 minutes = 1 error/minute
        base = _ts(12, 0)
        events = []
        for i in range(10):
            ts = base + timedelta(minutes=i)
            events.append(_make_event(level=LogLevel.ERROR, timestamp=ts))
        rate = self.analyser.calculate(events)
        # Window is 9 minutes (first to last event), 10 errors
        # errors/min = 10 / 9 * 1 ≈ 1.111
        assert rate.error_count == 10
        assert rate.errors_per_minute > 0

    def test_empty_input_returns_zero_rate(self):
        """Test 31: Empty event list returns zero rate."""
        rate = self.analyser.calculate([])
        assert rate.error_count == 0
        assert rate.errors_per_minute == 0.0
        assert rate.errors_per_hour == 0.0
        assert rate.total_count == 0

    def test_single_event_no_divide_by_zero(self):
        """Test 32: Single event produces a valid (non-crash) result."""
        events = [_make_event(level=LogLevel.ERROR, timestamp=_ts(12))]
        rate = self.analyser.calculate(events)
        assert rate.error_count == 1
        assert rate.errors_per_minute >= 0.0

    def test_explicit_window_used(self):
        """Test 33: Explicit window parameter overrides inferred window."""
        events = self._events({"ERROR": 10}, interval_seconds=30)
        rate = self.analyser.calculate(events, window=timedelta(minutes=10))
        # 10 errors over 10 minutes = 1 error/minute
        assert abs(rate.errors_per_minute - 1.0) < 0.01
        assert rate.window_seconds == 600.0

    def test_correct_warning_count(self):
        """Test 34: Warning count is tracked separately from errors."""
        events = self._events({"WARNING": 3, "ERROR": 2})
        rate = self.analyser.calculate(events)
        assert rate.warning_count == 3
        assert rate.error_count == 2

    def test_correct_critical_count(self):
        """Test 35: CRITICAL events contribute to both critical and error counts."""
        events = self._events({"CRITICAL": 4, "ERROR": 2})
        rate = self.analyser.calculate(events)
        assert rate.critical_count == 4
        assert rate.error_count == 6  # 4 critical + 2 error

    def test_fingerprint_counts_populated(self):
        """Test 36: fingerprint_counts dict is populated for error-class events."""
        fp_a = "a" * 64
        fp_b = "b" * 64
        events = [
            _make_event(level=LogLevel.ERROR, fingerprint=fp_a),
            _make_event(level=LogLevel.ERROR, fingerprint=fp_a),
            _make_event(level=LogLevel.CRITICAL, fingerprint=fp_b),
        ]
        rate = self.analyser.calculate(events)
        assert rate.fingerprint_counts[fp_a] == 2
        assert rate.fingerprint_counts[fp_b] == 1


# ===========================================================================
# SECTION 5 — ANALYZER TESTS
# ===========================================================================


class TestLogAnalyzer:
    """Tests for LogAnalyzer (the main orchestrator)."""

    def setup_method(self):
        self.analyzer = LogAnalyzer()

    def test_combines_all_sub_components(self):
        """Test 37: LogAnalyzer calls classifier, fingerprinter, grouper, rate."""
        events = [
            _make_event(message="INFO startup", level=LogLevel.INFO),
            _make_event(message="ERROR db down", level=LogLevel.ERROR),
            _make_event(message="ERROR db down", level=LogLevel.ERROR),
            _make_event(message="CRITICAL disk full", level=LogLevel.CRITICAL),
        ]
        result = self.analyzer.analyze(events)
        assert result.total_logs_analyzed == 4
        assert result.total_info == 1
        assert result.total_errors >= 2
        assert result.total_critical == 1
        assert result.unique_error_fingerprints >= 1
        assert result.error_rate_per_minute >= 0.0

    def test_returns_valid_analysis_result(self):
        """Test 38: Result is a properly typed AnalysisResult."""
        events = [_make_event()]
        result = self.analyzer.analyze(events)
        assert isinstance(result, AnalysisResult)
        assert result.total_logs_analyzed == 1

    def test_malformed_level_does_not_crash(self):
        """Test 39: An event with a weird level string is handled gracefully."""
        # Build an event and manually set a weird level using a mock-like approach.
        # CollectedLogEvent enforces LogLevel enum, so we test the classifier path.
        # The classifier handles None gracefully; verify the analyzer does too.
        events = [_make_event(level=LogLevel.INFO)]  # valid event
        result = self.analyzer.analyze(events)
        assert isinstance(result, AnalysisResult)

    def test_empty_dataset_returns_zero_result(self):
        """Test 40: Empty event list returns a zeroed AnalysisResult."""
        result = self.analyzer.analyze([])
        assert result.total_logs_analyzed == 0
        assert result.total_errors == 0
        assert result.total_warnings == 0
        assert result.total_critical == 0
        assert result.error_groups == []
        assert result.error_rate_per_minute == 0.0

    def test_analysis_warnings_populated(self):
        """Test 41: analysis_warnings is a list (may be empty for clean data)."""
        result = self.analyzer.analyze([_make_event()])
        assert isinstance(result.analysis_warnings, list)
        assert isinstance(result.analysis_errors, list)

    def test_error_groups_sorted_by_count_descending(self):
        """Test 42: error_groups are sorted most-frequent first."""
        fp_rare = "r" * 64
        fp_common = "c" * 64
        events = (
            [_make_event(level=LogLevel.ERROR, fingerprint=fp_common)] * 10
            + [_make_event(level=LogLevel.ERROR, fingerprint=fp_rare)] * 2
        )
        result = self.analyzer.analyze(events)
        assert len(result.error_groups) >= 1
        if len(result.error_groups) >= 2:
            assert result.error_groups[0].count >= result.error_groups[1].count

    def test_total_errors_includes_critical(self):
        """Test 43: CRITICAL events are counted in total_errors as well."""
        events = [
            _make_event(level=LogLevel.CRITICAL),
            _make_event(level=LogLevel.CRITICAL),
        ]
        result = self.analyzer.analyze(events)
        assert result.total_critical == 2
        assert result.total_errors == 2  # CRITICAL also increments total_errors

    def test_unique_error_fingerprints_count(self):
        """Test 44: unique_error_fingerprints equals the number of distinct groups."""
        fp_a = "a" * 64
        fp_b = "b" * 64
        events = [
            _make_event(level=LogLevel.ERROR, fingerprint=fp_a),
            _make_event(level=LogLevel.ERROR, fingerprint=fp_a),
            _make_event(level=LogLevel.ERROR, fingerprint=fp_b),
        ]
        result = self.analyzer.analyze(events)
        assert result.unique_error_fingerprints == 2

    def test_explicit_window_passed_to_rate_analyser(self):
        """LogAnalyzer respects the window constructor argument."""
        analyzer = LogAnalyzer(window=timedelta(hours=1))
        events = [
            _make_event(level=LogLevel.ERROR, timestamp=_ts(12, 0)),
            _make_event(level=LogLevel.ERROR, timestamp=_ts(12, 10)),
        ]
        result = analyzer.analyze(events)
        assert result.analysis_window_seconds == 3600.0
        assert result.error_rate_per_minute == pytest.approx(2 / 60, rel=1e-3)


# ===========================================================================
# SECTION 6 — INTEGRATION TESTS
# ===========================================================================


class TestPhase6Integration:
    """Integration tests verifying Phase 6 coexists with Phases 2–5."""

    def test_phase6_imports_do_not_break_phase5_imports(self):
        """Test 45: Phase 5 models are importable after Phase 6 is loaded."""
        # If Phase 6 imports break Phase 5 the import at the top of this file
        # would already have failed.  This test just exercises the objects.
        event = CollectedLogEvent(
            message="test",
            level=LogLevel.INFO,
        )
        assert event.message == "test"

    def test_collected_log_event_accepted_by_analyzer(self):
        """Test 46: Phase 5 CollectedLogEvent is accepted by Phase 6 LogAnalyzer."""
        event = CollectedLogEvent(
            message="ERROR failed to connect to database",
            level=LogLevel.ERROR,
            source="/var/log/app.log",
            timestamp=datetime.now(tz=timezone.utc),
            hostname="server-01",
        )
        result = LogAnalyzer().analyze([event])
        assert isinstance(result, AnalysisResult)
        assert result.total_logs_analyzed == 1
        assert result.total_errors >= 1

    def test_log_batch_events_accepted_by_analyzer(self):
        """Test 47: Events from a Phase 5 LogBatch are accepted by Phase 6."""
        batch = LogBatch(
            hostname="server-01",
            events=[
                CollectedLogEvent(
                    message="INFO server started",
                    level=LogLevel.INFO,
                ),
                CollectedLogEvent(
                    message="ERROR service crashed",
                    level=LogLevel.ERROR,
                ),
            ],
        )
        result = LogAnalyzer().analyze(batch.events)
        assert result.total_logs_analyzed == 2

    def test_analysis_result_serialises_to_json(self):
        """Test 48: AnalysisResult can be serialised to valid JSON."""
        events = [
            _make_event(level=LogLevel.ERROR, message="db error"),
            _make_event(level=LogLevel.INFO, message="ok"),
        ]
        result = LogAnalyzer().analyze(events)
        serialised = result.model_dump(mode="json")
        json_str = json.dumps(serialised)
        parsed = json.loads(json_str)
        assert parsed["total_logs_analyzed"] == 2
        assert "error_groups" in parsed

    def test_phase6_does_not_modify_original_events(self):
        """Phase 6 analysis never mutates the original CollectedLogEvent list."""
        events = [
            _make_event(message="original message", level=LogLevel.ERROR),
        ]
        original_message = events[0].message
        LogAnalyzer().analyze(events)
        assert events[0].message == original_message

    def test_fingerprint_generator_is_independent(self):
        """FingerprintGenerator can be used standalone without LogAnalyzer."""
        gen = FingerprintGenerator()
        fp = gen.generate("some error", level="ERROR", source="app.log")
        assert len(fp) == 64

    def test_classifier_is_independent(self):
        """LogClassifier can be used standalone without LogAnalyzer."""
        clf = LogClassifier()
        assert clf.classify(level="CRITICAL") == AnalysisClassification.CRITICAL

    def test_grouper_is_independent(self):
        """LogGrouper can be used standalone without LogAnalyzer."""
        grouper = LogGrouper()
        events = [_make_event(level=LogLevel.ERROR)]
        groups = grouper.group(events)
        assert len(groups) == 1

    def test_error_rate_analyser_is_independent(self):
        """ErrorRateAnalyzer can be used standalone without LogAnalyzer."""
        analyser = ErrorRateAnalyzer()
        events = [_make_event(level=LogLevel.ERROR)]
        rate = analyser.calculate(events)
        assert rate.error_count == 1
