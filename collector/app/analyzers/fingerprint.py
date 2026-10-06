"""
OpsTrace Collector — Error Fingerprint Generator
Phase 6: Log Analysis & Intelligence

Deterministic fingerprint generation for log events.

Purpose:
  Produce a short, stable identifier that groups log messages representing
  the *same underlying error* even when dynamic values (user IDs, IP
  addresses, timestamps, hex hashes, etc.) differ between occurrences.

Approach:
  1. Normalise the message by replacing common dynamic tokens with
     fixed placeholders using pre-compiled regular expressions.
  2. Lower-case and strip the normalised text.
  3. Compute SHA-256 of the canonical string.
  4. Return the first 64 hex characters (256 bits → 64 hex digits).

The normalisation step is intentionally conservative:
  - Only well-known dynamic patterns (UUIDs, IPs, long numbers, hex IDs,
    ISO timestamps) are replaced.
  - Normal dictionary words are NOT touched.
  - The result is human-readable after normalisation, aiding debugging.

Security:
  - No shell commands are derived from log message content.
  - hashlib.sha256 is a one-way function; raw message content is not
    reconstructable from the fingerprint.

Example::

    gen = FingerprintGenerator()
    fp1 = gen.generate("Connection to database failed for user 123")
    fp2 = gen.generate("Connection to database failed for user 456")
    assert fp1 == fp2  # dynamic user ID is normalised away
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Normalisation patterns (applied in order)
# ---------------------------------------------------------------------------

# Each entry is (compiled_pattern, replacement_string).
# Order matters: more specific patterns run first.
_NORM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ISO 8601 / RFC 3339 timestamps (e.g. 2024-01-15T12:34:56Z)
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
            re.IGNORECASE,
        ),
        "<timestamp>",
    ),
    # UUIDs (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    (
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        ),
        "<uuid>",
    ),
    # IPv6 addresses (simplified: groups of hex separated by colons)
    (
        re.compile(
            r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b",
            re.IGNORECASE,
        ),
        "<ipv6>",
    ),
    # IPv4 addresses
    (
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        "<ip>",
    ),
    # Long hex strings (≥8 hex chars that look like IDs/hashes)
    (
        re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE),
        "<hex>",
    ),
    # Numeric IDs
    # Normalises numeric IDs such as user 123, request 456, PID 99, error code 42
    (
        re.compile(r"\b\d+\b"),
        "<id>",
    ),
]

# After token replacement, collapse multiple whitespace/punctuation runs.
_RE_WHITESPACE = re.compile(r"\s+")


def _normalise_message(message: str) -> str:
    """
    Apply normalisation patterns to a log message and return the canonical form.

    The result:
      - has all dynamic tokens replaced with typed placeholders,
      - is lower-cased,
      - has collapsed whitespace.

    Args:
        message: Raw log message text (treated as untrusted input; not executed).

    Returns:
        Normalised string suitable for fingerprint hashing.
    """
    text = message
    for pattern, replacement in _NORM_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _RE_WHITESPACE.sub(" ", text).strip().lower()
    return text


# ---------------------------------------------------------------------------
# Public fingerprint generator
# ---------------------------------------------------------------------------


class FingerprintGenerator:
    """
    Deterministic SHA-256 fingerprint generator for log messages.

    A single instance is stateless and can be reused across many calls.

    Example::

        gen = FingerprintGenerator()
        fp = gen.generate("ERROR Database connection refused for user 42")
        assert len(fp) == 64  # 64 hex chars = 256-bit SHA-256
    """

    def generate(
        self,
        message: Optional[str],
        level: Optional[str] = None,
        source: Optional[str] = None,
    ) -> str:
        """
        Generate a 64-character hex fingerprint for a log event.

        The fingerprint is computed from:
          ``<normalised_level>:<source_prefix>:<normalised_message>``

        where:
          - ``normalised_level`` is the upper-cased level string (or ``UNKNOWN``).
          - ``source_prefix`` is the first 50 characters of the source identifier
            (file path, journal unit, etc.) — captures the error's origin without
            being sensitive to exact file positions.
          - ``normalised_message`` is the message after dynamic-token removal.

        Args:
            message: Log message body.  None or empty → fingerprint of empty string.
            level:   Log severity level string (optional, strengthens grouping).
            source:  Log source identifier (optional, strengthens grouping).

        Returns:
            64-character lowercase hex string (SHA-256 digest).
            Never raises; returns the fingerprint of an empty canonical string
            on unexpected errors.
        """
        try:
            norm_msg = _normalise_message(message or "")
            norm_level = (level or "unknown").strip().upper()
            norm_source = (source or "")[:50]
            canonical = f"{norm_level}:{norm_source}:{norm_msg}"
            digest = hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()
            return digest[:64]
        except Exception as exc:  # pragma: no cover — defensive
            logger.error("FingerprintGenerator.generate unexpected error: %s", exc)
            # Return a stable sentinel; callers treat this as a fallback fingerprint.
            return hashlib.sha256(b"").hexdigest()[:64]

    def normalise(self, message: Optional[str]) -> str:
        """
        Return the normalised (dynamic-token-removed) form of a message.

        Exposed for testing and debugging; not required by the main analysis flow.

        Args:
            message: Raw log message text.

        Returns:
            Normalised string with dynamic tokens replaced by placeholders.
        """
        return _normalise_message(message or "")
