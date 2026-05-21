"""
Tests for anomaly detection service.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.anomaly_detector import (
    score_anomaly, record_pattern, _levenshtein_distance,
    _similarity, _normalize_sender, _sender_counts, _sender_subjects
)


@pytest.fixture
def clear_patterns():
    """Clear pattern data before and after each test."""
    _sender_counts.clear()
    _sender_subjects.clear()
    yield
    _sender_counts.clear()
    _sender_subjects.clear()


class TestLevenshtein:
    """Tests for Levenshtein distance."""

    def test_identical_strings(self):
        assert _levenshtein_distance("hello", "hello") == 0

    def test_completely_different(self):
        assert _levenshtein_distance("abc", "xyz") == 3

    def test_one_edit(self):
        assert _levenshtein_distance("kitten", "sitten") == 1


class TestSimilarity:
    """Tests for similarity calculation."""

    def test_identical(self):
        assert _similarity("hello", "hello") == 1.0

    def test_empty(self):
        assert _similarity("", "") == 1.0

    def test_similar(self):
        sim = _similarity("paypal", "paypa1")
        assert sim > 0.8  # Very similar


class TestNormalizeSender:
    """Tests for sender normalization."""

    def test_email_only(self):
        assert _normalize_sender("test@example.com") == "test@example.com"

    def test_name_and_email(self):
        assert _normalize_sender("John Doe <test@example.com>") == "test@example.com"

    def test_case_insensitive(self):
        assert _normalize_sender("TEST@EXAMPLE.COM") == "test@example.com"


class TestScoreAnomaly:
    """Tests for anomaly scoring."""

    def test_unknown_sender(self, clear_patterns):
        """Unknown sender gets moderate anomaly score."""
        score = score_anomaly("unknown@newdomain.com", "Test subject")
        assert score > 0.3  # Unknown sender should have some anomaly

    def test_known_sender(self, clear_patterns):
        """Known sender gets lower anomaly score."""
        # Pre-populate with known sender
        for _ in range(5):
            record_pattern("known@example.com", "Regular newsletter")

        score = score_anomaly("known@example.com", "Regular newsletter")
        assert score < 0.5  # Known sender should be less anomalous

    def test_unusual_hour(self, clear_patterns):
        """Email at unusual hour gets higher time score."""
        score = score_anomaly(
            "test@example.com",
            "Subject",
            analyzed_at="2026-05-21T03:00:00Z"  # 3am
        )
        assert score > 0.1  # Should have some time anomaly

    def test_normal_hour(self, clear_patterns):
        """Email at normal hour gets low time score."""
        score = score_anomaly(
            "test@example.com",
            "Subject",
            analyzed_at="2026-05-21T14:00:00Z"  # 2pm
        )
        # Time score should be 0 for business hours
        assert score < 0.5


class TestRecordPattern:
    """Tests for pattern recording."""

    def test_record_increments_count(self, clear_patterns):
        """Recording a sender increments its count."""
        record_pattern("test@example.com", "Subject")
        assert _sender_counts["test@example.com"] == 1

        record_pattern("test@example.com", "Subject 2")
        assert _sender_counts["test@example.com"] == 2

    def test_record_stores_subject(self, clear_patterns):
        """Recording stores the subject for similarity checks."""
        record_pattern("test@example.com", "Hello World")
        assert "Hello World" in _sender_subjects["test@example.com"]

    def test_record_limits_subjects(self, clear_patterns):
        """Recording limits subjects to last 20 per sender."""
        for i in range(25):
            record_pattern("test@example.com", f"Subject {i}")

        assert len(_sender_subjects["test@example.com"]) == 20
