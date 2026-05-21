"""
Tests for persistent storage (SQLite dual-write layer).
"""
import os
import sys
import pytest
import tempfile
from unittest.mock import patch, MagicMock

# Add parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage.db import (
    init_db, write_analysis, write_false_positive,
    get_analysis_history, close_db, _db_initialized, _get_db_path
)


@pytest.fixture
def temp_db_dir():
    """Create a temporary directory for test database."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("storage.db._get_db_path", return_value=os.path.join(tmpdir, "test.db")):
            yield tmpdir


@pytest.fixture
def mock_settings_enabled():
    """Mock settings with USE_PERSISTENT_STORAGE=True."""
    settings = MagicMock()
    settings.USE_PERSISTENT_STORAGE = True
    with patch("config.get_settings", return_value=settings):
        yield settings


@pytest.fixture
def mock_settings_disabled():
    """Mock settings with USE_PERSISTENT_STORAGE=False."""
    settings = MagicMock()
    settings.USE_PERSISTENT_STORAGE = False
    with patch("config.get_settings", return_value=settings):
        yield settings


class TestInitDb:
    """Tests for database initialization."""

    def test_init_db_disabled(self, mock_settings_disabled, temp_db_dir):
        """When USE_PERSISTENT_STORAGE=False, init_db returns False and does nothing."""
        # Reset global state
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None

        result = init_db()
        assert result is False
        assert db_module._db_initialized is False

    def test_init_db_enabled_creates_tables(self, mock_settings_enabled, temp_db_dir):
        """When USE_PERSISTENT_STORAGE=True, init_db creates tables."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None

        result = init_db()
        assert result is True
        assert db_module._db_initialized is True

        # Verify tables exist
        cursor = db_module._db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = {row[0] for row in cursor.fetchall()}
        assert "analysis_records" in tables
        assert "false_positives" in tables
        assert "stats_snapshots" in tables

        # Cleanup
        close_db()


class TestWriteAnalysis:
    """Tests for writing analysis records."""

    def test_write_analysis_success(self, mock_settings_enabled, temp_db_dir):
        """Writing an analysis record succeeds and can be retrieved."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None
        init_db()

        record = {
            "id": "test-email-001",
            "email_id": "test-email-001",
            "verdict": "phishing",
            "confidence": 0.95,
            "reason": "Test phishing detection",
            "indicators": ["suspicious_url", "urgency"],
            "urls_analyzed": [{"url": "http://evil.com", "malicious": True}],
            "analyzed_at": "2026-05-21T00:00:00Z",
            "false_positive_reported": False,
        }

        result = write_analysis(record)
        assert result is True

        # Verify retrieval
        history = get_analysis_history()
        assert len(history) == 1
        assert history[0]["id"] == "test-email-001"
        assert history[0]["verdict"] == "phishing"
        assert history[0]["confidence"] == 0.95

        close_db()

    def test_write_analysis_not_initialized(self):
        """Writing when DB not initialized returns False."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None

        result = write_analysis({"id": "test"})
        assert result is False


class TestWriteFalsePositive:
    """Tests for false positive reporting."""

    def test_write_false_positive_success(self, mock_settings_enabled, temp_db_dir):
        """False positive is recorded and analysis is updated."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None
        init_db()

        # First write an analysis
        write_analysis({
            "id": "fp-test-001",
            "email_id": "fp-test-001",
            "verdict": "phishing",
            "confidence": 0.90,
            "reason": "Test",
            "indicators": [],
            "urls_analyzed": [],
            "analyzed_at": "2026-05-21T00:00:00Z",
        })

        # Then report false positive
        result = write_false_positive("fp-test-001", "Legitimate email from my bank")
        assert result is True

        # Verify analysis was updated
        history = get_analysis_history()
        assert len(history) == 1
        assert history[0]["false_positive_reported"] is True
        assert history[0]["false_positive_reason"] == "Legitimate email from my bank"

        close_db()


class TestGetAnalysisHistory:
    """Tests for retrieving analysis history."""

    def test_empty_history(self, mock_settings_enabled, temp_db_dir):
        """Empty database returns empty list."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None
        init_db()

        history = get_analysis_history()
        assert history == []

        close_db()

    def test_history_limit(self, mock_settings_enabled, temp_db_dir):
        """History respects the limit parameter."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None
        init_db()

        # Write 5 records
        for i in range(5):
            write_analysis({
                "id": f"hist-{i}",
                "email_id": f"email-{i}",
                "verdict": "safe",
                "confidence": 0.99,
                "reason": "Test",
                "indicators": [],
                "urls_analyzed": [],
                "analyzed_at": f"2026-05-21T00:00:0{i}Z",
            })

        # Request limit of 3
        history = get_analysis_history(limit=3)
        assert len(history) == 3

        close_db()


class TestCloseDb:
    """Tests for database cleanup."""

    def test_close_db(self, mock_settings_enabled, temp_db_dir):
        """Closing database resets state."""
        import storage.db as db_module
        db_module._db_initialized = False
        db_module._db = None
        init_db()
        assert db_module._db_initialized is True

        close_db()
        assert db_module._db_initialized is False
        assert db_module._db is None
