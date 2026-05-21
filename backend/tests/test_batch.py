"""
Tests for batch analysis service.
"""
import os
import sys
import pytest
import asyncio
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.batch_analyzer import (
    BatchJob, submit_batch, get_batch_status,
    cleanup_old_batches, get_batch_count, _batch_jobs
)


@pytest.fixture
def clear_batches():
    """Clear batch jobs before and after each test."""
    _batch_jobs.clear()
    yield
    _batch_jobs.clear()


@pytest.fixture
def mock_settings_batch():
    """Mock settings with USE_BATCH_ANALYSIS=True."""
    settings = MagicMock()
    settings.USE_BATCH_ANALYSIS = True
    settings.GEMINI_USE_V2 = False
    settings.GEMINI_API_KEY = "test-key"
    with patch("services.batch_analyzer.get_settings", return_value=settings):
        yield settings


class TestBatchJob:
    """Tests for BatchJob creation."""

    def test_batch_job_init(self):
        """BatchJob initializes with correct defaults."""
        emails = [{"email_id": "1"}, {"email_id": "2"}]
        job = BatchJob("test-batch", emails)

        assert job.batch_id == "test-batch"
        assert job.total == 2
        assert job.completed == 0
        assert job.status == "processing"
        assert job.results == []
        assert job.error is None


class TestSubmitBatch:
    """Tests for batch submission."""

    def test_submit_batch_returns_id(self, mock_settings_batch, clear_batches):
        """submit_batch returns a valid batch_id."""
        emails = [{"email_id": "test-1", "email_body": "Hello", "email_sender": "test@test.com", "email_subject": "Test"}]

        with patch("services.batch_analyzer.asyncio.create_task"):
            batch_id = submit_batch(emails)

        assert batch_id is not None
        assert batch_id in _batch_jobs

    def test_submit_batch_stores_job(self, mock_settings_batch, clear_batches):
        """submit_batch stores the job with correct data."""
        emails = [
            {"email_id": "test-1", "email_body": "Body 1"},
            {"email_id": "test-2", "email_body": "Body 2"},
        ]

        with patch("services.batch_analyzer.asyncio.create_task"):
            batch_id = submit_batch(emails)

        job = _batch_jobs[batch_id]
        assert job.total == 2
        assert len(job.emails) == 2


class TestGetBatchStatus:
    """Tests for batch status retrieval."""

    def test_get_status_existing_batch(self, mock_settings_batch, clear_batches):
        """Returns status for existing batch."""
        emails = [{"email_id": "test-1"}]
        with patch("services.batch_analyzer.asyncio.create_task"):
            batch_id = submit_batch(emails)

        status = get_batch_status(batch_id)
        assert status is not None
        assert status["batch_id"] == batch_id
        assert status["total"] == 1

    def test_get_status_nonexistent(self, clear_batches):
        """Returns None for non-existent batch."""
        status = get_batch_status("nonexistent-id")
        assert status is None


class TestBatchCount:
    """Tests for batch count tracking."""

    def test_batch_count(self, mock_settings_batch, clear_batches):
        """Returns correct count of processing batches."""
        emails = [{"email_id": "test-1"}]
        with patch("services.batch_analyzer.asyncio.create_task"):
            submit_batch(emails)
            submit_batch(emails)

        assert get_batch_count() == 2


class TestCleanup:
    """Tests for batch cleanup."""

    def test_cleanup_old_batches(self, clear_batches):
        """Removes batches older than cleanup interval."""
        # Manually insert an old batch
        from datetime import datetime, timezone, timedelta
        old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()

        job = BatchJob("old-batch", [{"email_id": "1"}])
        job.status = "completed"
        job.created_at = old_time
        _batch_jobs["old-batch"] = job

        removed = cleanup_old_batches()
        assert removed == 1
        assert "old-batch" not in _batch_jobs

    def test_cleanup_keeps_recent(self, clear_batches):
        """Keeps batches created within cleanup interval."""
        emails = [{"email_id": "test-1"}]
        with patch("services.batch_analyzer.asyncio.create_task"):
            submit_batch(emails)

        removed = cleanup_old_batches()
        assert removed == 0
        assert get_batch_count() == 1
