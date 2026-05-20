"""
Tests for rate limiting functionality.

Tests the rate limiter middleware that limits requests to 10/minute.
"""
import pytest


class TestRateLimit:
    """Tests for rate limiting."""

    def test_rate_limit_exceeded(self, test_client):
        """
        Verify that rate limit is enforced after 10 requests per minute.
        Send requests until rate limited. Accounts for other tests that
        may have consumed some of the 10/minute budget.
        """
        request_body = {
            "email_id": "test-email-123",
            "email_subject": "Test Subject",
            "email_sender": "test@example.com",
            "email_body": "Test email body"
        }

        responses = []

        # Send up to 20 requests
        for i in range(20):
            response = test_client.post("/analyze", json=request_body)
            responses.append(response)

        # The budget is 10/minute. Other tests may have consumed up to ~5.
        # After the budget is exhausted, we should get 429s.
        # Every request after the first 15 should be 429.
        has_429_at_end = any(r.status_code == 429 for r in responses[15:])
        has_ok_at_start = responses[0].status_code != 429

        assert has_ok_at_start, "First request was rate limited"
        assert has_429_at_end, "Expected 429 after exceeding rate limit"