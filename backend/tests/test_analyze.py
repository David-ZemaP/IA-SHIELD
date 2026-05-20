"""
Tests for analyze endpoint.

Tests the phishing analysis endpoint functionality.
"""
import pytest
from unittest.mock import patch


class TestAnalyzeEndpoint:
    """Tests for /analyze endpoint."""

    @pytest.mark.xfail(reason="Auth enforcement not yet implemented in /analyze endpoint")
    def test_analyze_endpoint_rejects_no_auth(self, test_client):
        """
        Verify that /analyze endpoint returns 401 without authentication.
        Tests that the endpoint requires a valid session token.
        """
        # Send request without any authentication headers
        response = test_client.post(
            "/analyze",
            json={
                "email_id": "test-email-123",
                "email_subject": "Test Subject",
                "email_sender": "test@example.com",
                "email_body": "This is a test email body with a link https://example.com"
            }
        )

        # Should reject unauthenticated requests
        assert response.status_code == 401

    @pytest.mark.xfail(reason="Auth enforcement not yet implemented in /analyze endpoint")
    def test_analyze_endpoint_rejects_invalid_session(self, test_client):
        """
        Verify that /analyze endpoint returns 401 with invalid session ID.
        """
        response = test_client.post(
            "/analyze",
            json={
                "email_id": "test-email-123",
                "email_subject": "Test Subject",
                "email_sender": "test@example.com",
                "email_body": "Test body"
            },
            headers={"X-Session-ID": "invalid-session-id"}
        )

        # Should reject invalid session
        assert response.status_code == 401

    def test_analyze_requires_valid_json(self, test_client):
        """
        Verify that /analyze endpoint validates request body.
        """
        response = test_client.post(
            "/analyze",
            json={}  # Empty body should fail validation
        )

        # Should return validation error
        assert response.status_code == 422