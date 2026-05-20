"""
Tests for authentication routes.

Tests the OAuth flow endpoints for Gmail authentication.
"""
import pytest
from unittest.mock import patch, MagicMock


class TestLoginRedirect:
    """Tests for /auth/gmail/login endpoint."""

    def test_login_returns_auth_url(self, test_client_with_mock_settings):
        """
        Verify that /auth/gmail/login returns a valid auth URL.
        The auth URL should be a Google OAuth redirect URL.
        """
        response = test_client_with_mock_settings.get("/auth/gmail/login")

        assert response.status_code == 200

        data = response.json()
        assert "auth_url" in data

        # Auth URL should be a Google OAuth URL
        auth_url = data["auth_url"]
        assert auth_url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")

        # Should contain client_id parameter
        assert "client_id" in auth_url

    def test_login_returns_session_id(self, test_client_with_mock_settings):
        """
        Verify that /auth/gmail/login returns a session_id.
        """
        response = test_client_with_mock_settings.get("/auth/gmail/login")

        assert response.status_code == 200

        data = response.json()
        assert "session_id" in data
        assert len(data["session_id"]) > 0

    def test_login_returns_callback_url(self, test_client_with_mock_settings):
        """
        Verify that /auth/gmail/login returns a callback_url.
        """
        response = test_client_with_mock_settings.get("/auth/gmail/login")

        assert response.status_code == 200

        data = response.json()
        assert "callback_url" in data
        assert "localhost" in data["callback_url"]
        assert "/auth/gmail/callback" in data["callback_url"]