"""
Pytest configuration and fixtures for IA Shield backend tests.
"""
import sys
import os
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

# Add parent directory to sys.path so tests can import services, middleware, etc.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ----------------------------------------------------------------------
# Mock Settings Fixture
# ----------------------------------------------------------------------
@pytest.fixture
def mock_settings():
    """
    Provides a mock settings object for testing.
    """
    settings = MagicMock()
    settings.GOOGLE_CLIENT_ID = "test-client-id"
    settings.GOOGLE_CLIENT_SECRET = "test-client-secret"
    settings.GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/gmail/callback"
    settings.GEMINI_API_KEY = "test-gemini-key"
    settings.SAFE_BROWSING_API_KEY = "test-safe-browsing-key"
    settings.MCP_SERVER_URL = "http://localhost:9000"
    settings.APP_HOST = "0.0.0.0"
    settings.APP_PORT = 8000
    settings.ALLOWED_EXTENSION_IDS = "test-extension-id"
    settings.TOKEN_ENCRYPTION_KEY = "test-encryption-key"
    return settings


@pytest.fixture
def mock_settings_dependency(mock_settings):
    """
    Patches get_settings to return mock settings.
    """
    with patch("config.get_settings", return_value=mock_settings):
        yield mock_settings


# ----------------------------------------------------------------------
# Mock HTTP Client Fixture
# ----------------------------------------------------------------------
@pytest.fixture
def mock_http_client():
    """
    Provides a mock HTTP client for testing external calls.
    """
    client = MagicMock()
    return client


@pytest.fixture
def mock_httpx_response():
    """
    Provides a mock httpx response object.
    """
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"success": True, "data": "test"}
    return response


# ----------------------------------------------------------------------
# Test Client Fixture
# ----------------------------------------------------------------------
@pytest.fixture
def test_client():
    """
    Provides a FastAPI test client.
    Imports the app from main.py and creates a TestClient.
    """
    from main import app
    return TestClient(app)


@pytest.fixture
def test_client_with_mock_settings(mock_settings):
    """
    Provides a FastAPI test client with mocked settings.
    """
    with patch("config.get_settings", return_value=mock_settings):
        from main import app
        yield TestClient(app)