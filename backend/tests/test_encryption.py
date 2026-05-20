"""
Tests for encryption service.

Tests the encryption utilities used for secure token storage.
"""
import pytest
from services import encryption


class TestGenerateKey:
    """Tests for generate_key function."""

    def test_generate_key_returns_string(self):
        """
        Verify that generate_key returns a string.
        """
        key = encryption.generate_key()
        assert isinstance(key, str)

    def test_generate_key_returns_non_empty(self):
        """
        Verify that generate_key returns a non-empty string.
        """
        key = encryption.generate_key()
        assert len(key) > 0

    def test_generate_key_returns_different_keys(self):
        """
        Verify that generate_key returns different keys on each call.
        """
        key1 = encryption.generate_key()
        key2 = encryption.generate_key()
        assert key1 != key2


class TestEncryptDecryptRoundtrip:
    """Tests for encrypt_token and decrypt_token roundtrip."""

    def test_encrypt_decrypt_returns_original(self, mock_settings):
        """
        Verify that encrypting and then decrypting returns the original token.
        """
        original_token = "test-access-token-12345"
        key = encryption.generate_key()

        encrypted = encryption.encrypt_token(original_token, key)
        decrypted = encryption.decrypt_token(encrypted, key)

        assert decrypted == original_token

    def test_encrypt_produces_different_output(self, mock_settings):
        """
        Verify that encryption produces output different from the original.
        """
        original_token = "test-token"
        key = encryption.generate_key()

        encrypted = encryption.encrypt_token(original_token, key)

        assert encrypted != original_token


class TestDecryptInvalidToken:
    """Tests for decrypt_token with invalid inputs."""

    def test_decrypt_invalid_token_returns_none(self):
        """
        Verify that decrypting an invalid token returns None.
        """
        key = encryption.generate_key()
        result = encryption.decrypt_token("invalid-base64-string", key)
        assert result is None

    def test_decrypt_wrong_key_returns_none(self):
        """
        Verify that decrypting with wrong key returns None.
        """
        original_token = "test-token"
        key1 = encryption.generate_key()
        key2 = encryption.generate_key()

        encrypted = encryption.encrypt_token(original_token, key1)
        result = encryption.decrypt_token(encrypted, key2)

        assert result is None

    def test_decrypt_empty_string_returns_none(self):
        """
        Verify that decrypting an empty string returns None.
        """
        key = encryption.generate_key()
        result = encryption.decrypt_token("", key)
        assert result is None