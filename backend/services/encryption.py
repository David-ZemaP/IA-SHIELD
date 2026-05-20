"""
Encryption utilities for token security.
Uses Fernet (symmetric encryption) for secure token storage.
"""
import base64
from cryptography.fernet import Fernet, InvalidToken
from typing import Optional


def generate_key() -> str:
    """
    Generate a 32-byte key for Fernet encryption.
    Returns the key as a base64-encoded string.
    """
    key = Fernet.generate_key()
    return base64.urlsafe_b64encode(key).decode()


def encrypt_token(token: str, key: str) -> str:
    """
    Encrypt a token using the provided key.

    Args:
        token: The token string to encrypt
        key: Base64-encoded key string

    Returns:
        Encrypted token as a base64-encoded string
    """
    key_bytes = base64.urlsafe_b64decode(key.encode())
    f = Fernet(key_bytes)
    encrypted = f.encrypt(token.encode())
    return base64.urlsafe_b64encode(encrypted).decode()


def decrypt_token(encrypted: str, key: str) -> Optional[str]:
    """
    Decrypt an encrypted token using the provided key.

    Args:
        encrypted: The encrypted token string (base64-encoded)
        key: Base64-encoded key string

    Returns:
        The original token string, or None if decryption fails
    """
    try:
        key_bytes = base64.urlsafe_b64decode(key.encode())
        f = Fernet(key_bytes)
        decrypted = f.decrypt(base64.urlsafe_b64decode(encrypted.encode()))
        return decrypted.decode()
    except (InvalidToken, ValueError):
        return None