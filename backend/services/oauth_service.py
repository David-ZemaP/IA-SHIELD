import secrets
import base64
import hashlib
import httpx
from typing import Optional
from config import get_settings


def generate_pkce_pair() -> tuple[str, str]:
    """
    Generate PKCE code_verifier and code_challenge.
    - code_verifier: random 64-byte string, base64url encoded
    - code_challenge: base64url(sha256(code_verifier))
    """
    # Generate 64 random bytes
    code_verifier = secrets.token_urlsafe(64)

    # Generate SHA256 hash and base64url encode
    sha256_hash = hashlib.sha256(code_verifier.encode('ascii')).digest()
    code_challenge = base64.urlsafe_b64encode(sha256_hash).decode('ascii').rstrip('=')

    return code_verifier, code_challenge


def get_authorization_url(code_challenge: str, state: str) -> str:
    """Generate Google OAuth authorization URL with PKCE."""
    settings = get_settings()

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.labels",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": state,
        "access_type": "offline",  # Request refresh token
        "prompt": "consent",  # Force consent to get refresh token
    }

    # Build URL manually to ensure proper encoding
    query_string = "&".join(f"{k}={v}" for k, v in params.items())
    return f"https://accounts.google.com/o/oauth2/v2/auth?{query_string}"


async def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    """
    Exchange authorization code for tokens using PKCE.
    Returns: {access_token, refresh_token, expires_in, token_type}
    """
    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code != 200:
            raise Exception(f"Token exchange failed: {response.text}")

        return response.json()


async def refresh_access_token(refresh_token: str) -> dict:
    """Refresh access token using refresh token."""
    settings = get_settings()

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        if response.status_code != 200:
            raise Exception(f"Token refresh failed: {response.text}")

        data = response.json()
        # Google may not return a new refresh token, so keep the old one
        if "refresh_token" not in data:
            data["refresh_token"] = refresh_token

        return data


async def get_user_email(access_token: str) -> str:
    """Get user email from Google OAuth userinfo endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )

        if response.status_code != 200:
            raise Exception(f"Failed to get user email: {response.text}")

        data = response.json()
        return data.get("email", "")