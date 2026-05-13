import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException, Query
from fastapi.responses import RedirectResponse

from services import oauth_service
from models.schemas import AuthStatus, TokenRequest, TokenResponse
from config import get_settings

router = APIRouter()

# In-memory token storage (prototype)
# Format: {session_id: {access_token, refresh_token, expires_at, email}}
sessions_store: dict = {}

# Temporary storage for PKCE (session_id -> {code_verifier, state})
pkce_store: dict = {}


@router.get("/gmail/login")
async def gmail_login(request: Request, response: Response):
    """
    Start OAuth flow. Returns the Google auth URL.
    The extension will open this URL in a popup window.
    """
    # Generate session ID
    session_id = secrets.token_urlsafe(32)

    # Generate PKCE pair
    code_verifier, code_challenge = oauth_service.generate_pkce_pair()

    # Generate state
    state = secrets.token_urlsafe(32)

    # Store PKCE data
    pkce_store[session_id] = {
        "code_verifier": code_verifier,
        "state": state
    }

    # Generate authorization URL
    auth_url = oauth_service.get_authorization_url(code_challenge, state)

    # Set session cookie (will be read by callback)
    response.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=3600 * 24  # 24 hours
    )

    # Return URL to open in popup
    return {
        "session_id": session_id,
        "auth_url": auth_url,
        "callback_url": f"http://localhost:8000/auth/gmail/callback"
    }


@router.get("/gmail/callback")
async def gmail_callback(
    request: Request,
    response: Response,
    code: str = Query(...),
    state: str = Query(...),
    session_id: str = Query(None)  # optional — for extension flow
):
    """
    Exchange authorization code for tokens.
    Extension flow: receives session_id via query param (no cookie in popup context).
    """
    # Get session ID: from query param (extension) or cookie (web browser fallback)
    sid = session_id or request.cookies.get("session_id")

    if not sid or sid not in pkce_store:
        raise HTTPException(status_code=400, detail="Sesión inválida o expirada")

    pkce_data = pkce_store[sid]

    # Verify state
    if state != pkce_data.get("state"):
        raise HTTPException(status_code=400, detail="State mismatch — posible ataque CSRF")

    code_verifier = pkce_data["code_verifier"]

    try:
        # Exchange code for tokens
        tokens = await oauth_service.exchange_code_for_tokens(code, code_verifier)

        # Get user email
        email = await oauth_service.get_user_email(tokens["access_token"])

        # Calculate expiry
        expires_at = datetime.utcnow() + timedelta(seconds=tokens.get("expires_in", 3600))

        # Store session data
        sessions_store[sid] = {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "expires_at": expires_at.isoformat(),
            "email": email
        }

        # Clean up PKCE data
        del pkce_store[sid]

        # Redirect to callback page — popup will detect session from storage
        return RedirectResponse(
            url=f"http://localhost:8000/auth-callback.html?sessionId={sid}&email={email}",
            status_code=302
        )

    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {str(e)}")


@router.get("/gmail/status", response_model=AuthStatus)
async def gmail_status(request: Request):
    """
    Returns authentication status via cookie (web browser flow).
    """
    session_id = request.cookies.get("session_id")

    if not session_id or session_id not in sessions_store:
        return AuthStatus(authenticated=False, email=None)

    session_data = sessions_store[session_id]

    # Check if expired
    expires_at = datetime.fromisoformat(session_data["expires_at"])
    if datetime.utcnow() > expires_at:
        # Try to refresh token
        try:
            new_tokens = await oauth_service.refresh_access_token(session_data["refresh_token"])
            expires_at = datetime.utcnow() + timedelta(seconds=new_tokens.get("expires_in", 3600))

            session_data["access_token"] = new_tokens["access_token"]
            if "refresh_token" in new_tokens:
                session_data["refresh_token"] = new_tokens["refresh_token"]
            session_data["expires_at"] = expires_at.isoformat()
        except Exception:
            # Refresh failed, clear session
            del sessions_store[session_id]
            return AuthStatus(authenticated=False, email=None)

    return AuthStatus(
        authenticated=True,
        email=session_data.get("email")
    )


@router.get("/session/{session_id}")
async def get_session(session_id: str):
    """
    Check if a session_id is valid (extension flow — no cookie needed).
    Returns {valid, email}. Used by popup.js after user reopens the extension.
    """
    if not session_id or session_id not in sessions_store:
        return {"valid": False, "email": None}

    session_data = await get_session_data(session_id)
    if not session_data:
        return {"valid": False, "email": None}

    return {"valid": True, "email": session_data.get("email")}


@router.post("/gmail/logout")
async def gmail_logout(request: Request, response: Response):
    """
    Logout and clear session.
    """
    session_id = request.cookies.get("session_id")

    if session_id:
        if session_id in sessions_store:
            del sessions_store[session_id]
        if session_id in pkce_store:
            del pkce_store[session_id]

    response.delete_cookie("session_id")

    return {"message": "Logged out successfully"}


async def get_session_data(session_id: str) -> Optional[dict]:
    """Helper to get session data if valid."""
    if session_id not in sessions_store:
        return None

    session_data = sessions_store[session_id]

    # Check expiry
    expires_at = datetime.fromisoformat(session_data["expires_at"])
    if datetime.utcnow() > expires_at:
        # Try to refresh
        try:
            new_tokens = await oauth_service.refresh_access_token(session_data["refresh_token"])
            expires_at = datetime.utcnow() + timedelta(seconds=new_tokens.get("expires_in", 3600))

            session_data["access_token"] = new_tokens["access_token"]
            if "refresh_token" in new_tokens:
                session_data["refresh_token"] = new_tokens["refresh_token"]
            session_data["expires_at"] = expires_at.isoformat()
        except Exception:
            # Refresh failed
            del sessions_store[session_id]
            return None

    return session_data


# Export for other routes
async def require_auth(request: Request) -> dict:
    """Dependency to require authentication.

    Accepts session via:
    1. X-Session-ID header (Chrome extension service worker flow)
    2. Cookie (web browser flow)
    """
    # Try header first (extension flow)
    session_id = request.headers.get("x-session-id")
    # Fallback to cookie (web browser flow)
    if not session_id:
        session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(status_code=401, detail="Authentication required")

    session_data = await get_session_data(session_id)

    if not session_data:
        raise HTTPException(status_code=401, detail="Session expired or invalid")

    return session_data