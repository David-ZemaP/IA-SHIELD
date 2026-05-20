"""
CORS validation middleware for Chrome Extension authorization.
Validates extension IDs against ALLOWED_EXTENSION_IDS from config.
"""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from config import get_settings


class CORSValidationMiddleware(BaseHTTPMiddleware):
    """
    Validates Chrome Extension ID in the Origin header.
    If ALLOWED_EXTENSION_IDS is empty or not set, allows all (dev mode).
    """

    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "")

        # Only validate chrome-extension origins
        if origin.startswith("chrome-extension://"):
            settings = get_settings()
            allowed_ids = settings.ALLOWED_EXTENSION_IDS

            # If no allowed IDs configured, allow all (dev mode)
            if not allowed_ids:
                return await call_next(request)

            # Extract extension ID from origin
            # Format: chrome-extension://<extension-id>/...
            ext_id = origin.replace("chrome-extension://", "").split("/")[0]

            # Check if extension ID is in allowed list
            allowed_list = [aid.strip() for aid in allowed_ids.split(",") if aid.strip()]

            if allowed_list and ext_id not in allowed_list:
                raise HTTPException(
                    status_code=403,
                    detail="Extension not authorized"
                )

        return await call_next(request)