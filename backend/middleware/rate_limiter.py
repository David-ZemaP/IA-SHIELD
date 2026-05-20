"""
Rate limiting middleware using slowapi.
Limits requests to 10 per minute on protected endpoints.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import Request
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse


# Use IP-based rate limiting
limiter = Limiter(key_func=get_remote_address)


@limiter.limit("10/minute")
async def rate_limited_request(request: Request):
    """Rate limited request handler."""
    pass


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    """Custom handler for rate limit exceeded errors."""
    return JSONResponse(
        status_code=429,
        content={"detail": "Rate limit exceeded, try again later"}
    )