from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import httpx
import os
import hashlib

router = APIRouter(tags=["mcp"])

# Cache simple en memoria
_url_cache = {}
CACHE_TTL_SECONDS = 1800  # 30 minutos
MAX_CACHE_ENTRIES = 10000

# Safe Browsing API Key
SB_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "")


class VerifyUrlRequest(BaseModel):
    url: str


class VerifyUrlResponse(BaseModel):
    malicious: bool
    threat_type: str | None = None
    platform: str | None = None
    cached: bool = False


def _get_cache_key(url: str) -> str:
    """Normalize URL and return cache key"""
    normalized = url.split('#')[0].split('?')[0]
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


def _is_cache_valid(cache_entry: dict) -> bool:
    import time
    return time.time() - cache_entry.get("cached_at", 0) < CACHE_TTL_SECONDS


@router.post("/verify", response_model=VerifyUrlResponse)
async def verify_url(request: VerifyUrlRequest):
    """
    Verifica una URL usando Google Safe Browsing API v4
    """
    if not SB_API_KEY:
        raise HTTPException(
            status_code=503,
            detail={"error": "config_error", "message": "SB_API_KEY no configurada"}
        )

    url = request.url.strip()
    if not url:
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_url", "message": "URL vacía"}
        )

    # Check cache first
    cache_key = _get_cache_key(url)
    if cache_key in _url_cache:
        cached = _url_cache[cache_key]
        if _is_cache_valid(cached):
            return VerifyUrlResponse(
                malicious=cached["malicious"],
                threat_type=cached.get("threat_type"),
                platform=cached.get("platform"),
                cached=True
            )

    # Prepare Safe Browsing request
    sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SB_API_KEY}"

    payload = {
        "client": {
            "clientId": "ia-seguridad",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(sb_url, json=payload)

            if response.status_code == 200:
                data = response.json()
                matches = data.get("matches", [])

                if matches:
                    # URL is malicious
                    match = matches[0]
                    result = {
                        "malicious": True,
                        "threat_type": match.get("threatType", "MALWARE").replace("SOCIAL_ENGINEERING", "PHISHING"),
                        "platform": match.get("platformType", "ANY_PLATFORM")
                    }
                else:
                    result = {
                        "malicious": False,
                        "threat_type": None,
                        "platform": None
                    }

            elif response.status_code == 403:
                # API key invalid or quota exceeded
                raise HTTPException(
                    status_code=503,
                    detail={"error": "rate_limited", "message": "Safe Browsing API quota agotada"}
                )
            else:
                # Other error - fail open (allow navigation but log)
                result = {"malicious": False, "error": f"http_{response.status_code}"}

    except httpx.TimeoutException:
        # Timeout - fail open
        result = {"malicious": False, "error": "timeout"}
    except Exception as e:
        # Any other error - fail open
        result = {"malicious": False, "error": str(e)}

    # Cache result (even if malicious)
    # Clean cache if too large
    if len(_url_cache) >= MAX_CACHE_ENTRIES:
        # Remove oldest entries
        keys_to_remove = list(_url_cache.keys())[:1000]
        for k in keys_to_remove:
            del _url_cache[k]

    import time
    _url_cache[cache_key] = {
        **result,
        "cached_at": time.time()
    }

    return VerifyUrlResponse(
        malicious=result["malicious"],
        threat_type=result.get("threat_type"),
        platform=result.get("platform"),
        cached=False
    )