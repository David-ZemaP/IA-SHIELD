"""
Google Safe Browsing API v4 integration.
Lookup API: POST https://safebrowsing.googleapis.com/v4/threatMatches:find
"""
import httpx
import hashlib
from typing import Optional
from cachetools import TTLCache
from config import get_config

# LRU Cache: TTL de 30 min, max 10000 URLs
url_cache: TTLCache = TTLCache(maxsize=10000, ttl=1800)

def hash_url(url: str) -> str:
    """Genera hash SHA-256 de la URL para cachear."""
    return hashlib.sha256(url.encode()).hexdigest()

def verify_url_safebrowsing(url: str) -> dict:
    """
    Verifica una URL contra Google Safe Browsing API.
    Returns: {
        "url": str,
        "malicious": bool,
        "threat_types": list[str],
        "platforms": list[str],
        "cache_hit": bool
    }
    """
    cache_key = hash_url(url)

    # Check cache
    if cache_key in url_cache:
        result = url_cache[cache_key]
        result["cache_hit"] = True
        return result

    config = get_config()
    api_key = config.get("SAFE_BROWSING_API_KEY", "")

    if not api_key:
        # Si no hay API key, retorna "unknown" (no bloqueado, pero sin verificar)
        result = {
            "url": url,
            "malicious": False,
            "threat_types": [],
            "platforms": [],
            "cache_hit": False,
            "error": "SAFE_BROWSING_API_KEY not configured"
        }
        url_cache[cache_key] = result
        return result

    # Build Safe Browsing request
    threat_info = {
        "threatTypes": [
            "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION", "THREAT_TYPE_UNSPECIFIED"
        ],
        "platformTypes": ["ANY_PLATFORM"],
        "threatEntryTypes": ["URL"],
        "threatEntries": [{"url": url}]
    }

    payload = {
        "client": {
            "clientId": "ia-seguridad",
            "clientVersion": "1.0.0"
        },
        "threatInfo": threat_info
    }

    try:
        response = httpx.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=5.0
        )
        response.raise_for_status()
        data = response.json()

        malicious = "matches" in data and len(data["matches"]) > 0

        if malicious:
            threat_types = list(set(m["threatType"] for m in data["matches"]))
            platforms = list(set(p["platformType"] for p in data["matches"]))
        else:
            threat_types = []
            platforms = []

        result = {
            "url": url,
            "malicious": malicious,
            "threat_types": threat_types,
            "platforms": platforms,
            "cache_hit": False
        }

    except httpx.TimeoutException:
        result = {
            "url": url,
            "malicious": False,  # Fail-open para no bloquear legítimas
            "threat_types": [],
            "platforms": [],
            "cache_hit": False,
            "error": "Safe Browsing timeout"
        }
    except Exception as e:
        result = {
            "url": url,
            "malicious": False,
            "threat_types": [],
            "platforms": [],
            "cache_hit": False,
            "error": str(e)
        }

    url_cache[cache_key] = result
    return result

def clear_cache():
    """Limpia el cache de URLs verificadas."""
    url_cache.clear()