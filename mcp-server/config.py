import os
from functools import lru_cache

@lru_cache
def get_config():
    return {
        "SAFE_BROWSING_API_KEY": os.getenv("SAFE_BROWSING_API_KEY", ""),
        "PORT": int(os.getenv("MCP_SERVER_PORT", "9000")),
        "HOST": os.getenv("MCP_SERVER_HOST", "0.0.0.0"),
        # Cache: max 10000 entries, 30 min TTL
        "CACHE_MAX_SIZE": 10000,
        "CACHE_TTL_SECONDS": 1800,
    }