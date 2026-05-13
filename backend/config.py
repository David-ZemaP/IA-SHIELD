from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # OAuth Gmail
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str = "http://localhost:8000/auth/gmail/callback"

    # Gemini
    GEMINI_API_KEY: str

    # Safe Browsing
    SAFE_BROWSING_API_KEY: str

    # MCP Server
    MCP_SERVER_URL: str = "http://localhost:9000"

    # App
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # In-memory token storage (prototype)
    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings():
    return Settings()