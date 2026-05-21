"""
Gemini v2 — Enhanced phishing analysis with structured output, caching, and few-shot prompting.

Feature-gated by GEMINI_USE_V2 env var (default false).
Falls back to v1 (gemini_service.analyze_email) on any failure.
Zero changes to existing v1 behavior.
"""
import hashlib
import json
import os
import re
from functools import lru_cache
from typing import Optional

import httpx

from config import get_settings

# Gemini API config
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

# Few-shot examples — real phishing patterns
FEW_SHOT_EXAMPLES = """
EJEMPLOS DE ANÁLISIS:

Email 1:
DE: soporte@paypa1-security.com
ASUNTO: Tu cuenta ha sido suspendida — Verifica ahora
CONTENIDO: Estimado usuario, hemos detectado actividad inusual. Haz click aquí para verificar tu identidad: http://paypa1-verify.xyz/login
→ verdict: "phishing", confidence: 0.20, reason: "Domain spoofing + urgency + suspicious TLD"

Email 2:
DE: noreply@google.com
ASUNTO: Security alert for your Google Account
CONTENIDO: We noticed a new sign-in to your Google Account on a Windows device. If this was you, no action is needed.
→ verdict: "safe", confidence: 0.90, reason: "Legitimate security notification from known sender"

Email 3:
DE: alerts@banco-santander-verify.tk
ASUNTO: Confirmación de identidad requerida
CONTENIDO: Por su seguridad, necesitamos que confirme sus datos bancarios en las próximas 24 horas o su cuenta será bloqueada.
→ verdict: "phishing", confidence: 0.92, reason: "Brand impersonation + urgency + suspicious TLD + data harvesting"
"""

# System prompt for v2
SYSTEM_PROMPT_V2 = f"""Eres un detector experto de phishing. Analiza emails con precisión.

RESPONDE SOLO CON ESTE JSON EXACTO (sin texto antes ni después):
{{"verdict":"safe","confidence":0.0,"reason":"una frase breve","indicators":["max 3 palabras clave"]}}

Rules:
- verdict: "safe" | "suspicious" | "phishing"
- confidence: 0.0 a 1.0 — representa "qué tan confiable es este email":
  · safe → 0.85 a 0.95 (email legítimo, confiable)
  · suspicious → 0.40 a 0.70 (dudoso, no te confíes)
  · phishing → 0.10 a 0.35 (peligroso, no confiar)
- reason: una frase breve en español
- indicators: hasta 3 banderas rojas específicas
- NO inventes indicadores que no existen

{FEW_SHOT_EXAMPLES}
"""


def _cache_key(sender: str, subject: str, body: str) -> str:
    """Generate a cache key from email content."""
    content = f"{sender}|{subject}|{body[:2000]}"
    return hashlib.sha256(content.encode()).hexdigest()


# LRU cache for analysis results (max 256 entries)
_analysis_cache: dict = {}
_CACHE_MAX_SIZE = 256
_CACHE_TTL = 300  # 5 minutes


def _get_cached(key: str) -> Optional[dict]:
    """Get cached result if still valid."""
    import time
    entry = _analysis_cache.get(key)
    if entry and (time.time() - entry["timestamp"]) < _CACHE_TTL:
        return entry["result"]
    # Evict expired
    if key in _analysis_cache:
        del _analysis_cache[key]
    return None


def _set_cache(key: str, result: dict):
    """Store result in cache with eviction."""
    import time
    if len(_analysis_cache) >= _CACHE_MAX_SIZE:
        # Evict oldest
        oldest_key = min(_analysis_cache, key=lambda k: _analysis_cache[k]["timestamp"])
        del _analysis_cache[oldest_key]
    _analysis_cache[key] = {"result": result, "timestamp": time.time()}


def call_gemini_v2(email_content: str, sender: str = "", subject: str = "") -> Optional[dict]:
    """
    Call Gemini v2 with structured output prompt.
    Returns parsed result dict or None on failure.
    """
    settings = get_settings()
    api_key = getattr(settings, "GEMINI_API_KEY", "")

    if not api_key:
        return None

    # Check cache first
    key = _cache_key(sender, subject, email_content)
    cached = _get_cached(key)
    if cached:
        return cached

    prompt = f"""{SYSTEM_PROMPT_V2}

---
Email A ANALIZAR:
DE: {sender if sender else 'Desconocido'}
ASUNTO: {subject if subject else 'Sin asunto'}
CONTENIDO: {email_content[:6000] if email_content else '(vacio)'}

Responde solo JSON."""

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 512
        }
    }

    try:
        response = httpx.post(
            f"{GEMINI_API_URL}?key={api_key}",
            json=payload,
            timeout=20.0
        )

        if response.status_code != 200:
            return None

        data = response.json()
        if "candidates" not in data or not data["candidates"]:
            return None

        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        text = re.sub(r'^```json\s*', '', text)
        text = re.sub(r'^```\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        text = text.strip()

        json_match = re.search(r'\{[\s\S]*\}', text)
        if not json_match:
            return None

        result = json.loads(json_match.group())

        # Validate required fields
        if "verdict" not in result or "confidence" not in result:
            return None

        parsed = {
            "verdict": result.get("verdict", "review_needed"),
            "confidence": float(result.get("confidence", 0.5)),
            "reason": result.get("reason", ""),
            "indicators": result.get("indicators", [])
        }

        # Cache the result
        _set_cache(key, parsed)

        return parsed

    except Exception:
        return None


def analyze_email_v2(email_content: str, sender: str = "", subject: str = "") -> Optional[dict]:
    """
    Main entry point for Gemini v2 analysis.
    Returns result dict or None (caller should fallback to v1).
    """
    return call_gemini_v2(email_content, sender, subject)


def get_cache_stats() -> dict:
    """Return cache statistics for monitoring."""
    return {
        "size": len(_analysis_cache),
        "max_size": _CACHE_MAX_SIZE,
        "ttl_seconds": _CACHE_TTL
    }
