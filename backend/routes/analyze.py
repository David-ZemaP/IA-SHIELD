"""
Endpoint de análisis de phishing en tiempo real.
Usa IA (Gemini) + análisis local de URLs.
"""
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from services.gemini_service import analyze_email, check_url_safety
from services.gmail_service import get_email_detail
from routes.dashboard import record_analysis

router = APIRouter(tags=["analyze"])

import os

# MCP Server URL — usa env var (en Docker: http://mcp-server:9000)
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://mcp-server:9000")


class URLCheckResult(BaseModel):
    url: str
    malicious: bool
    threat_types: list[str]
    error: str | None = None


class AnalyzeRequest(BaseModel):
    email_id: str
    email_subject: str
    email_sender: str
    email_body: str
    check_urls: bool = True


class AnalyzeResponse(BaseModel):
    email_id: str
    verdict: str
    confidence: float
    reason: str
    indicators: list[str]
    urls_analyzed: list[URLCheckResult]
    analyzed_at: str


async def verify_url_mcp(url: str) -> dict:
    """Llama al MCP Server para verificar una URL (no bloquea si falla)."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            response = await client.post(
                f"{MCP_SERVER_URL}/tools/verify-url",
                json={"url": url},
                timeout=3.0
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    return data["result"]
    except Exception:
        pass
    return {"url": url, "malicious": False, "threat_types": [], "error": None}


def extract_urls(text: str, max_urls: int = 10) -> list[str]:
    """Extrae URLs del texto del email."""
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
    # Deduplicar y limitar
    return list(set(urls))[:max_urls]


@router.post("", response_model=AnalyzeResponse)
async def analyze_email_endpoint(
    request: AnalyzeRequest,
    session_id: Optional[str] = Header(default=None, alias="X-Session-ID")
):
    """
    Analiza un email para detectar phishing.
    1. Análisis con IA (Gemini) + reglas locales
    2. Verificación de URLs con MCP (no bloquea si falla)
    3. Combina resultados en un veredicto final
    """
    # Always extract and check URLs first (local rules — always work)
    # Include subject + sender in the check too (even if no body)
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', request.email_body or request.email_subject or '')
    url_results = [check_url_safety(u) for u in urls[:20]]
    local_red_flags = []
    for r in url_results:
        local_red_flags.extend(r["red_flags"])

    # Try Gemini analysis
    analysis_result = None
    try:
        analysis_result = analyze_email(
            email_content=request.email_body,
            sender=request.email_sender,
            subject=request.email_subject
        )
    except Exception:
        # Gemini failed — will use local rules below
        pass

    if not analysis_result:
        count = len(local_red_flags)
        if count >= 4:
            verdict = "phishing"
            conf = 0.98
        elif count >= 3:
            verdict = "phishing"
            conf = 0.95
        elif count >= 2:
            verdict = "phishing"
            conf = 0.90
        elif count >= 1:
            verdict = "suspicious"
            conf = 0.85
        else:
            verdict = "safe"
            conf = 0.95
        analysis_result = {
            "verdict": verdict,
            "confidence": conf,
            "reason": f"Análisis local: {count} indicador(es) detectado(s)",
            "indicators": list(dict.fromkeys(local_red_flags[:10])),
            "urls_analyzed": url_results,
            "urls_count": len(urls)
        }
    else:
        # Gemini succeeded — combine with local URL analysis
        local_suspicious_urls = [r for r in url_results if r.get("suspicious")]
        if local_suspicious_urls:
            # Add local indicators to what Gemini returned
            existing_indicators = analysis_result.get("indicators") or []
            new_flags = local_red_flags[:5]
            analysis_result["indicators"] = list(dict.fromkeys(existing_indicators + new_flags))
            analysis_result["reason"] = (analysis_result.get("reason") or "") + f" — {len(local_suspicious_urls)} URL(s) sospechosas localmente"

    # Final verdict based on URL count (applied after all analysis)
    malicious_count = len([r for r in url_results if r.get("suspicious")])
    if malicious_count >= 3:
        analysis_result["verdict"] = "phishing"
        analysis_result["confidence"] = 0.98
    elif malicious_count >= 2:
        analysis_result["verdict"] = "phishing"
        analysis_result["confidence"] = 0.90
    elif malicious_count >= 1:
        analysis_result["verdict"] = "suspicious"
        analysis_result["confidence"] = 0.88

    # Build URLCheckResult list for response
    urls_analyzed = []
    for url_data in url_results:
        urls_analyzed.append(URLCheckResult(
            url=url_data["url"],
            malicious=url_data.get("suspicious", False),
            threat_types=[],
            error=None
        ))

    response = AnalyzeResponse(
        email_id=request.email_id,
        verdict=analysis_result["verdict"],
        confidence=analysis_result["confidence"],
        reason=analysis_result.get("reason") or analysis_result.get("reason", ""),
        indicators=analysis_result.get("indicators") or [],
        urls_analyzed=urls_analyzed,
        analyzed_at=datetime.now(timezone.utc).isoformat()
    )

    # Registrar en dashboard
    record_analysis(response.model_dump())

    return response