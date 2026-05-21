"""
Endpoint de análisis de phishing en tiempo real.
Usa IA (Gemini) + análisis local de URLs.
"""
import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

from services.gemini_service import analyze_email, check_url_safety
from services.gemini_v2 import analyze_email_v2
from services.gmail_service import get_email_detail
from routes.dashboard import record_analysis
from middleware.rate_limiter import limiter
from config import get_settings
from services.batch_analyzer import submit_batch, get_batch_status, get_batch_count, get_max_concurrent
from services.anomaly_detector import score_anomaly, record_pattern
from services.rag_service import build_rag_prompt, store_phishing_vector

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
    anomaly_score: Optional[float] = None


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
@limiter.limit("10/minute")
async def analyze_email_endpoint(
    request: Request,
    analyze_request: AnalyzeRequest,
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
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', analyze_request.email_body or analyze_request.email_subject or '')
    url_results = [check_url_safety(u) for u in urls[:20]]
    local_red_flags = []
    for r in url_results:
        local_red_flags.extend(r["red_flags"])

    # Try Gemini analysis (v2 if enabled, fallback to v1)
    analysis_result = None
    try:
        settings = get_settings()
        if getattr(settings, "GEMINI_USE_V2", False):
            # Try v2 first, fallback to v1 on failure
            analysis_result = analyze_email_v2(
                email_content=analyze_request.email_body,
                sender=analyze_request.email_sender,
                subject=analyze_request.email_subject
            )
            if not analysis_result:
                # v2 failed — fallback to v1
                analysis_result = analyze_email(
                    email_content=analyze_request.email_body,
                    sender=analyze_request.email_sender,
                    subject=analyze_request.email_subject
                )
        else:
            # Default: use v1
            analysis_result = analyze_email(
                email_content=analyze_request.email_body,
                sender=analyze_request.email_sender,
                subject=analyze_request.email_subject
            )
    except Exception:
        # Gemini failed — will use local rules below
        pass

    if not analysis_result:
        count = len(local_red_flags)
        if count >= 4:
            verdict = "phishing"
            conf = 0.15
        elif count >= 3:
            verdict = "phishing"
            conf = 0.25
        elif count >= 2:
            verdict = "phishing"
            conf = 0.35
        elif count >= 1:
            verdict = "suspicious"
            conf = 0.55
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
            existing_indicators = analysis_result.get("indicators") or []
            new_flags = local_red_flags[:5]
            analysis_result["indicators"] = list(dict.fromkeys(existing_indicators + new_flags))
            analysis_result["reason"] = (analysis_result.get("reason") or "") + f" — {len(local_suspicious_urls)} URL(s) sospechosas localmente"

    # Final verdict based on URL count — only override verdict, NOT Gemini's confidence
    malicious_count = len([r for r in url_results if r.get("suspicious")])
    if malicious_count >= 3:
        analysis_result["verdict"] = "phishing"
        # Only adjust confidence if it was higher than what phishing deserves
        if analysis_result["confidence"] > 0.35:
            analysis_result["confidence"] = 0.30
    elif malicious_count >= 2:
        analysis_result["verdict"] = "phishing"
        if analysis_result["confidence"] > 0.40:
            analysis_result["confidence"] = 0.35
    elif malicious_count >= 1 and analysis_result["verdict"] == "safe":
        analysis_result["verdict"] = "suspicious"
        if analysis_result["confidence"] > 0.70:
            analysis_result["confidence"] = 0.60

    # Build URLCheckResult list for response
    urls_analyzed = []
    for url_data in url_results:
        urls_analyzed.append(URLCheckResult(
            url=url_data["url"],
            malicious=url_data.get("suspicious", False),
            threat_types=[],
            error=None
        ))

    # Anomaly detection (feature-gated, additive)
    anomaly_score = None
    try:
        settings = get_settings()
        if getattr(settings, "USE_ANOMALY_DETECTION", False):
            anomaly_score = score_anomaly(
                email_sender=analyze_request.email_sender,
                email_subject=analyze_request.email_subject,
                email_body=analyze_request.email_body,
                analyzed_at=datetime.now(timezone.utc).isoformat()
            )
            # Record pattern for future learning
            record_pattern(analyze_request.email_sender, analyze_request.email_subject)
    except Exception:
        pass  # Non-fatal: anomaly detection is optional

    response = AnalyzeResponse(
        email_id=analyze_request.email_id,
        verdict=analysis_result["verdict"],
        confidence=analysis_result["confidence"],
        reason=analysis_result.get("reason") or analysis_result.get("reason", ""),
        indicators=analysis_result.get("indicators") or [],
        urls_analyzed=urls_analyzed,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        anomaly_score=anomaly_score,
    )

    # Registrar en dashboard
    record_analysis(response.model_dump())

    return response


# -------------------------------------------------------------------
# Batch Analysis endpoints (feature-gated by USE_BATCH_ANALYSIS)
# -------------------------------------------------------------------

class BatchEmailItem(BaseModel):
    email_id: str
    email_subject: str = ""
    email_sender: str = ""
    email_body: str = ""


class BatchSubmitRequest(BaseModel):
    emails: list[BatchEmailItem]


class BatchSubmitResponse(BaseModel):
    batch_id: str
    status: str
    total: int


class BatchStatusResponse(BaseModel):
    batch_id: str
    status: str
    total: int
    completed: int
    results: list[dict]
    created_at: str
    error: Optional[str] = None


@router.post("/batch", response_model=BatchSubmitResponse)
async def submit_batch_endpoint(request: BatchSubmitRequest):
    """
    Submit a batch of emails for background analysis.
    Returns 202 Accepted with batch_id for polling.
    Feature-gated by USE_BATCH_ANALYSIS.
    """
    settings = get_settings()
    if not getattr(settings, "USE_BATCH_ANALYSIS", False):
        raise HTTPException(
            status_code=404,
            detail={"error": "feature_disabled", "message": "Batch analysis is not enabled"}
        )

    if not request.emails:
        raise HTTPException(
            status_code=422,
            detail={"error": "empty_batch", "message": "No emails provided"}
        )

    if len(request.emails) > 100:
        raise HTTPException(
            status_code=422,
            detail={"error": "batch_max_exceeded", "message": "Maximum 100 emails per batch"}
        )

    # Check concurrent limit
    if get_batch_count() >= get_max_concurrent():
        raise HTTPException(
            status_code=429,
            detail={"error": "too_many_batches", "message": "Maximum concurrent batches reached"}
        )

    email_dicts = [e.model_dump() for e in request.emails]
    batch_id = submit_batch(email_dicts)

    return BatchSubmitResponse(
        batch_id=batch_id,
        status="processing",
        total=len(request.emails)
    )


@router.get("/batch/{batch_id}", response_model=BatchStatusResponse)
async def get_batch_endpoint(batch_id: str):
    """
    Get the status of a batch job.
    Returns 404 if batch not found.
    """
    settings = get_settings()
    if not getattr(settings, "USE_BATCH_ANALYSIS", False):
        raise HTTPException(
            status_code=404,
            detail={"error": "feature_disabled", "message": "Batch analysis is not enabled"}
        )

    status = get_batch_status(batch_id)
    if not status:
        raise HTTPException(
            status_code=404,
            detail={"error": "batch_not_found", "message": "Batch not found or expired"}
        )

    return BatchStatusResponse(**status)


# -------------------------------------------------------------------
# RAG Deep Analysis endpoint (feature-gated by USE_RAG)
# -------------------------------------------------------------------

class DeepAnalyzeResponse(BaseModel):
    email_id: str
    verdict: str
    confidence: float
    reason: str
    indicators: list[str]
    urls_analyzed: list[URLCheckResult]
    analyzed_at: str
    anomaly_score: Optional[float] = None
    rag_context: list[dict] = []


@router.post("/deep", response_model=DeepAnalyzeResponse)
@limiter.limit("5/minute")
async def deep_analyze_endpoint(
    request: Request,
    analyze_request: AnalyzeRequest,
    session_id: Optional[str] = Header(default=None, alias="X-Session-ID")
):
    """
    RAG-augmented deep analysis.
    Finds similar past phishing emails and augments the Gemini prompt.
    Feature-gated by USE_RAG.
    """
    settings = get_settings()
    if not getattr(settings, "USE_RAG", False):
        raise HTTPException(
            status_code=404,
            detail={"error": "feature_disabled", "message": "RAG analysis is not enabled"}
        )

    # Build RAG context
    rag_context_text, similar_examples = build_rag_prompt(
        analyze_request.email_sender,
        analyze_request.email_subject,
        analyze_request.email_body
    )

    # Run the same analysis as the regular endpoint
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', analyze_request.email_body or analyze_request.email_subject or '')
    url_results = [check_url_safety(u) for u in urls[:20]]
    local_red_flags = []
    for r in url_results:
        local_red_flags.extend(r["red_flags"])

    # Try Gemini analysis (with RAG context if available)
    analysis_result = None
    try:
        if getattr(settings, "GEMINI_USE_V2", False):
            analysis_result = analyze_email_v2(
                email_content=analyze_request.email_body,
                sender=analyze_request.email_sender,
                subject=analyze_request.email_subject
            )
            if not analysis_result:
                analysis_result = analyze_email(
                    email_content=analyze_request.email_body,
                    sender=analyze_request.email_sender,
                    subject=analyze_request.email_subject
                )
        else:
            analysis_result = analyze_email(
                email_content=analyze_request.email_body,
                sender=analyze_request.email_sender,
                subject=analyze_request.email_subject
            )
    except Exception:
        pass

    if not analysis_result:
        count = len(local_red_flags)
        if count >= 3:
            verdict, conf = "phishing", 0.25
        elif count >= 1:
            verdict, conf = "suspicious", 0.55
        else:
            verdict, conf = "safe", 0.92
        analysis_result = {
            "verdict": verdict,
            "confidence": conf,
            "reason": f"Análisis local: {count} indicador(es)",
            "indicators": list(dict.fromkeys(local_red_flags[:10])),
        }

    # Augment with RAG context
    if rag_context_text and similar_examples:
        # Boost confidence if similar phishing found
        max_similarity = max(e.get("similarity", 0) for e in similar_examples)
        if max_similarity > 0.8 and analysis_result["verdict"] in ("phishing", "suspicious"):
            analysis_result["confidence"] = min(0.99, analysis_result["confidence"] + 0.1)
            analysis_result["reason"] += f" — {len(similar_examples)} caso(s) similar(es) encontrado(s)"

    # Final verdict based on URL count — only override verdict, NOT Gemini's confidence
    malicious_count = len([r for r in url_results if r.get("suspicious")])
    if malicious_count >= 3:
        analysis_result["verdict"] = "phishing"
        if analysis_result["confidence"] > 0.35:
            analysis_result["confidence"] = 0.30
    elif malicious_count >= 2:
        analysis_result["verdict"] = "phishing"
        if analysis_result["confidence"] > 0.40:
            analysis_result["confidence"] = 0.35
    elif malicious_count >= 1 and analysis_result["verdict"] == "safe":
        analysis_result["verdict"] = "suspicious"
        if analysis_result["confidence"] > 0.70:
            analysis_result["confidence"] = 0.60

    # Build URLCheckResult list
    urls_analyzed = []
    for url_data in url_results:
        urls_analyzed.append(URLCheckResult(
            url=url_data["url"],
            malicious=url_data.get("suspicious", False),
            threat_types=[],
            error=None
        ))

    # Anomaly detection
    anomaly_score = None
    try:
        if getattr(settings, "USE_ANOMALY_DETECTION", False):
            anomaly_score = score_anomaly(
                email_sender=analyze_request.email_sender,
                email_subject=analyze_request.email_subject,
                email_body=analyze_request.email_body,
                analyzed_at=datetime.now(timezone.utc).isoformat()
            )
            record_pattern(analyze_request.email_sender, analyze_request.email_subject)
    except Exception:
        pass

    response = DeepAnalyzeResponse(
        email_id=analyze_request.email_id,
        verdict=analysis_result["verdict"],
        confidence=analysis_result["confidence"],
        reason=analysis_result.get("reason", ""),
        indicators=analysis_result.get("indicators", []),
        urls_analyzed=urls_analyzed,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        anomaly_score=anomaly_score,
        rag_context=similar_examples,
    )

    # Record in dashboard
    record_analysis(response.model_dump())

    # Store vector for future RAG lookup (only phishing/suspicious)
    try:
        store_phishing_vector(
            email_id=analyze_request.email_id,
            text=f"From: {analyze_request.email_sender}\nSubject: {analyze_request.email_subject}\nBody: {analyze_request.email_body[:2000]}",
            verdict=analysis_result["verdict"],
            reason=analysis_result.get("reason", ""),
            indicators=analysis_result.get("indicators", [])
        )
    except Exception:
        pass

    return response