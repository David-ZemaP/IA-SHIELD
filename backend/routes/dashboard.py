"""
Dashboard API — estadísticas y historial de análisis de phishing.
Endpoints:
- GET /api/dashboard/stats → estadísticas generales
- GET /api/dashboard/history → historial de análisis (últimos 50)
- POST /api/dashboard/false-positive → reportar falso positivo
"""
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timezone
from collections import defaultdict
import uuid
import asyncio
import csv
import io

from storage import write_analysis, write_false_positive

router = APIRouter(tags=["dashboard"])

# In-memory storage (prototype)
# Estructura: {analysis_id: AnalysisRecord}
analysis_history: dict = {}
# Contadores
stats = {
    "total_analyzed": 0,
    "total_phishing": 0,
    "total_suspicious": 0,
    "total_safe": 0,
    "total_review_needed": 0,
    "total_urls_checked": 0,
    "total_malicious_urls": 0,
    "false_positives_reported": 0,
}

# Lock simple para thread safety
from threading import Lock
_history_lock = Lock()

class FalsePositiveReport(BaseModel):
    analysis_id: str
    reason: Optional[str] = None

@router.get("/stats")
async def get_stats():
    """
    Devuelve estadísticas generales del sistema.
    """
    return {
        "total_analyzed": stats["total_analyzed"],
        "total_phishing": stats["total_phishing"],
        "total_suspicious": stats["total_suspicious"],
        "total_safe": stats["total_safe"],
        "total_review_needed": stats["total_review_needed"],
        "total_urls_checked": stats["total_urls_checked"],
        "total_malicious_urls": stats["total_malicious_urls"],
        "false_positives_reported": stats["false_positives_reported"],
        "detection_rate": (
            round(stats["total_phishing"] / stats["total_analyzed"] * 100, 1)
            if stats["total_analyzed"] > 0 else 0
        ),
        "phishing_rate": (
            round(stats["total_phishing"] / stats["total_analyzed"] * 100, 1)
            if stats["total_analyzed"] > 0 else 0
        ),
    }

@router.get("/history")
async def get_history(limit: int = 50):
    """
    Devuelve el historial de análisis.
    """
    with _history_lock:
        items = sorted(
            analysis_history.values(),
            key=lambda x: x.get("analyzed_at", ""),
            reverse=True
        )[:limit]
    return {"items": items, "total": len(items)}


@router.get("/export")
async def export_history_csv():
    """
    Export analysis history as CSV download.
    Uses in-memory data (no config gate — safe by nature).
    """
    with _history_lock:
        items = sorted(
            analysis_history.values(),
            key=lambda x: x.get("analyzed_at", ""),
            reverse=True
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "email_id", "verdict", "confidence", "reason",
        "analyzed_at", "false_positive_reported", "indicators"
    ])

    for item in items:
        writer.writerow([
            item.get("email_id", ""),
            item.get("verdict", ""),
            item.get("confidence", 0),
            item.get("reason", ""),
            item.get("analyzed_at", ""),
            item.get("false_positive_reported", False),
            "; ".join(item.get("indicators", []))
        ])

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=ia-shield-analysis-export.csv"
        }
    )

@router.post("/false-positive")
async def report_false_positive(report: FalsePositiveReport):
    """
    Reporta un falso positivo para mejorar el modelo.
    """
    with _history_lock:
        if report.analysis_id in analysis_history:
            analysis_history[report.analysis_id]["false_positive_reported"] = True
            analysis_history[report.analysis_id]["false_positive_reason"] = report.reason

        stats["false_positives_reported"] += 1
        # Reducir el contador de phishing si lo había
        record = analysis_history.get(report.analysis_id, {})
        if record.get("verdict") == "phishing":
            stats["total_phishing"] = max(0, stats["total_phishing"] - 1)
            stats["total_safe"] += 1
            analysis_history[report.analysis_id]["verdict"] = "safe"
            analysis_history[report.analysis_id]["verdict_overridden"] = True
            analysis_history[report.analysis_id]["override_reason"] = "false_positive_reported"

    # Dual-write to SQLite (non-blocking, after in-memory update)
    try:
        write_false_positive(report.analysis_id, report.reason)
    except Exception:
        pass  # Non-fatal

    return {"ok": True, "message": "Falso positivo registrado"}

def record_analysis(result: dict):
    """
    Registra un análisis en el historial.
    Llama esta función desde el endpoint /analyze después de completar el análisis.
    """
    with _history_lock:
        analysis_id = result.get("email_id") or str(uuid.uuid4())
        record = {
            "id": analysis_id,
            "email_id": result.get("email_id"),
            "verdict": result.get("verdict"),
            "confidence": result.get("confidence"),
            "reason": result.get("reason"),
            "indicators": result.get("indicators", []),
            "urls_analyzed": result.get("urls_analyzed", []),
            "analyzed_at": result.get("analyzed_at", datetime.now(timezone.utc).isoformat()),
            "false_positive_reported": False,
        }
        analysis_history[analysis_id] = record

        # Actualizar stats
        stats["total_analyzed"] += 1
        verdict = result.get("verdict", "review_needed")
        key = f"total_{verdict}"
        if key in stats:
            stats[key] += 1

        # Contar URLs
        urls = result.get("urls_analyzed", [])
        stats["total_urls_checked"] += len(urls)
        stats["total_malicious_urls"] += sum(1 for u in urls if u.get("malicious"))

        # Dual-write to SQLite (non-blocking, after in-memory write)
        try:
            write_analysis(record)
        except Exception:
            pass  # Non-fatal: in-memory is primary, SQLite is secondary

        return analysis_id