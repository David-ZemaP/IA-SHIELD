"""
Batch Analysis — Background async analysis of multiple emails.

Feature-gated by USE_BATCH_ANALYSIS env var (default false).
New endpoints: POST /analyze/batch, GET /analyze/batch/{batch_id}
Zero changes to existing /analyze endpoint.
"""
import asyncio
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

from services.gemini_service import analyze_email, check_url_safety
from services.gemini_v2 import analyze_email_v2
from routes.dashboard import record_analysis
from config import get_settings

# Module-level state
_batch_jobs: dict = {}
_max_concurrent = 5
_cleanup_interval = 3600  # 1 hour in seconds


class BatchJob:
    """Represents a batch analysis job."""

    def __init__(self, batch_id: str, emails: list[dict]):
        self.batch_id = batch_id
        self.emails = emails
        self.total = len(emails)
        self.completed = 0
        self.status = "processing"  # processing | completed | failed
        self.results: list[dict] = []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.error: Optional[str] = None


async def _analyze_single_email(email: dict) -> dict:
    """Analyze a single email using the current Gemini version."""
    settings = get_settings()
    use_v2 = getattr(settings, "GEMINI_USE_V2", False)

    body = email.get("email_body", email.get("body", ""))
    sender = email.get("email_sender", email.get("sender", ""))
    subject = email.get("email_subject", email.get("subject", ""))

    # Try Gemini analysis
    analysis_result = None
    try:
        if use_v2:
            analysis_result = analyze_email_v2(body, sender, subject)
        if not analysis_result:
            analysis_result = analyze_email(body, sender, subject)
    except Exception:
        pass

    # Fallback to local rules
    if not analysis_result:
        urls = []
        import re
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', body or subject or '')
        url_results = [check_url_safety(u) for u in urls[:20]]
        red_flags = []
        for r in url_results:
            red_flags.extend(r["red_flags"])

        count = len(red_flags)
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
            "indicators": list(dict.fromkeys(red_flags[:10])),
        }

    return {
        "email_id": email.get("email_id", email.get("id", "")),
        "verdict": analysis_result["verdict"],
        "confidence": analysis_result["confidence"],
        "reason": analysis_result.get("reason", ""),
        "indicators": analysis_result.get("indicators", []),
        "analyzed_at": datetime.now(timezone.utc).isoformat()
    }


async def _process_batch(job: BatchJob):
    """Process all emails in a batch asynchronously."""
    try:
        for email in job.emails:
            try:
                result = await _analyze_single_email(email)
                job.results.append(result)
                job.completed += 1

                # Record in dashboard
                record_analysis(result)

                # Rate limiting: small delay between analyses
                await asyncio.sleep(0.5)

            except Exception as e:
                job.results.append({
                    "email_id": email.get("email_id", email.get("id", "")),
                    "error": str(e),
                    "verdict": "error",
                    "confidence": 0.0,
                    "reason": f"Analysis failed: {e}",
                    "indicators": [],
                    "analyzed_at": datetime.now(timezone.utc).isoformat()
                })
                job.completed += 1

        job.status = "completed"

    except Exception as e:
        job.status = "failed"
        job.error = str(e)


def submit_batch(emails: list[dict]) -> str:
    """
    Submit a batch of emails for analysis.
    Returns the batch_id.
    """
    batch_id = str(uuid.uuid4())
    job = BatchJob(batch_id, emails)
    _batch_jobs[batch_id] = job

    # Start background processing
    asyncio.create_task(_process_batch(job))

    return batch_id


def get_batch_status(batch_id: str) -> Optional[dict]:
    """
    Get the status of a batch job.
    Returns None if batch not found.
    """
    job = _batch_jobs.get(batch_id)
    if not job:
        return None

    return {
        "batch_id": job.batch_id,
        "status": job.status,
        "total": job.total,
        "completed": job.completed,
        "results": job.results,
        "created_at": job.created_at,
        "error": job.error,
    }


def cleanup_old_batches():
    """Remove completed/failed batches older than cleanup_interval."""
    now = time.time()
    to_remove = []

    for batch_id, job in _batch_jobs.items():
        created = datetime.fromisoformat(job.created_at).timestamp()
        if (now - created) > _cleanup_interval:
            to_remove.append(batch_id)

    for batch_id in to_remove:
        del _batch_jobs[batch_id]

    return len(to_remove)


def get_batch_count() -> int:
    """Get the number of active (processing) batches."""
    return sum(1 for job in _batch_jobs.values() if job.status == "processing")


def get_max_concurrent() -> int:
    """Get the maximum number of concurrent batches."""
    return _max_concurrent
