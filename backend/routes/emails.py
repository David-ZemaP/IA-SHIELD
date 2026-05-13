"""
Endpoints para leer emails desde Gmail API.
"""
import re
from typing import Optional
from fastapi import APIRouter, Request, HTTPException

from services.gmail_service import get_emails_list, get_email_detail
from models.schemas import EmailListResponse, EmailDetail

router = APIRouter()


def parse_from_header(from_header: str) -> tuple[Optional[str], Optional[str]]:
    """Extrae nombre y email del header From."""
    if not from_header:
        return None, None

    match = re.match(r'^(.+?)\s*<(.+?)>$', from_header)
    if match:
        name = match.group(1).strip().strip('"')
        email = match.group(2).strip()
        return name, email

    if '@' in from_header:
        return None, from_header.strip()

    return from_header.strip(), None


@router.get("", response_model=EmailListResponse)
async def list_emails(request: Request, max_results: int = 20):
    """Lista los emails del inbox."""
    from routes.auth import require_auth
    session_data = await require_auth(request)

    try:
        emails = await get_emails_list(
            access_token=session_data["access_token"],
            max_results=max_results
        )

        for email in emails:
            name, email_addr = parse_from_header(email.get("from", ""))
            email["fromName"] = name
            email["fromEmail"] = email_addr

        return EmailListResponse(emails=emails, next_page_token=None)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{email_id}", response_model=EmailDetail)
async def get_email(request: Request, email_id: str):
    """Detalle de un email específico."""
    from routes.auth import require_auth
    session_data = await require_auth(request)

    try:
        email_detail = await get_email_detail(
            access_token=session_data["access_token"],
            email_id=email_id
        )

        name, email_addr = parse_from_header(email_detail.get("from", ""))
        email_detail["from_name"] = name
        email_detail["from_email"] = email_addr

        return EmailDetail(**email_detail)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))