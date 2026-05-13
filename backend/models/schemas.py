from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# Auth schemas
class TokenRequest(BaseModel):
    code: str
    code_verifier: str


class TokenResponse(BaseModel):
    session_id: str
    expires_at: str


class AuthStatus(BaseModel):
    authenticated: bool
    email: Optional[str] = None


# Email schemas
class EmailListResponse(BaseModel):
    emails: List[dict]
    next_page_token: Optional[str] = None


class EmailDetail(BaseModel):
    id: str
    thread_id: str
    subject: str
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    date: str
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[str] = []
    attachments: List[dict] = []
    labels: List[str] = []


# Analysis schemas
class AnalyzeRequest(BaseModel):
    email_id: str
    subject: str
    from_name: Optional[str] = None
    from_email: Optional[str] = None
    body_plain: Optional[str] = None
    body_html: Optional[str] = None
    urls: List[str] = []


class AnalyzeResponse(BaseModel):
    analysis_id: str
    email_id: str
    verdict: str
    confidence: float
    reason: str
    indicators: List[str]
    urls_analyzed: List[dict]
    model: str
    timestamp: str


# Dashboard schemas
class DashboardStats(BaseModel):
    total_analyzed: int = 0
    phishing_detected: int = 0
    suspicious: int = 0
    safe: int = 0
    review_needed: int = 0
    false_positives_reported: int = 0
    url_blocks_active: int = 0
    last_analysis_at: Optional[str] = None


class DashboardHistoryItem(BaseModel):
    analysis_id: str
    email_id: str
    subject: str
    from_field: str
    verdict: str
    confidence: float
    reason: str
    indicators: List[str]
    timestamp: str


class DashboardHistoryResponse(BaseModel):
    items: List[DashboardHistoryItem]
    total: int
    has_more: bool


class FalsePositiveRequest(BaseModel):
    analysis_id: str
    reason: str


# Error response
class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[dict] = None