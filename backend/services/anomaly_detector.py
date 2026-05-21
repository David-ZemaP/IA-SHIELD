"""
Anomaly Detection — Behavioral pattern learning for email analysis.

Feature-gated by USE_ANOMALY_DETECTION env var (default false).
Learns from analysis_history: sender frequency, time patterns, subject similarity.
Returns anomaly_score: 0.0 (normal) to 1.0 (highly anomalous).
Zero changes to existing analysis flow.
"""
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from routes.dashboard import analysis_history, stats

# Module-level state
_sender_counts: dict = defaultdict(int)
_sender_hours: dict = defaultdict(list)
_sender_subjects: dict = defaultdict(list)
_initialized = False


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def _similarity(s1: str, s2: str) -> float:
    """Calculate similarity between 0.0 and 1.0."""
    if not s1 and not s2:
        return 1.0
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    distance = _levenshtein_distance(s1, s2)
    return 1.0 - (distance / max_len)


def _normalize_sender(sender: str) -> str:
    """Extract email from sender string."""
    match = re.search(r'<(.+?)>', sender)
    return match.group(1).lower() if match else sender.lower().strip()


def _learn_from_history():
    """Build pattern models from existing analysis history."""
    global _initialized

    if _initialized:
        return

    for record in analysis_history.values():
        sender = _normalize_sender(record.get("email_id", ""))
        if sender:
            _sender_counts[sender] += 1

    _initialized = True


def _score_sender_frequency(sender: str) -> float:
    """
    Score based on sender frequency.
    Unknown senders get higher anomaly scores.
    """
    normalized = _normalize_sender(sender)
    count = _sender_counts.get(normalized, 0)

    if count == 0:
        return 0.7  # Unknown sender — moderately anomalous
    elif count == 1:
        return 0.4  # Seen once — slightly anomalous
    elif count <= 3:
        return 0.2  # Seen a few times — low anomaly
    else:
        return 0.0  # Frequent sender — normal


def _score_time_pattern(sender: str, analyzed_at: Optional[str] = None) -> float:
    """
    Score based on time patterns.
    Emails at unusual hours get higher anomaly scores.
    """
    if not analyzed_at:
        return 0.0

    try:
        dt = datetime.fromisoformat(analyzed_at.replace("Z", "+00:00"))
        hour = dt.hour
    except (ValueError, AttributeError):
        return 0.0

    # Unusual hours: 1am-5am
    if 1 <= hour <= 5:
        return 0.5
    # Early morning or late night: 5am-7am, 10pm-1am
    elif 5 <= hour <= 7 or 22 <= hour <= 24:
        return 0.3
    # Normal business hours: 8am-6pm
    elif 8 <= hour <= 18:
        return 0.0
    # Evening: 6pm-10pm
    else:
        return 0.1


def _score_subject_similarity(sender: str, subject: str) -> float:
    """
    Score based on subject similarity to previous emails from same sender.
    Very different subjects from known senders are anomalous.
    """
    normalized = _normalize_sender(sender)
    previous_subjects = _sender_subjects.get(normalized, [])

    if not previous_subjects or not subject:
        return 0.0

    # Check similarity to most recent subjects
    max_similarity = max(_similarity(subject, ps) for ps in previous_subjects[-5:])

    if max_similarity > 0.8:
        return 0.0  # Very similar — normal
    elif max_similarity > 0.5:
        return 0.2  # Somewhat similar — low anomaly
    else:
        return 0.5  # Very different — moderately anomalous


def score_anomaly(
    email_sender: str,
    email_subject: str = "",
    email_body: str = "",
    analyzed_at: Optional[str] = None
) -> float:
    """
    Calculate anomaly score for an email.
    Returns 0.0 (normal) to 1.0 (highly anomalous).

    Factors:
    - Sender frequency (40% weight)
    - Time pattern (30% weight)
    - Subject similarity (30% weight)
    """
    _learn_from_history()

    sender_score = _score_sender_frequency(email_sender)
    time_score = _score_time_pattern(email_sender, analyzed_at)
    subject_score = _score_subject_similarity(email_sender, email_subject)

    # Weighted average
    anomaly_score = (
        sender_score * 0.4 +
        time_score * 0.3 +
        subject_score * 0.3
    )

    return round(min(1.0, max(0.0, anomaly_score)), 3)


def record_pattern(email_sender: str, email_subject: str):
    """
    Record a sender/subject pattern for future anomaly detection.
    Call this after each analysis to build the pattern model.
    """
    normalized = _normalize_sender(email_sender)
    if normalized:
        _sender_counts[normalized] += 1
        if email_subject:
            _sender_subjects[normalized].append(email_subject)
            # Keep only last 20 subjects per sender
            if len(_sender_subjects[normalized]) > 20:
                _sender_subjects[normalized] = _sender_subjects[normalized][-20:]
