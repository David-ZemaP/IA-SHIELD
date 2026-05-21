"""
RAG / Phishing Memory — Vector-based phishing pattern memory.

Feature-gated by USE_RAG env var (default false).
Uses Gemini text-embedding-004 API for embeddings.
Stores vectors in JSONL format for zero-dependency vector search.
New endpoint: POST /analyze/deep (RAG-augmented analysis).
Zero changes to existing /analyze endpoint.
"""
import httpx
import json
import math
import os
import re
import time
from typing import Optional

from config import get_settings

# Config
EMBEDDING_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/text-embedding-004:embedContent"
VECTORS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "phishing_vectors.jsonl")
MAX_VECTORS = 1000  # Configurable via RAG_MAX_VECTORS
SIMILARITY_THRESHOLD = 0.6  # Minimum cosine similarity to consider a match
TOP_K = 3  # Number of similar examples to include in prompt


def _get_max_vectors() -> int:
    """Get max vectors from config."""
    try:
        settings = get_settings()
        return getattr(settings, "RAG_MAX_VECTORS", MAX_VECTORS)
    except Exception:
        return MAX_VECTORS


def _ensure_data_dir():
    """Ensure the data directory exists."""
    os.makedirs(os.path.dirname(VECTORS_FILE), exist_ok=True)


def _load_vectors() -> list[dict]:
    """Load all vectors from JSONL file."""
    if not os.path.exists(VECTORS_FILE):
        return []

    vectors = []
    try:
        with open(VECTORS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    vectors.append(json.loads(line))
    except Exception:
        pass

    return vectors


def _save_vectors(vectors: list[dict]):
    """Save all vectors to JSONL file."""
    _ensure_data_dir()
    with open(VECTORS_FILE, "w") as f:
        for v in vectors:
            f.write(json.dumps(v) + "\n")


def _add_vector(vector: dict):
    """Add a vector and evict oldest if over limit."""
    vectors = _load_vectors()
    vectors.append(vector)

    max_vectors = _get_max_vectors()
    if len(vectors) > max_vectors:
        # Evict oldest (first entries)
        vectors = vectors[-max_vectors:]

    _save_vectors(vectors)


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if not a or not b:
        return 0.0

    dot_product = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot_product / (norm_a * norm_b)


def get_embedding(text: str) -> Optional[list[float]]:
    """
    Get embedding for text using Gemini text-embedding-004.
    Returns embedding vector or None on failure.
    """
    settings = get_settings()
    api_key = getattr(settings, "GEMINI_API_KEY", "")

    if not api_key:
        return None

    payload = {
        "model": "models/text-embedding-004",
        "content": {
            "parts": [{"text": text}]
        }
    }

    try:
        response = httpx.post(
            f"{EMBEDDING_API_URL}?key={api_key}",
            json=payload,
            timeout=15.0
        )

        if response.status_code != 200:
            return None

        data = response.json()
        embedding = data.get("embedding", {}).get("values")
        return embedding

    except Exception:
        return None


def store_phishing_vector(
    email_id: str,
    text: str,
    verdict: str,
    reason: str = "",
    indicators: list = None
):
    """
    Store a phishing/suspicious email vector for future RAG lookup.
    Only stores if verdict is "phishing" or "suspicious".
    """
    if verdict not in ("phishing", "suspicious"):
        return

    embedding = get_embedding(text)
    if not embedding:
        return

    vector = {
        "email_id": email_id,
        "text": text[:2000],  # Truncate for storage
        "embedding": embedding,
        "verdict": verdict,
        "reason": reason,
        "indicators": indicators or [],
        "stored_at": time.time()
    }

    _add_vector(vector)


def find_similar_phishing(text: str, top_k: int = TOP_K) -> list[dict]:
    """
    Find similar past phishing emails using cosine similarity.
    Returns list of {email_id, verdict, reason, similarity, indicators}.
    """
    query_embedding = get_embedding(text)
    if not query_embedding:
        return []

    vectors = _load_vectors()
    if not vectors:
        return []

    # Calculate similarities
    results = []
    for v in vectors:
        sim = cosine_similarity(query_embedding, v.get("embedding", []))
        if sim >= SIMILARITY_THRESHOLD:
            results.append({
                "email_id": v.get("email_id", ""),
                "verdict": v.get("verdict", ""),
                "reason": v.get("reason", ""),
                "indicators": v.get("indicators", []),
                "similarity": round(sim, 4),
            })

    # Sort by similarity descending, return top_k
    results.sort(key=lambda x: x["similarity"], reverse=True)
    return results[:top_k]


def build_rag_prompt(email_sender: str, email_subject: str, email_body: str) -> tuple[str, list[dict]]:
    """
    Build an augmented prompt with RAG context.
    Returns (augmented_prompt, similar_examples).
    """
    # Build text to embed
    text_to_embed = f"From: {email_sender}\nSubject: {email_subject}\nBody: {email_body[:2000]}"

    # Find similar past phishing
    similar = find_similar_phishing(text_to_embed)

    if not similar:
        return "", []

    # Build RAG context
    rag_context = "\n\nCASOS SIMILARES DETECTADOS ANTERIORMENTE:\n"
    for i, example in enumerate(similar, 1):
        rag_context += f"\n{i}. [Similitud: {example['similarity']*100:.0f}%] Veredicto: {example['verdict']}"
        rag_context += f"\n   Razón: {example['reason']}"
        if example['indicators']:
            rag_context += f"\n   Indicadores: {', '.join(example['indicators'])}"

    return rag_context, similar
