"""
Tests for RAG / Phishing Memory service.
"""
import os
import sys
import pytest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.rag_service import (
    cosine_similarity, _normalize_sender,
    _load_vectors, _save_vectors, _add_vector,
    get_embedding, find_similar_phishing, store_phishing_vector,
    build_rag_prompt, VECTORS_FILE
)


@pytest.fixture
def temp_vectors_file():
    """Use a temporary file for vectors."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        temp_path = f.name
    with patch("services.rag_service.VECTORS_FILE", temp_path):
        yield temp_path
    # Cleanup
    if os.path.exists(temp_path):
        os.remove(temp_path)


@pytest.fixture
def mock_settings_rag():
    """Mock settings with RAG enabled."""
    settings = MagicMock()
    settings.GEMINI_API_KEY = "test-gemini-key"
    settings.USE_RAG = True
    settings.RAG_MAX_VECTORS = 100
    with patch("services.rag_service.get_settings", return_value=settings):
        yield settings


class TestCosineSimilarity:
    """Tests for cosine similarity calculation."""

    def test_identical_vectors(self):
        """Identical vectors have similarity 1.0."""
        v = [1.0, 0.0, 0.0]
        assert cosine_similarity(v, v) == 1.0

    def test_orthogonal_vectors(self):
        """Orthogonal vectors have similarity 0.0."""
        assert cosine_similarity([1, 0], [0, 1]) == 0.0

    def test_opposite_vectors(self):
        """Opposite vectors have similarity -1.0."""
        assert cosine_similarity([1, 0], [-1, 0]) == -1.0

    def test_empty_vectors(self):
        """Empty vectors return 0.0."""
        assert cosine_similarity([], [1, 2, 3]) == 0.0


class TestVectorStorage:
    """Tests for vector storage operations."""

    def test_save_and_load(self, temp_vectors_file):
        """Vectors can be saved and loaded."""
        vectors = [
            {"email_id": "test-1", "embedding": [0.1, 0.2, 0.3]},
            {"email_id": "test-2", "embedding": [0.4, 0.5, 0.6]},
        ]
        _save_vectors(vectors)
        loaded = _load_vectors()
        assert len(loaded) == 2
        assert loaded[0]["email_id"] == "test-1"

    def test_add_vector_evicts_oldest(self, temp_vectors_file):
        """Adding over limit evicts oldest vectors."""
        with patch("services.rag_service._get_max_vectors", return_value=3):
            for i in range(5):
                _add_vector({"email_id": f"test-{i}", "embedding": [0.1] * 3})

            vectors = _load_vectors()
            assert len(vectors) == 3
            # Oldest should be evicted
            ids = [v["email_id"] for v in vectors]
            assert "test-0" not in ids
            assert "test-4" in ids


class TestFindSimilarPhishing:
    """Tests for similarity search."""

    def test_no_vectors_returns_empty(self, temp_vectors_file):
        """Returns empty list when no vectors stored."""
        with patch("services.rag_service.get_embedding", return_value=[0.1] * 10):
            results = find_similar_phishing("test text")
        assert results == []

    def test_finds_similar(self, temp_vectors_file):
        """Finds similar vectors when they exist."""
        # Pre-store a vector
        _save_vectors([
            {
                "email_id": "phish-1",
                "text": "Verify your account now",
                "embedding": [0.5] * 10,
                "verdict": "phishing",
                "reason": "Urgency + account verification",
                "indicators": ["urgency"],
            }
        ])

        # Query with similar embedding
        with patch("services.rag_service.get_embedding", return_value=[0.51] * 10):
            results = find_similar_phishing("Verify your account immediately")

        assert len(results) >= 1
        assert results[0]["email_id"] == "phish-1"


class TestStorePhishingVector:
    """Tests for storing phishing vectors."""

    def test_only_stores_phishing(self, temp_vectors_file, mock_settings_rag):
        """Only stores vectors for phishing/suspicious verdicts."""
        with patch("services.rag_service.get_embedding", return_value=[0.1] * 10):
            # Safe email should not be stored
            store_phishing_vector("safe-1", "Safe email text", "safe")
            vectors = _load_vectors()
            assert len(vectors) == 0

            # Phishing should be stored
            store_phishing_vector("phish-1", "Phishing text", "phishing", "Test reason")
            vectors = _load_vectors()
            assert len(vectors) == 1
            assert vectors[0]["email_id"] == "phish-1"
