# SDD Spec: ia-shield-evolution-v2

| Field | Value |
|-------|-------|
| **Change** | ia-shield-evolution-v2 |
| **Status** | `spec` |
| **Base** | phishing-extension-prototype (existing) |
| **Constraint** | Zero breaking changes — all features config-gated, defaults off |
| **Artifact Store** | engram |

---

## Purpose

Add 6 major capabilities to IA-Shield's phishing detection system, all opt-in via `.env` flags. Every feature is independently toggleable, preserves existing API contracts, and requires zero Chrome Extension changes.

---

## Feature 1: Persistent Storage (PS)

**Config flag**: `USE_PERSISTENT_STORAGE` (`bool`, default `false`)
**New files**: `backend/storage/db.py`, `backend/data/` directory
**Modified files** (additive only): `backend/config.py`, `backend/main.py`, `backend/routes/dashboard.py`
**Dependencies**: `sqlite3` (stdlib)

### Requirement PS-1: Dual-write on analysis record

The system MUST write every analysis record to SQLite in addition to the existing in-memory store when `USE_PERSISTENT_STORAGE=true`. The existing `record_analysis()` function signature and return type MUST NOT change.

#### Scenario: Dual-write with flag ON

- GIVEN `USE_PERSISTENT_STORAGE=true`
- WHEN `record_analysis(result)` is called from `POST /analyze`
- THEN the analysis is written to in-memory `analysis_history` (unchanged)
- AND the same record is written to SQLite table `analysis_records`
- AND the response to the client is unchanged (no new latency visible)

#### Scenario: Dual-write with flag OFF

- GIVEN `USE_PERSISTENT_STORAGE=false` (default)
- WHEN `record_analysis(result)` is called
- THEN only the in-memory store receives the record
- AND no SQLite database file is created
- AND no SQLite import or connection is attempted

#### Scenario: SQLite write failure is non-fatal

- GIVEN `USE_PERSISTENT_STORAGE=true`
- WHEN the SQLite write fails (disk full, permissions error)
- THEN the in-memory write MUST still succeed
- AND the error is logged but NOT propagated to the client
- AND the HTTP response is the same as if SQLite was off

### Requirement PS-2: SQLite tables and schema

The system MUST create and manage a SQLite database at `backend/data/ia_shield.db` with the following tables when `USE_PERSISTENT_STORAGE=true`:

- `analysis_records`: same schema as in-memory record, plus `sqlite_created_at` TIMESTAMP
- `false_positives`: analysis_id, reason, created_at
- `stats_snapshots`: snapshot_date, json_stats TEXT (stores serialized stats)

#### Scenario: Database initialization on startup

- GIVEN `USE_PERSISTENT_STORAGE=true`
- WHEN the application starts (lifespan startup)
- THEN `backend/data/ia_shield.db` is created if absent
- AND all three tables are created with correct schemas
- AND WAL journal mode is enabled

#### Scenario: Idempotent table creation

- GIVEN `USE_PERSISTENT_STORAGE=true` and the database already exists with tables
- WHEN the application restarts
- THEN no error occurs (CREATE TABLE IF NOT EXISTS)
- AND existing data is preserved

### Requirement PS-3: Stats snapshots

The system MUST periodically persist a snapshot of in-memory stats to the `stats_snapshots` table when `USE_PERSISTENT_STORAGE=true`, so that dashboard stats survive a server restart.

#### Scenario: Stats persist across restart

- GIVEN `USE_PERSISTENT_STORAGE=true` and 50 analyses have been recorded
- WHEN the server restarts
- THEN `GET /api/dashboard/stats` returns the same counts as before the restart
- AND the stats are reconstructed from the most recent `stats_snapshots` row plus replay from `analysis_records`

### Non-Requirements (PS)

- No migration tooling for SQLite schema versions
- No multi-user isolation in persistent storage
- No encryption-at-rest for SQLite data
- No automatic purge of old records

---

## Feature 2: Gemini v2 (GV2)

**Config flag**: `GEMINI_USE_V2` (`bool`, default `false`)
**New files**: `backend/services/gemini_v2.py`
**Modified files** (additive only): `backend/config.py`, `backend/requirements.txt`
**Dependencies**: `google-generativeai` Python SDK

### Requirement GV2-1: Structured output via response_schema

When `GEMINI_USE_V2=true`, the system MUST use the `google-generativeai` SDK's `response_schema` parameter to enforce structured JSON output from Gemini, instead of the current string-prompt + regex parsing approach.

#### Scenario: Structured output returns valid schema

- GIVEN `GEMINI_USE_V2=true`
- WHEN `analyze_email()` is called with a phishing email
- THEN the Gemini response MUST be parsed using `response_schema`
- AND the returned dict MUST contain `verdict`, `confidence`, `reason`, `indicators`
- AND parsing errors MUST fall back to v1 behavior (string prompt + regex)

#### Scenario: Fallback to v1 when v2 fails

- GIVEN `GEMINI_USE_V2=true`
- WHEN the `google-generativeai` SDK raises an exception (network error, schema mismatch)
- THEN the system MUST fall back to the existing v1 Gemini call (`call_gemini`)
- AND the analysis completes successfully with v1 logic
- AND the error is logged

#### Scenario: Feature flag OFF uses v1

- GIVEN `GEMINI_USE_V2=false` (default)
- WHEN `analyze_email()` is called
- THEN the existing `call_gemini()` function is used (string prompt + regex)
- AND the `google-generativeai` SDK is never imported

### Requirement GV2-2: LRU cache for Gemini results

When `GEMINI_USE_V2=true`, the system MUST cache Gemini analysis results in an LRU cache (max 500 entries) keyed by a hash of the email content + sender + subject.

#### Scenario: Cache hit returns cached result

- GIVEN `GEMINI_USE_V2=true`
- WHEN the same email content is analyzed twice within the cache TTL
- THEN the second call MUST NOT invoke the Gemini API
- AND the cached result is returned directly

#### Scenario: Cache eviction

- GIVEN `GEMINI_USE_V2=true` and the cache has 500 entries
- WHEN a new unique email is analyzed
- THEN the least recently used entry is evicted
- AND the new result is cached

### Requirement GV2-3: Few-shot prompt augmentation

When `GEMINI_USE_V2=true`, the system MUST include 2-3 few-shot examples in the Gemini system prompt to improve classification accuracy for borderline cases.

#### Scenario: Few-shot prompts improve suspicious classification

- GIVEN `GEMINI_USE_V2=true`
- WHEN analyzing a borderline phishing email (e.g., brand impersonation without urgency)
- THEN the prompt MUST include 2-3 labeled examples (safe, suspicious, phishing)
- AND the response SHOULD be factually grounded by the examples

### Non-Requirements (GV2)

- No fine-tuning or model training
- No cost tracking per API call
- No streaming responses

---

## Feature 3: Dashboard Export (DE)

**Config flag**: NONE (safe by nature, always available)
**Modified files** (additive only): `backend/routes/dashboard.py`, `backend/static/index.html`

### Requirement DE-1: CSV export endpoint

The system MUST provide `GET /api/dashboard/export` that returns all analysis records as a CSV file download.

#### Scenario: Export with data returns CSV

- GIVEN the in-memory store has 10 analysis records
- WHEN `GET /api/dashboard/export` is called
- THEN the response is `Content-Type: text/csv`
- AND the CSV contains a header row: `email_id,verdict,confidence,reason,indicators,analyzed_at`
- AND the CSV contains 10 data rows (one per record)
- AND `Content-Disposition` is `attachment; filename="analyses-export.csv"`

#### Scenario: Export with no data

- GIVEN the in-memory store is empty
- WHEN `GET /api/dashboard/export` is called
- THEN the response is `Content-Type: text/csv`
- AND the CSV contains only the header row
- AND HTTP status is 200

#### Scenario: Export includes URL analysis columns

- GIVEN records contain `urls_analyzed` data
- WHEN `GET /api/dashboard/export` is called
- THEN the CSV row for each record includes a `malicious_urls_count` column
- AND a `urls_analyzed_summary` column with abbreviated URL results

### Requirement DE-2: Export button in dashboard UI

The dashboard `index.html` MUST include an "Export CSV" button in the history section header.

#### Scenario: Export button visible

- GIVEN the dashboard page is loaded at `/dashboard`
- WHEN the user views the history section
- THEN an "Export CSV" button MUST be visible next to the "Actualizar" (Refresh) button
- AND clicking it triggers a download of the CSV file
- AND the existing "Actualizar" button behavior is unchanged

### Non-Requirements (DE)

- No filtered export (exports ALL records)
- No paginated export
- No JSON export format
- No date-range filtering

---

## Feature 4: Anomaly Detection (AD)

**Config flag**: `USE_ANOMALY_DETECTION` (`bool`, default `false`)
**New files**: `backend/services/anomaly_detector.py`
**Modified files** (additive only): `backend/config.py`, `backend/models/schemas.py`, `backend/routes/analyze.py`
**Depends on**: Feature 1 (Persistent Storage) for long-term pattern learning

### Requirement AD-1: anomaly_score field in AnalyzeResponse

The `AnalyzeResponse` schema MUST include an optional `anomaly_score` field of type `Optional[float]` (null when flag is off).

#### Scenario: anomaly_score present when flag ON

- GIVEN `USE_ANOMALY_DETECTION=true`
- WHEN `POST /analyze` returns a response
- THEN the response body MUST include `"anomaly_score": <float or null>`
- AND the anomaly_score is in range 0.0–1.0

#### Scenario: anomaly_score absent when flag OFF

- GIVEN `USE_ANOMALY_DETECTION=false` (default)
- WHEN `POST /analyze` returns a response
- THEN `anomaly_score` MUST be either absent or `null` in the response
- AND existing clients parsing the response MUST NOT break (optional field)

### Requirement AD-2: Pattern learning

When `USE_ANOMALY_DETECTION=true`, the system MUST learn patterns from analyzed emails: sender frequency, time-of-day distribution, subject-line structure.

#### Scenario: Unusual sender detected

- GIVEN `USE_ANOMALY_DETECTION=true` and the system has analyzed 10+ emails from known senders
- WHEN an email arrives from a sender never seen before
- THEN `anomaly_score` MUST be > 0.5

#### Scenario: Normal email from known sender

- GIVEN `USE_ANOMALY_DETECTION=true` and a known sender has sent 5+ emails at similar times
- WHEN a new email arrives from that known sender at a normal time
- THEN `anomaly_score` MUST be < 0.3

### Requirement AD-3: Pattern persistence with SQLite

When `USE_ANOMALY_DETECTION=true` AND `USE_PERSISTENT_STORAGE=true`, anomaly patterns MUST persist across server restarts.

#### Scenario: Patterns survive restart with SQLite

- GIVEN both flags are ON and 20 emails have been analyzed
- WHEN the server restarts
- THEN anomaly patterns are reloaded from the persistent store
- AND a known sender is still recognized as low-anomaly

### Non-Requirements (AD)

- No machine learning model training (rule-based heuristics only)
- No anomaly time-series visualization
- No sender reputation external lookup

---

## Feature 5: RAG / Phishing Memory (RAG)

**Config flag**: `USE_RAG` (`bool`, default `false`)
**New files**: `backend/services/rag_service.py`, `backend/data/phishing_vectors.jsonl`
**Modified files** (additive only): `backend/config.py`, `backend/routes/analyze.py`, `backend/main.py`
**Depends on**: Feature 1 (Persistent Storage), Gemini API key (`GEMINI_API_KEY`)
**Dependencies**: `google-generativeai` SDK (shared with GV2)

### Requirement RAG-1: Vector store for phishing memory

The system MUST maintain a vector store at `backend/data/phishing_vectors.jsonl` (one JSON object per line) mapping email content hash to embedding vector + metadata, when `USE_RAG=true`.

#### Scenario: Phishing email stored as vector

- GIVEN `USE_RAG=true` and `POST /analyze` returns `verdict: "phishing"`
- WHEN the analysis completes
- THEN the email content is embedded via Gemini `text-embedding-004`
- AND the embedding vector + metadata (subject, sender, indicators) is appended to `phishing_vectors.jsonl`

#### Scenario: Non-phishing email not stored

- GIVEN `USE_RAG=true` and `POST /analyze` returns `verdict: "safe"` or `"suspicious"`
- WHEN the analysis completes
- THEN NO entry is added to `phishing_vectors.jsonl`

### Requirement RAG-2: POST /analyze/deep endpoint

The system MUST provide `POST /analyze/deep` that performs RAG-augmented analysis. Request body is the same as `POST /analyze`. Response is the same `AnalyzeResponse` plus an optional `rag_matched_entries: Optional[int]`.

#### Scenario: Deep analysis augments prompt with similar phishing

- GIVEN `USE_RAG=true` and the vector store has 5+ phishing entries
- WHEN `POST /analyze/deep` is called with a suspicious email
- THEN the system embeds the email content
- AND searches for the top-3 most similar phishing vectors by cosine similarity
- AND the Gemini prompt is augmented with those 3 examples
- AND the response includes `rag_matched_entries: 3`

#### Scenario: Deep analysis with no matches

- GIVEN `USE_RAG=true` and the vector store is empty
- WHEN `POST /analyze/deep` is called
- THEN the analysis proceeds without augmentation
- AND `rag_matched_entries: 0` in the response

#### Scenario: Deep analysis with feature flag OFF

- GIVEN `USE_RAG=false` (default)
- WHEN `POST /analyze/deep` is called
- THEN the endpoint returns `404 Not Found`
- AND the body contains `{ "error": "feature_disabled", "message": "RAG feature is not enabled" }`

#### Scenario: Embedding API failure

- GIVEN `USE_RAG=true`
- WHEN the Gemini embedding API fails (timeout, auth error)
- THEN the system falls back to regular `POST /analyze` behavior
- AND `rag_matched_entries: null` in the response
- AND the error is logged

### Requirement RAG-3: Similarity search

The system MUST implement cosine similarity search over the in-memory vector store, returning the top-K most similar entries (K defaults to 3, configurable).

#### Scenario: Similarity threshold filter

- GIVEN `USE_RAG=true` and the vector store has varied entries
- WHEN searching for similar vectors
- THEN only entries with cosine similarity > 0.7 are returned as matches
- AND if fewer than 3 entries meet the threshold, only those are returned

### Non-Requirements (RAG)

- No persistent vector index (vectors rebuilt from JSONL on restart)
- No approximate nearest neighbor (ANN) — brute-force cosine similarity only
- No embedding cache beyond LRU (shared with GV2 cache)
- No automatic re-embedding of existing vectors

---

## Feature 6: Batch Analysis (BA)

**Config flag**: `USE_BATCH_ANALYSIS` (`bool`, default `false`)
**New files**: `backend/services/batch_analyzer.py`
**Modified files** (additive only): `backend/config.py`, `backend/routes/analyze.py`, `backend/main.py`

### Requirement BA-1: POST /analyze/batch endpoint

The system MUST provide `POST /analyze/batch` that accepts an array of email analysis requests and returns a batch ID for polling.

**Request**:
```json
{
  "emails": [
    {
      "email_id": "string",
      "subject": "string",
      "from_name": "string|null",
      "from_email": "string|null",
      "body_plain": "string|null",
      "urls": ["string"]
    }
  ]
}
```

**Response** (HTTP 202):
```json
{
  "batch_id": "uuid-string",
  "status": "pending",
  "total": 5,
  "completed": 0,
  "failed": 0
}
```

#### Scenario: Batch submission with feature flag ON

- GIVEN `USE_BATCH_ANALYSIS=true`
- WHEN `POST /analyze/batch` is called with 3 valid email objects
- THEN the response is HTTP 202
- AND the response contains a valid `batch_id`
- AND `total` equals 3
- AND `status` is `"pending"`

#### Scenario: Batch submission with feature flag OFF

- GIVEN `USE_BATCH_ANALYSIS=false` (default)
- WHEN `POST /analyze/batch` is called
- THEN the endpoint returns HTTP 404
- AND the body contains `{ "error": "feature_disabled", "message": "Batch analysis is not enabled" }`

#### Scenario: Empty email list rejected

- GIVEN `USE_BATCH_ANALYSIS=true`
- WHEN `POST /analyze/batch` is called with an empty `emails` array
- THEN the response is HTTP 422
- AND the error message indicates at least 1 email is required

#### Scenario: Max batch size enforced

- GIVEN `USE_BATCH_ANALYSIS=true`
- WHEN `POST /analyze/batch` is called with more than 100 emails
- THEN the response is HTTP 422
- AND the error message indicates the max batch size is 100

### Requirement BA-2: GET /analyze/batch/{batch_id} polling endpoint

The system MUST provide `GET /analyze/batch/{batch_id}` for polling batch status and retrieving results.

**Response** (when running):
```json
{
  "batch_id": "uuid-string",
  "status": "running",
  "total": 5,
  "completed": 2,
  "failed": 0,
  "progress_pct": 40.0
}
```

**Response** (when complete):
```json
{
  "batch_id": "uuid-string",
  "status": "completed",
  "total": 5,
  "completed": 5,
  "failed": 0,
  "progress_pct": 100.0,
  "results": [
    {
      "email_id": "string",
      "verdict": "safe|suspicious|phishing",
      "confidence": 0.95,
      "reason": "string",
      "indicators": ["string"]
    }
  ]
}
```

#### Scenario: Poll batch during processing

- GIVEN `USE_BATCH_ANALYSIS=true` and a submitted batch is still running
- WHEN `GET /analyze/batch/{batch_id}` is called
- THEN the response shows `status: "running"` and 0 < `completed` < `total`

#### Scenario: Poll completed batch

- GIVEN `USE_BATCH_ANALYSIS=true` and a batch has finished processing
- WHEN `GET /analyze/batch/{batch_id}` is called
- THEN the response shows `status: "completed"`
- AND `completed` equals `total`
- AND `results` is present with all analysis results

#### Scenario: Poll non-existent batch

- GIVEN `USE_BATCH_ANALYSIS=true`
- WHEN `GET /analyze/batch/non-existent-id` is called
- THEN the response is HTTP 404
- AND the body contains `{ "error": "batch_not_found", "message": "No batch found with that ID" }`

### Requirement BA-3: Background processing with concurrency limit

The system MUST process batch analyses in the background (via `asyncio.create_task` or `BackgroundTasks`) and MUST NOT exceed a configurable concurrency limit (default 5).

#### Scenario: Concurrent batch limit enforced

- GIVEN `USE_BATCH_ANALYSIS=true` and 3 batches are already running (15 emails total)
- WHEN a 4th batch is submitted
- THEN the system processes the new batch at the same time (under the limit)
- AND no error is returned

#### Scenario: Auto-cleanup of completed batches

- GIVEN `USE_BATCH_ANALYSIS=true` and a batch completed more than 1 hour ago
- WHEN the batch is polled
- THEN the system SHOULD still return the results (completed batches are NOT immediately cleaned up)
- AND batches older than 1 hour MAY be cleaned up to free memory
- AND accessing a cleaned-up batch returns 404

### Non-Requirements (BA)

- No WebSocket or SSE streaming for batch progress
- No batch cancellation endpoint
- No persistent batch storage (in-memory only, lost on restart)
- No priority queue

---

## Cross-Cutting Requirements

### CC-1: Config-gated feature discovery

All new endpoints MUST return HTTP 404 with `{ "error": "feature_disabled", "message": "..." }` when their corresponding config flag is set to `false` (or absent).

| Endpoint | Config Flag |
|----------|-------------|
| `POST /analyze/deep` | `USE_RAG` |
| `POST /analyze/batch` | `USE_BATCH_ANALYSIS` |
| `GET /analyze/batch/{batch_id}` | `USE_BATCH_ANALYSIS` |

### CC-2: Extension compatibility guarantee

All changes MUST be compatible with the existing Chrome MV3 extension without modifications. Specifically:
- `POST /analyze` response MUST remain parseable by existing extension code
- No new required fields or headers in existing endpoints
- The `/api/` prefix dashboard endpoints are extension-internal, but remain unchanged

### CC-3: Existing test suite must pass

All existing tests in `backend/tests/` MUST continue to pass with zero modifications, regardless of which feature flags are enabled or disabled.

---

## Scenarios Summary

| Feature | Happy | Flag OFF | Error | Edge |
|---------|-------|----------|-------|------|
| PS | Dual-write succeeds | No SQLite created | Write failure non-fatal | Idempotent init |
| GV2 | Structured output parsed | Falls to v1 | v2 fail → v1 fallback | Cache eviction |
| DE | CSV with data | Empty CSV | N/A | Export button renders |
| AD | anomaly_score computed | anomaly_score null | N/A | Patterns survive restart |
| RAG | Deep analysis with matches | 404 feature_disabled | Embedding fails → fallback | Similarity threshold |
| BA | 202 accepted + poll done | 404 feature_disabled | 422 empty/max | Auto-cleanup after 1h |

---

## Error Code Additions

| Code | HTTP | Feature | Meaning |
|------|------|---------|---------|
| `feature_disabled` | 404 | All (config-gated) | Feature flag is not enabled |
| `batch_not_found` | 404 | BA | Batch ID does not exist or was cleaned up |
| `batch_max_exceeded` | 422 | BA | More than 100 emails in one batch request |
