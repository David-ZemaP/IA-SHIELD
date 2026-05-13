# SDD Spec: phishing-extension-prototype

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Project**        | ia-seguridad                                                 |
| **Change**         | phishing-extension-prototype                                 |
| **Status**         | `spec`                                                       |
| **Deadline**       | 19 Mayo 2026                                                 |
| **Artifact Store** | engram                                                       |
| **Stack**          | FastAPI + Chrome MV3 + Gemini 1.5 Flash + Gmail API + Safe Browsing API |

---

## Executive Summary

This spec defines a Chrome Extension (Manifest V3) + FastAPI backend prototype that detects phishing emails in Gmail. The extension reads a user's Gmail inbox via OAuth 2.0, sends email content to a Gemini 1.5 Flash analysis pipeline, cross-checks URLs against Google Safe Browsing via an MCP server, and surfaces results through a browser popup badge, URL-blocking alerts, and a lightweight dashboard. The prototype is scoped to Gmail only — no Facebook or in-tab URL injection. No full test suite is included in this phase.

---

## Out of Scope

- Facebook / non-Gmail email providers
- In-tab URL blocking (declarativeNetRequest used for link clicks only)
- Full automated test suite (manual verification only)
- Production auth beyond Gmail OAuth (no SSO, no MFA enforcement)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Chrome MV3 Extension (JS/TS)                           │
│  ┌──────────┐  ┌──────────────┐  ┌───────────────────┐ │
│  │ Popup UI │  │ Service Worker│  │ webNavigation hook│ │
│  │ + Badge  │  │ (polling)     │  │ (URL blocking)    │ │
│  └────┬─────┘  └──────┬────────┘  └────────┬──────────┘ │
│       │               │                    │            │
│       ▼               ▼                    ▼            │
│  ┌─────────────────────────────────────────────────┐    │
│  │              background.js (MV3)                 │    │
│  │  - chrome.alarms (60s polling)                   │    │
│  │  - chrome.webNavigation.onBeforeNavigate        │    │
│  │  - chrome.declarativeNetRequest (dynamic rules)  │    │
│  └─────────────────────┬───────────────────────────┘    │
│                        │ fetch calls                     │
└────────────────────────┼─────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  FastAPI Backend (Python)                               │
│  ┌──────────────┐ ┌───────────────┐ ┌────────────────┐ │
│  │ /api/emails  │ │ /api/analyze  │ │ /api/mcp       │ │
│  │ + OAuth2     │ │ + Gemini LLM  │ │ + SafeBrowsing │ │
│  └──────────────┘ └───────────────┘ └────────────────┘ │
│  ┌──────────────────────────────────────────────────┐  │
│  │ /api/dashboard (stats + history)                  │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Artifacts

| Artifact | Format | Purpose |
|----------|--------|---------|
| This spec | Markdown | Full SDD delta spec |
| `backend/` | Python/FastAPI | Gmail reader, Gemini pipeline, MCP server, Dashboard |
| `extension/` | JS/TS Chrome MV3 | Popup, service worker, badge, URL blocking |
| `.atl/skill-registry.md` | Markdown | Skill registry (pre-existing) |

---

## Modules

### Module 1: Gmail OAuth + Email Reader

**Purpose**: Authenticate the user via Gmail OAuth 2.0 and read email data for phishing analysis.

#### Authentication Flow

- **Type**: OAuth 2.0 Authorization Code with PKCE (Proof Key for Code Exchange)
- **Provider**: Google Identity Platform
- **Scopes requested**:
  - `https://www.googleapis.com/auth/gmail.readonly`
  - `https://www.googleapis.com/auth/gmail.labels`
- **PKCE**: `code_verifier` (random 64-char string), `code_challenge` = `SHA256(code_verifier)` base64url-encoded

#### Happy Path

1. User clicks "Connect Gmail" in the extension popup.
2. Extension opens `https://accounts.google.com/o/oauth2/v2/auth?...&code_challenge=...&code_challenge_method=S256`
3. User grants permission → Google redirects to the registered `redirect_uri` with `?code=AUTH_CODE`
4. Extension sends `AUTH_CODE` + `code_verifier` to `POST /api/auth/token`
5. Backend exchanges code for tokens via Google's token endpoint
6. Backend stores `access_token`, `refresh_token`, `expires_at` (encrypted at rest)
7. Backend returns success to extension; extension stores session ID in `chrome.storage.local`

```
POST /api/auth/token
Request:  { code: string, code_verifier: string }
Response: { session_id: string, expires_at: ISO8601 }
```

#### Token Refresh

- Before any Gmail API call, backend checks `expires_at`.
- If expired: automatically calls Google's refresh endpoint with `refresh_token`.
- If refresh fails (refresh_token expired/revoked): returns `401`, extension forces re-auth.

**Endpoint**: `POST /api/auth/refresh`
```
Request:  { session_id: string }
Response: { access_token: string, expires_at: ISO8601 }
```

#### Email Listing

**Endpoint**: `GET /api/emails`
```
Query params:
  - maxResults (int, default: 50)
  - pageToken (string, optional)
  - labelId (string, optional, default: "INBOX")

Response: {
  emails: [
    {
      id: string,
      threadId: string,
      snippet: string,           // Plain text preview
      subject: string,
      from: string,              // Raw From header
      fromName: string | null,   // Parsed display name
      fromEmail: string | null,  // Parsed email address
      date: ISO8601,
      hasAttachments: boolean,
      labels: string[]
    }
  ],
  nextPageToken: string | null
}
```

#### Email Detail

**Endpoint**: `GET /api/emails/{id}`
```
Response: {
  id: string,
  threadId: string,
  subject: string,
  from: string,
  fromName: string | null,
  fromEmail: string | null,
  date: ISO8601,
  bodyPlain: string | null,
  bodyHtml: string | null,       // HTML stripped to text via <body>.textContent
  urls: string[],               // All <a href> URLs extracted from bodyHtml + regex in bodyPlain
  attachments: [
    { filename: string, mimeType: string, sizeBytes: number }
  ],
  labels: string[]
}
```

**HTML extraction logic**: Parse HTML with `BeautifulSoup`, get `.get_text(separator=' ', strip=True)`, extract all `<a href>` values via regex + soup.

#### Error Paths

| Scenario | HTTP Code | Response |
|----------|-----------|----------|
| No auth / session expired | `401` | `{ error: "auth_required", message: "Re-authentication needed" }` |
| Gmail API rate limit | `429` | `{ error: "rate_limited", message: "Retry after N seconds", retryAfter: number }` |
| User has zero emails | `200` | `{ emails: [], nextPageToken: null }` |
| Email ID not found | `404` | `{ error: "not_found", message: "Email not found" }` |
| Network error (Google unreachable) | `503` | `{ error: "upstream_unavailable", message: "Gmail API unreachable" }` |
| Corrupted email (no headers) | `200` | Email object with `subject: "(no subject)"`, `from: "unknown"` |

#### Edge Cases

- **Empty inbox**: Return empty array, no error.
- **Very large emails (>100KB body)**: Truncate `bodyPlain` and `bodyHtml` to 10,000 characters for analysis. Flag `truncated: true` in response.
- **Non-UTF8 encoding**: Transcode via `chardet` fallback, replace un-decodable bytes with `�`.
- **Multiple From addresses**: Take the first one; log a warning.

---

### Module 2: Gemini Analysis Pipeline

**Purpose**: Analyze email content using Gemini 1.5 Flash to detect phishing indicators.

#### System Prompt (Detector de Phishing)

```
Eres un detector de phishing avanzado. Tu tarea es analizar el contenido de un correo
electrónico y determinar si es legítimo, sospechoso o un intento de phishing.

Analiza los siguientes aspectos:
1. Remitente: ¿Es una dirección conocida o sospechosa? ¿Contiene errores tipográficos
   en el dominio (ej: g00gle.com, rnicrosoft.com)?
2. Asunto: ¿Usa urgencia, miedo, premios o amenazas para forzar acción inmediata?
3. Cuerpo: ¿Contiene enlaces a dominios distintos del supuesto remitente? ¿Pide
   credenciales, datos bancarios o información personal?
4. URLs: Verifica si los dominios usan homoglyphs, subdominios engañosos o redirecciones.
5. Tono y gramática: ¿Errores gramaticales excesivos o tono inusual?
6. Headers implícitos: Si el From muestra un nombre pero el email es de otro dominio,
   es una señal de spoofing.

Responde SIEMPRE en JSON con este formato exacto:
{
  "verdict": "safe" | "suspicious" | "phishing",
  "confidence": <float 0.0-1.0>,
  "reason": "<explicación concisa en español>",
  "indicators": ["<indicador 1>", "<indicador 2>", ...]
}

Reglas:
- Si hay al menos 2 indicadores fuertes de phishing → verdict: "phishing"
- Si hay 1 indicador o señales ambiguas → verdict: "suspicious"
- Si no hay señales sospechosas → verdict: "safe"
- NUNCA devuelvas claves adicionales fuera del esquema.
```

#### Input Payload

```json
POST /api/analyze
{
  "email_id": string,
  "subject": string,
  "from_name": string | null,
  "from_email": string | null,
  "body_plain": string | null,
  "body_html": string | null,
  "urls": string[]
}
```

#### Output (Gemini Response → Wrapped)

```json
{
  "analysis_id": UUID,
  "email_id": string,
  "verdict": "safe" | "suspicious" | "phishing" | "review_needed",
  "confidence": 0.0-1.0,
  "reason": string,
  "indicators": string[],
  "urls_analyzed": [
    {
      "url": string,
      "domain": string,
      "malicious": boolean,
      "threat_type": string | null
    }
  ],
  "model": "gemini-1.5-flash",
  "timestamp": ISO8601
}
```

#### Fallback: `review_needed`

If ANY of these conditions occur, the pipeline sets `verdict: "review_needed"`:

1. Gemini API returns an error (5xx, timeout > 30s, rate limit 429)
2. Gemini returns malformed JSON or missing required fields
3. Confidence score cannot be parsed
4. Total analysis time exceeds 45 seconds

When `review_needed`, the system:
- Logs the error to `analysis_errors` store
- Returns `review_needed` to the extension
- Displays a yellow "?" badge instead of red/green
- Queues the email for manual review in the Dashboard

#### Edge Cases

| Scenario | Behavior |
|----------|----------|
| Empty body (both plain and HTML) | Send system prompt with `"<email sin cuerpo>"`; expect `safe` with low confidence |
| Body is binary/encoded (base64 attachment as body) | Skip analysis, return `{ verdict: "review_needed", reason: "Cuerpo no parseable" }` |
| Gemini returns HTTP 500 | Retry once with exponential backoff (1s → 2s). If still fails → `review_needed` |
| Gemini returns output outside JSON schema | Attempt to extract JSON via regex; if fails → `review_needed` |
| Email is very long (>50K chars total) | Truncate to 50K chars, add `[TRUNCATED]` marker to prompt |

---

### Module 3: MCP Server + Safe Browsing

**Purpose**: Provide a Model Context Protocol (MCP) server that wraps the Google Safe Browsing API v4 for the extension and backend to query URL safety.

#### MCP Protocol Implementation

The MCP server runs as a separate process (or as a FastAPI sub-route `/mcp`) that implements the MCP JSON-RPC 2.0 specification.

**Transport**: Stdio (for local extension communication) AND SSE (for remote FastAPI calls)

**Server capabilities**:
- `tools/list` → advertises one tool: `verify_url`

#### Tool: `verify_url`

```
Name: verify_url
Description: Consulta la API de Google Safe Browsing para verificar si una URL es maliciosa
Input: { url: string }
Output: {
  malicious: boolean,
  threat_type: string | null,      // "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION", null
  platform: string | null,         // "ANY_PLATFORM", "WINDOWS", "LINUX", "ANDROID", "OSX", null
  threat_entry_type: string | null // "URL", "EXECUTABLE", etc.
}
```

#### Internal Safe Browsing Integration

- Uses Google Safe Browsing API v4 (`https://safebrowsing.googleapis.com/v4/threatMatches:find`)
- API key stored in environment variable `SB_API_KEY`
- Request body uses `{ client: { clientId: "ia-seguridad", clientVersion: "1.0" }, threatInfo: { ... } }`
- Supports all threat types: `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, `POTENTIALLY_HARMFUL_APPLICATION`

#### Cache Layer

- URL results cached in memory (LRU, 10,000 entries, TTL 30 minutes)
- Reduces API calls and rate limit risk
- Cache key = SHA256 of normalized URL

#### MCP Request/Response Examples

**Request**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "verify_url",
    "arguments": { "url": "https://g00gle.com/login" }
  }
}
```

**Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "malicious": true,
    "threat_type": "SOCIAL_ENGINEERING",
    "platform": "ANY_PLATFORM",
    "threat_entry_type": "URL"
  }
}
```

#### Error Paths

| Scenario | Response |
|----------|----------|
| URL format invalid | `{ error: "invalid_url", message: "URL proporcionada no es válida" }`, code: `-32602` |
| Safe Browsing API 5xx | Retry once; if fails → `{ malicious: false, threat_type: null, cached: false, error: "upstream_error" }` (fail-open for safety → but conservative: return `malicious: true` with `error` flag) |
| API key not configured | `{ error: "config_error", message: "SB_API_KEY no configurada" }`, code: `-32603` |
| Rate limit (429) | Wait + retry with backoff; if exhausted → `{ malicious: null, error: "rate_limited" }` |
| Malformed response from Google | `{ malicious: false, error: "parse_error" }` + log warning |

#### Edge Cases

- **URL with fragments/anchors**: Strip fragment before lookup (fragments are client-side only)
- **URL with port**: Include port in lookup (different services on different ports)
- **IP addresses**: Safe Browsing supports direct IP lookup — pass through as-is
- **Empty URL**: Return error immediately, do not call upstream

---

### Module 4: Chrome Extension MV3 — Popup + Badge

**Purpose**: Browser extension that shows phishing status via popup and badge.

#### Manifest V3 Structure

```
extension/
├── manifest.json
├── background.js              (Service Worker — no background.html)
├── popup.html
├── popup.js
├── popup.css
├── icons/
│   ├── icon-16.png
│   ├── icon-48.png
│   ├── icon-128.png
│   ├── icon-safe.png          (verde)
│   ├── icon-suspicious.png    (amarillo)
│   └── icon-phishing.png      (rojo)
└── content.js                 (NO manifest content scripts — no inyección en páginas)
```

**`manifest.json`**:
```json
{
  "manifest_version": 3,
  "name": "IA Seguridad — Phishing Detector",
  "version": "1.0.0",
  "description": "Detecta emails de phishing en Gmail usando IA",
  "permissions": ["storage", "alarms", "identity"],
  "host_permissions": ["https://mail.google.com/*"],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html",
    "default_icon": {
      "16": "icons/icon-16.png",
     48: "icons/icon-48.png",
      128: "icons/icon-128.png"
    }
  },
  "icons": {
    "16": "icons/icon-16.png",
    "48": "icons/icon-48.png",
    "128": "icons/icon-128.png"
  }
}
```

#### Service Worker (`background.js`)

**Polling**: Uses `chrome.alarms.create("poll-gmail", { periodInMinutes: 1 })` to trigger every **60 seconds**.

On alarm:
1. Check if auth session exists in `chrome.storage.local`
2. If yes: call `GET /api/emails` on backend
3. Call `GET /api/analyze` for each new/unanalyzed email
4. Aggregate: count of phishing, suspicious, safe
5. Update badge text: `"3⚠"` (count of suspicious + phishing)
6. Update badge color:
   - 🟢 Green: all safe
   - 🟡 Yellow: suspicious detected
   - 🔴 Red: phishing detected
7. Store results in `chrome.storage.local` for popup

**Badge API**:
```javascript
chrome.action.setBadgeText({ text: "3" });
chrome.action.setBadgeBackgroundColor({ color: "#FF4444" }); // red
chrome.action.setBadgeTextColor({ color: "#FFFFFF" });
```

**Re-auth flow**: If API returns 401, open `chrome.identity.launchWebAuthFlow(...)` for re-auth.

#### Popup UI (`popup.html` + `popup.js`)

**Layout**:
- Header: "IA Seguridad — Estado del Correo"
- Connection status indicator (connected/disconnected)
- List of recent 20 emails with:
  - Subject
  - From (name + email)
  - Date
  - Badge: 🟢 Safe / 🟡 Suspicious / 🔴 Phishing / ❓ Review Needed
  - Click → opens email detail modal

**Badge colors** (on toolbar icon overlay):
- Green circle with checkmark: all emails safe
- Yellow triangle: suspicious emails found
- Red exclamation mark: phishing detected
- Grey question mark: `review_needed` items exist

#### Error Paths

| Scenario | Behavior |
|----------|----------|
| No internet | Badge shows "!" in grey; popup shows "Sin conexión" |
| Token expired mid-session | Auto-triggers re-auth flow via `chrome.identity` |
| Backend unreachable | Badge unchanged; popup shows "Backend no disponible" with retry button |
| Gmail scope not granted | Shows "Conectar Gmail" button; explains required permissions |
| Chrome storage full | Falls back to in-memory variables; logs warning |

#### Edge Cases

- **First install**: No auth → show "Conectar Gmail" prompt, no badge until connected
- **User revokes Gmail access**: 401 on next poll → clear stored tokens, force re-auth
- **Very large inbox (1000+ emails)**: Only poll first 50 per cycle; rotate through pagination over multiple cycles
- **Extension reloaded**: Service worker restarts; re-establishes alarm and fetches latest state

---

### Module 5: URL Blocking + Alert

**Purpose**: Intercept link clicks in Gmail emails and verify URLs before navigation.

#### Implementation Strategy

**Layer 1: `chrome.webNavigation.onBeforeNavigate`**

In background.js:
```javascript
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only intercept clicks from Gmail tabs
  if (!details.url.startsWith('https://mail.google.com')) return;

  const clickedUrl = extractUrlFromClick(details);
  if (!clickedUrl) return;

  const result = await fetch('/api/mcp/verify', {
    method: 'POST',
    body: JSON.stringify({ url: clickedUrl })
  });

  if (result.malicious) {
    // Cancel navigation
    // Show overlay alert via chrome.tabs.sendMessage
    chrome.tabs.sendMessage(details.tabId, {
      type: 'URL_BLOCKED_ALERT',
      url: clickedUrl,
      threatType: result.threat_type
    });
    // Cancel: return { cancel: true } — NOT available in onBeforeNavigate
  }
});
```

> **Nota**: `onBeforeNavigate` in MV3 **cannot cancel** navigation directly. For actual blocking, use `declarativeNetRequest`.

**Layer 2: `chrome.declarativeNetRequest` (dynamic rules)**

When a URL is confirmed malicious:
1. Backend adds the URL's domain to a dynamic block list
2. Extension creates a `declarativeNetRequest` dynamic rule:
```javascript
chrome.declarativeNetRequest.updateDynamicRules({
  addRules: [{
    id: uniqueRuleId,
    priority: 1,
    action: { type: 'block' },
    condition: {
      urlFilter: domain,
      resourceTypes: ['main_frame']
    }
  }]
});
```
3. Future navigations to that domain are blocked at browser level
4. A redirect page (`blocked.html`) shows the alert with threat details

#### Alert Overlay (`blocked.html`)

```
┌────────────────────────────────────────────┐
│  ⚠️ ALERTA DE SEGURIDAD                    │
│                                            │
│  La URL que intentas visitar fue           │
│  identificada como: PHISHING               │
│                                            │
│  URL: https://malicious-site.example.com   │
│  Tipo de amenaza: Ingeniería social        │
│                                            │
│  [Volver al correo]    [Reportar falso     │
│                         positivo]          │
└────────────────────────────────────────────┘
```

#### Error Paths

| Scenario | Behavior |
|----------|----------|
| MCP server down | URL is NOT blocked (fail-open); log error; show "no se pudo verificar" warning |
| URL extraction fails | Allow navigation silently; log error |
| `declarativeNetRequest` rule limit reached (30K max) | Evict oldest rules by LRU; log warning |
| False positive reported by user | Remove dynamic rule for that domain; send feedback to backend |

#### Edge Cases

- **URLs in email body obfuscated via redirectors** (e.g., `https://go.company.com/?url=encoded`): Resolve via HEAD request on backend before adding to block list
- **Same domain used for legitimate and malicious pages**: Block at URL path level, not just domain
- **Multiple clicks in rapid succession**: Debounce; only verify once per unique URL per session

---

### Module 6: Dashboard Backend

**Purpose**: Web dashboard showing aggregated phishing analysis statistics.

**Note**: No authentication (prototipo). Protected behind localhost-only binding in dev mode.

#### Endpoints

**`GET /api/dashboard/stats`**
```
Response: {
  "total_analyzed": number,
  "phishing_detected": number,
  "suspicious": number,
  "safe": number,
  "review_needed": number,
  "false_positives_reported": number,
  "url_blocks_active": number,
  "last_analysis_at": ISO8601 | null
}
```

**`GET /api/dashboard/history`**
```
Query params:
  - limit (int, default: 50)
  - offset (int, default: 0)
  - verdict (string, optional: "phishing"|"suspicious"|"safe"|"review_needed")

Response: {
  "items": [
    {
      "analysis_id": UUID,
      "email_id": string,
      "subject": string,
      "from": string,
      "verdict": string,
      "confidence": number,
      "reason": string,
      "indicators": string[],
      "timestamp": ISO8601
    }
  ],
  "total": number,
  "has_more": boolean
}
```

**`POST /api/dashboard/false-positive`** (Feedback)
```
Request: {
  "analysis_id": UUID,
  "reason": string
}
Response: { success: true }
```
This endpoint records a false positive report, which is used to improve the Gemini prompt over time.

#### Dashboard UI (Stretch)

Simple HTML page at `/dashboard` with:
- Summary cards showing counts
- Table with last 50 analyses
- Color-coded verdicts
- "Report false positive" button per row

#### Error Paths

| Scenario | HTTP Code | Response |
|----------|-----------|----------|
| No analyses yet | `200` | `{ total_analyzed: 0, ... all zeros }` |
| Invalid limit/offset | `400` | `{ error: "validation_error", message: "..." }` |
| Analysis ID not found in false-positive report | `404` | `{ error: "not_found" }` |

#### Edge Cases

- **Concurrent access**: Stats are derived from a single in-memory store + engram persistence; use async locks
- **High volume**: History endpoint paginates; never returns more than 100 items even if limit > 100
- **Empty database**: All counts return 0; history returns empty array

---

## Requirements

### Functional Requirements

| ID | Requirement | Module |
|----|-------------|--------|
| R1 | User can authenticate with Gmail via OAuth 2.0 + PKCE | Module 1 |
| R2 | System reads email subject, sender, and body (plain + HTML stripped) | Module 1 |
| R3 | Email list supports pagination (maxResults, pageToken) | Module 1 |
| R4 | Token refresh is automatic before expiry | Module 1 |
| R5 | Gemini analyzes email and returns verdict + confidence + indicators | Module 2 |
| R6 | Fallback to `review_needed` when Gemini is unavailable | Module 2 |
| R7 | MCP server exposes `verify_url` tool | Module 3 |
| R8 | MCP queries Google Safe Browsing API v4 | Module 3 |
| R9 | URL results are cached (30 min TTL, 10K entries) | Module 3 |
| R10 | Extension shows color-coded badge on toolbar | Module 4 |
| R11 | Popup shows list of emails with verdicts | Module 4 |
| R12 | Service worker polls Gmail every 60 seconds | Module 4 |
| R13 | Malicious URLs are blocked via declarativeNetRequest | Module 5 |
| R14 | Alert overlay shows when navigation is blocked | Module 5 |
| R15 | Dashboard shows aggregate stats | Module 6 |
| R16 | Dashboard shows last 50 analyses with details | Module 6 |
| R17 | Users can report false positives | Module 6 |
| R18 | All analysis results are persisted via engram | All |

### Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR1 | Extension compatible with Chrome 120+ |
| NFR2 | Backend API response time < 2s for `/api/emails` |
| NFR3 | End-to-end analysis latency < 15s (email read + Gemini + Safe Browsing) |
| NFR4 | Badge updates within 60s of new email arrival |
| NFR5 | Extension uses < 50MB RAM |
| NFR6 | All API responses are JSON with consistent error format |
| NFR7 | Secrets (API keys, tokens) never logged or exposed in responses |

### Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11+, FastAPI |
| AI Model | Google Gemini 1.5 Flash (free tier) |
| Email | Gmail API (OAuth 2.0) |
| URL Safety | Google Safe Browsing API v4 |
| Protocol | MCP (JSON-RPC 2.0 over SSE) |
| Extension | Chrome MV3 (JS/TS) |
| Storage | engram (persistent memory) |
| Auth state | `chrome.storage.local` + backend encrypted session store |

---

## Scenarios

### Scenario 1: Happy Path — Phishing Detected

1. **User** opens Gmail in Chrome
2. **Service worker** fires alarm (60s poll)
3. **Backend** calls Gmail API → retrieves 50 emails
4. **Backend** sends top 10 new emails to Gemini
5. **Gemini** returns: `{ verdict: "phishing", confidence: 0.94, reason: "Dominio 'g00gle.com' es un homoglyph de 'google.com'", indicators: ["dominio_homoglyph", "pedido_credenciales_urgente"] }`
6. **Backend** also extracts URLs from email → queries MCP → MCP calls Safe Browsing → confirms malicious
7. **Badge** turns red with count "1"
8. **User** clicks popup → sees email listed as 🔴 Phishing with reason
9. **User** clicks the link in the email → `declarativeNetRequest` blocks navigation → overlay shows "⚠️ ALERTA: URL bloqueada"

### Scenario 2: Happy Path — Safe Email

1. Service worker polls
2. Email analyzed by Gemini → `{ verdict: "safe", confidence: 0.91 }`
3. All URLs pass Safe Browsing
4. Badge stays green
5. Email shown as ✅ Safe in popup

### Scenario 3: Suspicious Email (Manual Review)

1. Gemini returns `{ verdict: "suspicious", confidence: 0.55 }`
2. Safe Browsing says URL is clean
3. Badge turns yellow
4. Email shown as 🟡 Suspicious with indicators
5. User can dismiss or report

### Scenario 4: Gemini Down — Fallback

1. Service worker polls
2. Backend sends email to Gemini → receives HTTP 503
3. Backend retries once with 2s backoff → 503 again
4. Backend marks `verdict: "review_needed"`, stores error in `analysis_errors`
5. Badge shows ❓ grey question mark
6. Dashboard shows email in "Needs Review" queue

### Scenario 5: Token Expired During Polling

1. Service worker polls
2. Backend tries Gmail API → returns 401
3. Backend attempts token refresh → succeeds
4. Gmail call retried with new token
5. Normal flow continues

### Scenario 6: Token Refresh Failed

1. Refresh token expired (user revoked access or > 6 months old)
2. Refresh → 400 from Google
3. Backend returns 401 to extension
4. Extension clears stored session
5. Popup shows "Conectar Gmail" button

### Scenario 7: User Reports False Positive

1. User sees email flagged as phishing but it's legitimate
2. Clicks "Reportar falso positivo" in popup
3. `POST /api/dashboard/false-positive` called with `analysis_id`
4. Backend records report in engram
5. Dashboard updates `false_positives_reported` counter

### Scenario 8: First Install Experience

1. User installs extension
2. Badge shows "—" (no data yet)
3. Popup shows "Conecta tu cuenta de Gmail" with Connect button
4. User clicks → OAuth flow begins
5. After auth, first poll fetches emails
6. Badges update normally

---

## Error Handling Specification

### Global Error Format

All error responses follow this structure:
```json
{
  "error": "error_code",
  "message": "Descripción del error en español",
  "details": { }
}
```

### Error Code Registry

| Code | HTTP | Meaning |
|------|------|---------|
| `auth_required` | 401 | Authentication needed or session expired |
| `auth_failed` | 401 | Token exchange failed |
| `rate_limited` | 429 | Rate limit hit, retry after delay |
| `not_found` | 404 | Resource not found |
| `validation_error` | 400 | Invalid input data |
| `upstream_unavailable` | 503 | Gmail / Gemini / Safe Browsing API down |
| `analysis_failed` | 502 | Gemini analysis failed (after retries) |
| `config_error` | 500 | Missing environment variable or config |
| `internal_error` | 500 | Unexpected error (generic) |
| `invalid_url` | 400 | URL format not valid for Safe Browsing |
| `mcp_error` | 502 | MCP server communication failure |

### Retry Policy

| Target | Max Retries | Backoff | After Exhaustion |
|--------|-------------|---------|------------------|
| Gmail API | 3 | Linear: 1s, 2s, 3s | Return 503 upstream_unavailable |
| Gemini API | 2 | Exponential: 1s, 2s | Mark as `review_needed` |
| Safe Browsing API | 2 | Linear: 1s, 2s | Return `{ malicious: true, error: "upstream_error" }` (fail-closed) |
| MCP Server (local) | 1 | Immediate | Return 503 |

### Degradation Strategy

- **Gmail unreachable**: Badge freezes at last known state; popup shows "Sin conexión a Gmail"
- **Gemini down**: Emails are listed but marked `review_needed`; no analysis shown
- **Safe Browsing down**: Clicking links shows "No se pudo verificar esta URL" warning; navigation proceeds (fail-open for UX, but logged as warning)
- **Both Gemini AND Safe Browsing down**: Extension enters "monitor-only" mode — shows emails but no analysis

---

## Skill Resolution

These skills from the environment will be used during implementation:

| Skill | Phase | Purpose |
|-------|-------|---------|
| `sdd-spec` | (current) | Write this spec |
| `sdd-design` | Post-spec | Create technical design (data models, DB schema, component diagrams) |
| `sdd-tasks` | Post-design | Break into implementation tasks |
| `sdd-apply` | Post-tasks | Implement the code |
| `sdd-verify` | Post-apply | Verify implementation matches spec |
| `sdd-archive` | Post-verify | Archive completed change |
| `go-testing` | If tests added later | Go test patterns (if Go components added) |

---

## Data Model (Simplified)

```
AnalysisRecord {
  id: UUID
  email_id: string
  subject: string
  from_name: string | null
  from_email: string | null
  body_plain: string | null
  urls: string[]
  verdict: "safe" | "suspicious" | "phishing" | "review_needed"
  confidence: float
  reason: string
  indicators: string[]
  url_results: URLAnalysis[]
  model: string
  timestamp: DateTime
  false_positive_reported: boolean
}

URLAnalysis {
  url: string
  domain: string
  malicious: boolean
  threat_type: string | null
  platform: string | null
}

Session {
  id: string
  access_token: string (encrypted)
  refresh_token: string (encrypted)
  expires_at: DateTime
  gmail_user_email: string
}
```

---

## Acceptance Criteria Summary

- [ ] OAuth 2.0 + PKCE flow works end-to-end
- [ ] Token refresh triggers automatically before expiry
- [ ] Email listing returns subject, from, body, URLs
- [ ] Gemini analysis returns verdict + confidence + indicators in correct schema
- [ ] Fallback to `review_needed` works when Gemini is down
- [ ] MCP `verify_url` tool returns Safe Browsing results
- [ ] URL caching works (30min TTL, LRU eviction)
- [ ] Chrome badge shows correct color/number
- [ ] Popup lists emails with verdicts
- [ ] Service worker polls every 60s
- [ ] Malicious URL click triggers alert overlay + navigation block
- [ ] Dashboard `/stats` returns correct totals
- [ ] Dashboard `/history` returns paginated results
- [ ] False positive reporting works
- [ ] All error paths return correct HTTP codes and messages
- [ ] Edge cases (empty inbox, large emails, network failures) handled gracefully