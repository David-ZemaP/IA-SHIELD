# 🛡️ IA-Shield — Detección de Phishing con Gemini + Chrome Extension

**IA-Shield** es un sistema de detección proactiva de phishing en Gmail que combina:

- **Gemini 2.5 Flash** (IA generativa) para análisis semántico de correos
- **MCP (Model Context Protocol)** para verificación de URLs en tiempo real
- **Chrome Extension MV3** con análisis automático cada 60s
- **Detección de homoglyphs** (paypa1 → paypal) por distancia de Levenshtein

---

## 🔥 Lo más interesante del proyecto

### 1. Análisis dual con Gemini + detección local

No depende únicamente de la IA. Si Gemini falla (timeout, cuota), el sistema cae a un análisis local con reglas heurísticas. Esto asegura que **nunca** se quede sin responder.

### 2. Rate limiting inteligente (10 req/min)

El backend limita el análisis a 10 requests por minuto vía slowapi, protegiendo tanto al backend como a la cuota de Gemini. Si se excede, responde `429 Too Many Requests`.

### 3. Homoglyph detection con Levenshtein

Detecta URLs que suplantan dominios conocidos usando distancia de edición. `paypa1.com` → similitud 83% con `paypal`. `go0gle.com` → similitud 83% con `google`.

### 4. Encriptación AES-256-GCM de tokens

Los tokens OAuth se encriptan con Fernet antes de almacenarse en `chrome.storage`. El backend expone funciones dedicadas para encriptar/desencriptar en el borde entre backend y extensión.

### 5. Análisis 100% automático

La extensión analiza emails nuevos automáticamente:
- Al cargar la extensión
- Cada 60 segundos (vía `chrome.alarms`)
- Con badge que muestra el conteo de amenazas
- Con notificaciones push de Chrome si detecta phishing con confianza > 80%

---

## 🧠 Cómo se aplica Gemini

```
Email nuevo
    │
    ▼
[1] Extracción de texto (subject + body + sender + metadatos)
    │
    ▼
[2] Se envía a Gemini 2.5 Flash via API v1beta
    ├─ Prompt: "Analiza este email para detectar phishing..."
    ├─ Contexto: 10+ patrones de phishing conocidos
    └─ Safety: Instrucciones de evitar falsos positivos
    │
    ▼
[3] Gemini devuelve JSON con:
    ├─ verdict: "safe" | "suspicious" | "phishing"
    ├─ confidence: 0.0 - 1.0
    ├─ reason: explicación en español
    └─ indicators: lista de banderas rojas
    │
    ▼
[4] Se combina con:
    ├─ Análisis local de URLs (Safe Browsing + patrones)
    ├─ Detección de homoglyphs en URLs
    └─ Reglas heurísticas (TLDs sospechosos, hosting acortadores)
    │
    ▼
[5] Verdeto final + notificación si es necesario
```

**Gemini usa el modelo `gemini-2.5-flash`** con la API `v1beta` (no v1) para mejor rendimiento en clasificación de texto. El prompt está en español y pide explícitamente que **no invente** si no está segura.

---

## 🔌 Cómo se aplica MCP (Model Context Protocol)

MCP es el protocolo estándar para que los LLMs interactúen con herramientas externas. En IA-Shield:

```
┌──────────────┐      POST /mcp/verify       ┌─────────────────────┐
│  Backend     │ ──────────────────────────►  │   MCP Server        │
│  FastAPI     │                              │   (JSON-RPC over    │
│  /analyze    │ ◄──────────────────────────  │    HTTP)            │
│              │      {url, malicious, ...}    │                     │
└──────────────┘                              │  tools/             │
                                              │   safebrowsing.py   │
                                              │   └── Safe Browsing │
                                              │       API de Google │
                                              └─────────────────────┘
```

El MCP Server:
- Corre como servicio separado en Docker (`mcp-server:9000`)
- Expone el endpoint `/tools/verify-url` usando JSON-RPC sobre HTTP
- Verifica URLs contra la **Google Safe Browsing API**
- **No bloquea** si falla — siempre devuelve un resultado seguro por defecto

Si el MCP no responde, el análisis continúa sin URLs verificadas. Esto asegura **resiliencia total**.

---

## 📦 Stack técnico

| Capa | Tecnología |
|------|-----------|
| **Frontend** | Chrome Extension MV3 (JavaScript vanilla) |
| **Backend** | Python FastAPI (uvicorn) |
| **IA** | Google Gemini 2.5 Flash |
| **Protocolo** | MCP (Model Context Protocol) vía JSON-RPC |
| **Seguridad** | OAuth 2.0 PKCE, AES-256-GCM (Fernet) |
| **Rate limiting** | slowapi (10 req/min) |
| **Testing** | pytest + pytest-asyncio |
| **Infra** | Docker Compose (3 servicios) |

---

## 🚀 Paso a paso: Cómo se usa

### 1. Requisitos

- Docker Desktop (recomendado) o Python 3.11+
- Google Chrome
- Gmail account (para testear)

### 2. Credenciales

Necesitás 3 claves gratuitas:

| Clave | Dónde obtenerla |
|-------|----------------|
| **Google OAuth Client ID** | [GCP Console](https://console.cloud.google.com/apis/credentials) → Crear OAuth 2.0 Web Application. Agregar redirect URI: `http://localhost:8000/auth/gmail/callback` |
| **Gemini API Key** | [Google AI Studio](https://aistudio.google.com/app/apikey) |
| **Safe Browsing API Key** | GCP Console → APIs → Safe Browsing API → Habilitar + Credenciales |

### 3. Configurar `.env`

```bash
# Copiar y editar
GOOGLE_CLIENT_ID=tu-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu-client-secret
GEMINI_API_KEY=tu-gemini-api-key
SAFE_BROWSING_API_KEY=tu-safebrowsing-key
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/gmail/callback
MCP_SERVER_URL=http://localhost:9001
```

### 4. Iniciar todo

```bash
docker compose up -d --build
```

Esto levanta 3 servicios:
- **Backend** → `http://localhost:8000`
- **MCP Server** → `http://localhost:9001`
- **Test** (se ejecuta y termina)

### 5. Cargar la extensión en Chrome

1. Abrí `chrome://extensions`
2. Activá **Developer mode**
3. Click **Load unpacked**
4. Seleccioná la carpeta `extension/`

### 6. Usar

```
1. Click en el icono de IA-Shield en la barra de Chrome
2. Click "Conectar con Gmail" → te redirige a Google
3. Aceptá los permisos de lectura de Gmail
4. Volvé a la extensión → los emails se cargan solos
5. Los emails nuevos se analizan automáticamente cada 60s
```

---

## 🤖 ¿Qué está automatizado?

| Funcionalidad | Automático | Descripción |
|---------------|-----------|-------------|
| **Análisis de emails** | ✅ | Cada 60s via `chrome.alarms`, más al cargar la extensión |
| **Detección de phishing** | ✅ | Gemini + reglas locales, sin intervención del usuario |
| **Verificación de URLs** | ✅ | MCP Server via Safe Browsing API |
| **Homoglyphs** | ✅ | Detección automática en todas las URLs extraídas |
| **Notificaciones** | ✅ | Push de Chrome si detecta phishing con confianza > 80% |
| **Badge update** | ✅ | El icono muestra el número de amenazas detectadas |
| **Token refresh** | ✅ | Si el token expira, se refresca automáticamente |
| **Rate limiting** | ✅ | 10 requests/min para proteger el backend y cuota de Gemini |
| **Encriptación** | ✅ | Tokens se encriptan al volver a la extensión |
| **Fallback sin Gemini** | ✅ | Si Gemini falla, usa reglas heurísticas locales |

---

## 📁 Estructura del proyecto

```
ia-shield/
├── backend/                          # FastAPI backend
│   ├── main.py                       # App + middlewares
│   ├── config.py                     # Settings desde .env
│   ├── requirements.txt
│   ├── routes/
│   │   ├── auth.py                   # OAuth PKCE + sesiones
│   │   ├── analyze.py                # Análisis con Gemini
│   │   ├── emails.py                 # Endpoints Gmail API
│   │   └── dashboard.py              # Stats + history
│   ├── services/
│   │   ├── oauth_service.py          # OAuth + token exchange
│   │   ├── gmail_service.py          # Gmail API client
│   │   ├── gemini_service.py         # Gemini prompt + analysis
│   │   ├── encryption.py             # AES-256-GCM (Fernet)
│   │   └── homoglyph.py              # Levenshtein detection
│   ├── middleware/
│   │   ├── cors_validation.py        # Extension ID validation
│   │   └── rate_limiter.py           # slowapi 10/min
│   ├── models/
│   │   └── schemas.py                # Pydantic models
│   └── tests/                        # pytest suite (14 tests)
│       ├── test_encryption.py
│       ├── test_auth.py
│       ├── test_analyze.py
│       └── test_rate_limit.py
│
├── extension/                        # Chrome Extension MV3
│   ├── manifest.json                 # Permisos declarativeNetRequest
│   ├── service-worker.js             # Polling + notificaciones
│   ├── blocked.html                  # Página de bloqueo con reportar
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   └── icons/
│
├── mcp-server/                       # MCP (JSON-RPC over HTTP)
│   ├── main.py                       # MCP server
│   ├── config.py
│   ├── requirements.txt
│   └── tools/
│       └── safebrowsing.py           # Safe Browsing API
│
├── docker-compose.yml
├── Dockerfile.backend
├── Dockerfile.mcp
└── .env                              # Variables de entorno
```

---

## 🧪 Tests

```bash
# Correr tests del backend
docker compose exec backend pytest tests/ -v

# Resultado esperado: 13 passed, 2 xfailed
# (2 xfailed = tests de auth que requieren implementación futura)
```

---

## 📊 Endpoints de la API

| Método | Ruta | Descripción |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/auth/gmail/login` | Inicia OAuth PKCE |
| `GET` | `/auth/gmail/callback` | Callback OAuth |
| `GET` | `/auth/session/{id}` | Verificar sesión |
| `POST` | `/analyze` | Analizar email (rate limited: 10/min) |
| `GET` | `/emails` | Listar emails |
| `GET` | `/api/dashboard/stats` | Estadísticas |
| `GET` | `/api/dashboard/history` | Historial de análisis |
| `POST` | `/api/dashboard/false-positive` | Reportar falso positivo |
| `GET` | `/docs` | Swagger UI |

---

## ⚠️ A mejorar (futuro)

- [ ] Autenticación en `/analyze` (actualmente no checkea session)
- [ ] Redis para rate limiting en producción
- [ ] HTTPS vía reverse proxy (nginx)
- [ ] Soporte para Outlook/Yahoo
- [ ] Dashboard con exportación CSV y gráficas
- [ ] Sincronización multi-dispositivo
