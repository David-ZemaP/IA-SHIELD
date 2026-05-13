# IA-Seguridad — Phishing Detection Extension

Prototipo de extensión Chrome (MV3) + backend FastAPI para detección proactiva de phishing en Gmail usando Gemini AI + MCP (Model Context Protocol).

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────┐
│              CHROME EXTENSION (MV3)                     │
│  ┌─────────┐  ┌──────────┐  ┌───────────────────┐     │
│  │ Service │  │  Popup   │  │  Auth Callback    │     │
│  │ Worker  │  │   UI     │  │  (OAuth flow)     │     │
│  └────┬────┘  └────┬─────┘  └─────────┬─────────┘     │
│       │            │                  │                │
│       └────────────┴──────────────────┘                │
│                    │                                   │
│                    ▼ HTTP + Cookie                     │
│         ┌─────────────────────────┐                   │
│         │     BACKEND FastAPI      │                   │
│         │  ┌───────────────────┐  │                   │
│         │  │  /auth  — OAuth   │  │                   │
│         │  │  /emails — Gmail  │  │                   │
│         │  │  /analyze — IA   │  │                   │
│         │  │  /dashboard — Stats│                  │
│         │  └─────────┬─────────┘  │                   │
│         │            │            │                   │
│         │   ┌────────┴───────┐    │                   │
│         │   │  Gemini 1.5   │    │                   │
│         │   │  Flash (IA)   │    │                   │
│         │   └────────┬───────┘    │                   │
│         │            │            │                   │
│         │   ┌────────▼───────┐   │                   │
│         │   │  MCP Server    │   │                   │
│         │   │  Safe Browsing │   │                   │
│         │   └────────────────┘   │                   │
│         └─────────────────────────┘                   │
└─────────────────────────────────────────────────────────┘
```

---

## Setup Rápido (Día 1)

### 1. Credenciales GCP

Necesitás crear un proyecto en [Google Cloud Console](https://console.cloud.google.com) y habilitar:

- **Gmail API** (`gmail.googleapis.com`)
- **Safe Browsing API** (opcional, para verificación de URLs)

Luego crear un **OAuth 2.0 Client ID** (tipo "Web application") y copiar el Client ID y Secret.

### 2. API Keys

- **GEMINI_API_KEY**: Obtener de [Google AI Studio](https://aistudio.google.com/app/apikey)
- **SAFE_BROWSING_API_KEY**: En GCP Console → APIs y Servicios → Safe Browsing API → Credenciales

### 3. Variables de Entorno

```bash
# backend/.env (crear archivo)
GOOGLE_CLIENT_ID=tu-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=tu-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/gmail/callback
GEMINI_API_KEY=tu-gemini-api-key
SAFE_BROWSING_API_KEY=tu-safebrowsing-key
APP_HOST=0.0.0.0
APP_PORT=8000
```

### 4. Instalar Dependencias

```bash
# Backend
cd backend
pip install -r requirements.txt

# MCP Server
cd mcp-server
pip install -r requirements.txt
```

### 5. Ejecutar

```bash
# Terminal 1 — Backend
cd backend
python -m uvicorn main:app --reload --port 8000

# Terminal 2 — MCP Server
cd mcp-server
python -m uvicorn main:app --reload --port 9000
```

### 6. Cargar Extensión en Chrome

1. Abrir `chrome://extensions`
2. Toggle **Developer mode** (arriba a la derecha)
3. Click **Load unpacked**
4. Seleccionar la carpeta `extension/`

---

## Docker Setup (Alternativo)

Si no tenés Python instalado, podés ejecutar todo con Docker.

### 1. Crear archivo `.env`

```bash
# Copiar el template
cp backend/.env.docker .env

# Editar con tus credenciales (ver sección "Setup Rápido")
# GOOGLE_CLIENT_ID=...
# GEMINI_API_KEY=...
# etc.
```

### 2. Construir y ejecutar

```bash
# Construir imágenes y ejecutar contenedores
docker-compose up --build

# O en background (detached)
docker-compose up -d --build
```

### 3. Ver logs

```bash
# Ver logs de todos los servicios
docker-compose logs -f

# Ver logs de un servicio específico
docker-compose logs -f backend
docker-compose logs -f mcp-server
```

### 4. Acceder a los servicios

- **Backend**: http://localhost:8000
- **MCP Server**: http://localhost:9000
- **Health Check**: http://localhost:8000/health

### 5. Detener

```bash
# Detener contenedores
docker-compose down

# Detener y eliminar volúmenes
docker-compose down -v
```

### Notas

- El backend sirve `extension/auth-callback.html` en la ruta `/auth-callback.html`
- La extensión Chrome debe apuntar a `http://localhost:8000` (no `localhost:3000`)
- Si necesitás recargar el código, hacé `docker-compose up --build` de nuevo

---

## Flujo de Autenticación

1. Usuario clickea "Conectar con Gmail" en el popup
2. La extensión genera PKCE verifier+challenge
3. Backend devuelve la URL de Google OAuth
4. Se abre popup de Google (con PKCE params)
5. Usuario acepta permisos
6. Google redirige a `auth-callback.html` (en la extensión)
7. El callback guarda el código de autorización en `chrome.storage.local`
8. El popup detecta el código y lo envía al backend
9. Backend intercambia código por tokens y guarda sesión en cookie
10. Extensión muestra emails

---

## Endpoints

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/auth/gmail/login` | Inicia OAuth, devuelve URL + session_id |
| POST | `/auth/gmail/callback` | Intercambia código por tokens |
| GET | `/auth/gmail/status` | Estado de autenticación |
| GET | `/api/emails` | Lista de emails (requiere auth) |
| GET | `/api/emails/{id}` | Detalle de un email (requiere auth) |
| POST | `/api/analyze` | Analiza un email con Gemini |
| GET | `/api/dashboard/stats` | Estadísticas del sistema |
| GET | `/api/dashboard/history` | Historial de análisis |
| GET | `/dashboard` | Dashboard web |

---

## Verbos de Prueba

### Con curl (después de obtener tokens)

```bash
# Login
curl -X GET "http://localhost:8000/auth/gmail/login" -c cookies.txt

# Ver estado
curl -X GET "http://localhost:8000/auth/gmail/status" -b cookies.txt

# Analizar un email (ejemplo)
curl -X POST "http://localhost:8000/api/analyze" \
  -H "Content-Type: application/json" \
  -H "X-Session-ID: your-session-id" \
  -d '{
    "email_id": "test123",
    "email_subject": "Verify your account",
    "email_sender": "support@paypa1-secure.com",
    "email_body": "Click here immediately to verify: https://paypa1-secure.com/verify"
  }'

# Dashboard
curl "http://localhost:8000/api/dashboard/stats"
```

---

## Estructura de Archivos

```
ia-seguridad/
├── backend/
│   ├── main.py              # FastAPI app
│   ├── config.py            # Configuración desde .env
│   ├── requirements.txt
│   ├── routes/
│   │   ├── auth.py          # OAuth endpoints
│   │   ├── emails.py        # Gmail API endpoints
│   │   ├── analyze.py       # Análisis con Gemini + MCP
│   │   └── dashboard.py     # Estadísticas
│   ├── services/
│   │   ├── oauth_service.py # PKCE + OAuth logic
│   │   ├── gmail_service.py # Gmail API client
│   │   └── gemini_service.py# Gemini AI integration
│   ├── models/
│   │   └── schemas.py       # Pydantic models
│   └── static/
│       └── dashboard.html   # Dashboard web
│
├── mcp-server/
│   ├── main.py              # MCP server (JSON-RPC over HTTP)
│   ├── config.py
│   ├── requirements.txt
│   └── tools/
│       └── safebrowsing.py  # Google Safe Browsing API
│
├── extension/
│   ├── manifest.json         # Chrome Extension MV3
│   ├── service-worker.js     # Background service worker
│   ├── auth-callback.html    # OAuth callback page
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   └── icons/
│       └── README.md        # Necesitás agregar iconos PNG
│
├── .env.example             # Template de variables
└── README.md
```

---

## Limitaciones del Prototipo

- **Facebook/Instagram**: No implementado (auth approval tarda semanas)
- **Almacenamiento en memoria**: Sesiones se pierden al reiniciar el servidor
- **URL blocking**: Solo funciona para links en emails analizados (no intercepta navegación general)
- **Iconos**: Falta agregar archivos PNG reales en `extension/icons/`

---

## Troubleshooting

### "401 Unauthorized" en emails
- Verificar que la cookie `session_id` esté presente
- Verificar que el token no haya expirado (1 hora por defecto)
- Ir a la extensión y hacer logout + login de nuevo

### "Failed to get emails list"
- Verificar que la Gmail API esté habilitada en GCP
- Verificar que el token tenga el scope `gmail.readonly`

### Gemini no responde
- Verificar `GEMINI_API_KEY` en `.env`
- Verificar que el plan tenga cuota disponible (Gemini 1.5 Flash: 1.5M tokens/min)

### Safe Browsing siempre dice "no maliciosa"
- Es normal si la URL no está en listas negras de Google
- Configurar `SAFE_BROWSING_API_KEY` para activación real