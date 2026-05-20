from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
import logging
import pathlib

from routes import auth, analyze
from routes.emails import router as emails_router
from routes.dashboard import router as dashboard_router
from routes.mcp import router as mcp_router

# Configure logging
logging.basicConfig(level=logging.WARNING, format='%(message)s')
logging.getLogger('httpx').setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — ensure directories exist
    os.makedirs("static", exist_ok=True)
    yield


app = FastAPI(
    title="IA Seguridad Backend",
    description="Backend para detección de phishing en Gmail",
    version="1.0.0",
    lifespan=lifespan
)

# CORS para Chrome Extension
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers — paths sin /api redundante
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(emails_router, prefix="/emails", tags=["emails"])
app.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(mcp_router, prefix="/mcp", tags=["mcp"])

# Mount static files for dashboard
app.mount("/dashboard", StaticFiles(directory="static", html=True), name="dashboard")

# Serve auth-callback.html directly (no StaticFiles para evitar trailing slash redirect)
_ext_path = os.path.join(os.path.dirname(__file__), "..", "extension")
_callback_path = os.path.join(_ext_path, "auth-callback.html")

@app.get("/auth-callback.html")
async def serve_auth_callback():
    # Try multiple possible paths
    possible_paths = [
        "/app/extension/auth-callback.html",
    ]
    for path in possible_paths:
        if os.path.exists(path):
            return FileResponse(path)
    return {"error": "Callback page not found", "checked": possible_paths}


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.get("/")
async def root():
    return {"message": "IA Seguridad Backend", "version": "1.0.0"}