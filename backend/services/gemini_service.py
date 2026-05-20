"""
Servicio de análisis de phishing usando Gemini 1.5 Flash.
Detecta en tiempo real intentos de phishing con IA.
"""
import httpx
import json
import os
import re
from typing import Optional

from .homoglyph import detect_homoglyph, check_url_homoglyphs

# Config
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Phishing patterns (local fallback si Gemini falla)
SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.top', '.icu', '.pw', '.cc']
SUSPICIOUS_HOSTING = [
    '000webhostapp.com', 'bit.ly', 'tinyurl.com', 'goo.gl',
    'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', '000webhost.com'
]
IMPERSONATED_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon',
    'netflix', 'facebook', 'instagram', 'dropbox',
    'bank', 'chase', 'wellsfargo', 'citi', 'banamex',
    'spotify', 'linkedin', 'twitter', 'uber', 'airbnb',
    'mercadopago', 'bancobci', 'santander', 'bbva'
]
SAFE_DOMAINS = [
    'google.com', 'mail.google.com',
    'microsoft.com', 'outlook.com', 'office.com',
    'amazon.com', 'paypal.com', 'apple.com', 'facebook.com',
    'instagram.com', 'twitter.com', 'linkedin.com',
    'netflix.com', 'spotify.com', 'dropbox.com',
    'github.com', 'gitlab.com', 'bitbucket.org',
    'pinterest.com', 't.co'  # t.co es de Twitter/X, no malicioso
]

# Keywords sospechosos
SUSPICIOUS_KEYWORDS = [
    'urgente', 'inmediatamente', 'actuar ya', 'cuenta suspendida',
    'verificar', 'confirmar datos', 'password', 'contraseña',
    'actualizar datos', 'datos personales', 'banco', 'tarjeta',
    'premio', 'ganador', 'loteria', 'regalo', 'gratis',
    'iniciar sesión', 'login', 'sign in', 'cliente',
    'soporte', 'help desk', 'seguridad', 'alerta'
]


def extract_urls(text: str) -> list:
    pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(pattern, text)


def extract_domain(url: str) -> str:
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1).lower() if match else ''


def check_url_safety(url: str) -> dict:
    domain = extract_domain(url).lower()
    red_flags = []
    is_suspicious = False

    # Si el dominio es conocido y seguro, no analizar más
    if any(safe in domain for safe in SAFE_DOMAINS):
        return {"url": url, "domain": domain, "suspicious": False, "red_flags": []}

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            red_flags.append(f"TLD sospechoso: {tld}")
            is_suspicious = True

    for hosting in SUSPICIOUS_HOSTING:
        if hosting in domain:
            red_flags.append(f"Hosting gratuito sospechoso: {hosting}")
            is_suspicious = True

    for brand in IMPERSONATED_BRANDS:
        if brand in domain and not any(safe in domain for safe in SAFE_DOMAINS):
            red_flags.append(f"Posible suplantación de marca: {brand}")
            is_suspicious = True

    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        red_flags.append("URL con dirección IP en vez de dominio")
        is_suspicious = True

    if re.search(r'\.(php|asp|jsp|cgi)\?', url):
        red_flags.append("URL dinámica con script sospechoso")
        is_suspicious = True

    return {"url": url, "domain": domain, "suspicious": is_suspicious, "red_flags": red_flags}


SYSTEM_PROMPT = """Eres un detector de phishing. Analiza este email.

RESPONDE SOLO CON ESTE JSON EXACTO (sin texto antes ni después):
{"verdict":"safe","confidence":0.0,"reason":"texto","indicators":[]}

verdict: safe|suspicious|phishing
confidence: 0.0 a 1.0
reason: una frase breve
indicators: hasta 3 palabras clave
"""


def call_gemini(prompt: str) -> Optional[dict]:
    """Llama a Gemini y retorna el JSON parseado o None si falla."""
    if not GEMINI_API_KEY:
        print("[Gemini] No API Key configurada")
        return None

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 512
        }
    }

    try:
        response = httpx.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            json=payload,
            timeout=20.0
        )

        if response.status_code != 200:
            print(f"[Gemini] Error HTTP {response.status_code}")
            return None

        data = response.json()
        if "candidates" not in data or not data["candidates"]:
            print("[Gemini] No candidates en respuesta")
            return None

        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        text = re.sub(r'^```json\s*', '', text)
        text = re.sub(r'^```\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        text = text.strip()

        # Try to find JSON - handle partial responses
        json_match = re.search(r'\{[\s\S]*\}', text)
        if not json_match:
            print(f"[Gemini] No se encontró JSON. Respuesta: {text[:200]}")
            return None

        try:
            result = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            print(f"[Gemini] JSON decode error: {e}. Respuesta: {text[:200]}")
            return None
        return {
            "verdict": result.get("verdict", "review_needed"),
            "confidence": float(result.get("confidence", 0.5)),
            "reason": result.get("reason", ""),
            "indicators": result.get("indicators", [])
        }

    except Exception as e:
        print(f"[Gemini] Exception: {e}")
        return None


def analyze_email(email_content: str, sender: str = "", subject: str = "") -> dict:
    """
    Analiza email para phishing con IA.
    1. Intenta Gemini para análisis contextual
    2. Si falla, usa análisis por reglas local
    """
    urls = extract_urls(email_content or "")
    url_results = []
    url_red_flags = []

    for url in urls[:20]:
        r = check_url_safety(url)
        url_results.append(r)
        url_red_flags.extend(r["red_flags"])

    # Detectar homoglyphs en todas las URLs
    homoglyph_results = check_url_homoglyphs(urls[:20])
    homoglyph_warnings = homoglyph_results.get("high_risk", [])

    for hg in homoglyph_warnings:
        red_flags.append(f"Homoglyph: {hg['warning']}")

    # Build prompt for Gemini
    prompt = f"""ANALIZA ESTE EMAIL:

DE: {sender if sender else 'Desconocido'}
ASUNTO: {subject if subject else 'Sin asunto'}
CONTENIDO: {email_content[:6000] if email_content else '(vacio)'}
URLs: {', '.join(urls[:10]) if urls else 'Ninguna'}

Responde solo JSON."""

    # Try Gemini
    gemini_result = call_gemini(SYSTEM_PROMPT + "\n\n" + prompt)

    if gemini_result:
        verdict = gemini_result["verdict"]
        confidence = gemini_result["confidence"]
        reason = gemini_result["reason"]
        indicators = gemini_result["indicators"]
    else:
        # Fallback: rule-based
        red_flag_count = len(url_red_flags)

        if red_flag_count >= 3:
            verdict = "phishing"
            confidence = min(0.95, 0.5 + red_flag_count * 0.15)
        elif red_flag_count >= 1:
            verdict = "suspicious"
            confidence = min(0.8, 0.3 + red_flag_count * 0.2)
        else:
            verdict = "safe"
            confidence = 0.6
            reason = "No se detectaron indicadores obvios de phishing"
            if urls:
                reason += f" - {len(urls)} enlace(s) sin patrones sospechosos"

        if not gemini_result:
            reason = reason or "Analisis local: sin indicadores obvios de phishing"
            indicators = url_red_flags[:10]

    # Override si hay URLs maliciosas
    if url_red_flags and verdict == "safe":
        verdict = "suspicious"
        confidence = min(0.7, confidence)
        reason = reason or "Se detectaron patrones sospechosos en URLs"
        indicators = list(dict.fromkeys(indicators + url_red_flags[:5]))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "indicators": list(dict.fromkeys(indicators[:10])),
        "urls_analyzed": url_results,
        "urls_count": len(urls)
    }