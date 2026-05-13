"""
Servicio de análisis de phishing usando Gemini 2.5 Flash.
Detecta en tiempo real intentos de phishing con IA.
"""
import httpx
import json
import os
import re
from typing import Optional

# Config
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# Phishing patterns (local fallback si Gemini falla)
SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.top', '.icu', '.pw', '.cc']
SUSPICIOUS_HOSTING = [
    '000webhostapp.com', 'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
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
            red_flags.append(f"Posible suplantación de marca: '{brand}'")
            is_suspicious = True

    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        red_flags.append("URL con dirección IP en vez de dominio")
        is_suspicious = True

    if re.search(r'\.(php|asp|jsp|cgi)\?', url):
        red_flags.append("URL dinámica con script sospechoso")
        is_suspicious = True

    return {"url": url, "domain": domain, "suspicious": is_suspicious, "red_flags": red_flags}


SYSTEM_PROMPT = """Eres un experto en ciberseguridad. Analiza este email y determina si es un intento de phishing.

RESPUESTA OBLIGATORIA: JSON puro sin markdown, sin código, sin explicaciones adicionales.
{
  "verdict": "safe|suspicious|phishing|review_needed",
  "confidence": 0.0 a 1.0,
  "reason": "breve explicación en español",
  "indicators": ["indicador 1", "indicador 2"]
}

INDICADORES DE PHISHING:
- Remitente con dominio que no corresponde a la empresa declarada
- Urgencia: "actúa ahora", "cuenta suspendida", "verificar inmediatamente"
- URLs con hosting gratuito (.tk, .xyz, .000webhostapp.com, bit.ly)
- Dominios que suplantan marcas conocidas (secure-paypal.xyz, login-amazon.net)
- Errores ortográficos o gramática sospechosa
- Solicitud de contraseñas, datos personales, financieros
- Ofertas demasiado buenas para ser verdad
- URLs con direcciones IP en vez de dominio

Si no hay indicadores claros → verdict: "safe"
Si hay dudas → verdict: "review_needed"
Si es claramente phishing → verdict: "phishing"
"""


def call_gemini(prompt: str) -> Optional[dict]:
    """Llama a Gemini y retorna el JSON parseado o None si falla."""
    if not GEMINI_API_KEY:
        return None

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 512  # Respuesta corta, JSON puro
        }
    }

    try:
        response = httpx.post(
            f"{GEMINI_API_URL}?key={GEMINI_API_KEY}",
            json=payload,
            timeout=20.0
        )

        if response.status_code != 200:
            return None

        data = response.json()
        if "candidates" not in data or not data["candidates"]:
            return None

        text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        # Strip markdown code blocks
        text = re.sub(r'^```json\s*', '', text)
        text = re.sub(r'^```\s*', '', text)
        text = re.sub(r'\s*```$', '', text)
        text = text.strip()

        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if not json_match:
            return None

        result = json.loads(json_match.group())
        return {
            "verdict": result.get("verdict", "review_needed"),
            "confidence": float(result.get("confidence", 0.5)),
            "reason": result.get("reason", ""),
            "indicators": result.get("indicators", [])
        }

    except Exception:
        return None


def analyze_email(email_content: str, sender: str = "", subject: str = "") -> dict:
    """
    Analiza email para phishing con IA en tiempo real.
    1. Intenta Gemini para análisis contextual profundo
    2. Si falla, usa análisis por reglas local
    3. Combina indicadores de URLs
    """
    urls = extract_urls(email_content)
    url_results = []
    url_red_flags = []

    for url in urls[:20]:
        r = check_url_safety(url)
        url_results.append(r)
        url_red_flags.extend(r["red_flags"])

    # Build prompt for Gemini
    prompt = f"""ANALIZA ESTE EMAIL:

DE: {sender if sender else 'Desconocido'}
ASUNTO: {subject if subject else 'Sin asunto'}
CONTENIDO: {email_content[:6000] if email_content else '(vacío)'}
URLs: {', '.join(urls[:10]) if urls else 'Ninguna'}

Responde solo JSON."""


    # Try Gemini first
    gemini_result = call_gemini(SYSTEM_PROMPT + "\n\n" + prompt)

    if gemini_result:
        verdict = gemini_result["verdict"]
        confidence = gemini_result["confidence"]
        reason = gemini_result["reason"]
        indicators = gemini_result["indicators"]
    else:
        # Fallback: rule-based analysis
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
            if urls:
                reason = f"No se detectaron indicadores obvios — {len(urls)} enlace(s) sin patrones sospechosos"
            else:
                reason = "No se detectaron indicadores de phishing"

        if not gemini_result:
            reason = reason or "Análisis local: sin indicadores obvios de phishing"
            indicators = url_red_flags[:10]

    # Override si hay URLs maliciosas detectadas localmente
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


def analyze_email(email_content: str, sender: str = "", subject: str = "") -> dict:
    """
    Analiza email para phishing de forma simple.
    1. Extrae URLs
    2. Verifica patrones sospechosos
    3. Usa Gemini SOLO si hay contenido ambiguo
    """
    if not email_content and not subject:
        return {
            "verdict": "review_needed",
            "confidence": 0.0,
            "reason": "Email sin contenido para analizar",
            "indicators": []
        }

    urls = extract_urls(email_content)
    all_red_flags = []
    url_results = []

    # Check each URL
    for url in urls[:20]:  # Max 20 URLs
        result = check_url_safety(url)
        url_results.append(result)
        if result["red_flags"]:
            all_red_flags.extend(result["red_flags"])

    # Check sender email
    sender_domain = ''
    if '@' in sender:
        sender_domain = sender.split('@')[1].lower()
        if sender_domain:
            if any(tld in sender_domain for tld in SUSPICIOUS_TLDS):
                all_red_flags.append(f"Remitente con dominio sospechoso: {sender_domain}")
            if not any(safe in sender_domain for safe in SAFE_DOMAINS):
                for kw in SUSPICIOUS_KEYWORDS[:5]:
                    if kw in email_content.lower() or kw in subject.lower():
                        all_red_flags.append(f"Palabra sospechosa en email: '{kw}'")
                        break

    # Check for suspicious keywords in subject
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in subject.lower():
            all_red_flags.append(f"Asunto sospechoso: '{kw}'")
            break

    # Count suspicious patterns
    red_flag_count = len(all_red_flags)

    # Determine verdict
    if red_flag_count >= 3:
        verdict = "phishing"
        confidence = min(0.95, 0.6 + red_flag_count * 0.1)
        reason = f"Se detectaron {red_flag_count} indicadores de phishing"
    elif red_flag_count >= 1:
        verdict = "suspicious"
        confidence = min(0.8, 0.4 + red_flag_count * 0.15)
        reason = f"Se detectaron {red_flag_count} indicadores sospechosos — revisar manualmente"
    else:
        verdict = "safe"
        confidence = 0.7
        reason = "No se detectaron indicadores obvios de phishing"
        if urls:
            reason += f" — {len(urls)} enlace(s) encontrado(s) sin patrones sospechosos"

    # Deduplicate flags
    unique_flags = list(dict.fromkeys(all_red_flags))

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "indicators": unique_flags[:10],  # Max 10 indicators
        "urls_analyzed": url_results,
        "urls_count": len(urls)
    }