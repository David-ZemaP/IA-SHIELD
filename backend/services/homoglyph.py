"""
Homoglyph Detection Service
Detecta URLs que intentan suplantar dominios conocidos usando similitud visual.
"""
import re
from typing import List, Tuple


# Dominios conocidos a proteger
KNOWN_DOMAINS = [
    "paypal", "google", "microsoft", "amazon", "facebook",
    "apple", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "spotify", "github", "gitlab", "bitbucket",
    "chase", "wellsfargo", "citi", "banamex", "santander",
    "bbva", "mercadopago", "bancobci", "bancochile", "itau",
    "gmail", "outlook", "office", "yahoo", "icloud",
    "amazonaws", "digitalocean", "heroku", "vercel", "netlify",
    "adobe", "zoom", "teams", "slack", "discord",
    "ebay", "walmart", "target", "costco", "bestbuy",
    "coinbase", "binance", "paypal", "venmo", "cashapp",
    "fedex", "ups", "usps", "dhl",
]


def levenshtein_distance(s1: str, s2: str) -> int:
    """
    Calcula la distancia de Levenshtein entre dos strings.
    Distancia = número mínimo de ediciones (insertar, eliminar, reemplazar)
    para transformar s1 en s2.
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

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


def normalize_domain(domain: str) -> str:
    """Extrae el nombre base del dominio (sin TLD)."""
    domain = domain.lower().strip()
    # Remover protocolo
    domain = re.sub(r'^https?://', '', domain)
    # Remover www
    domain = re.sub(r'^www\d*\.', '', domain)
    # Remover TLD común
    domain = re.sub(r'\.(com|org|net|io|co|gov|edu|info|xyz|tk|ml|ga|cf|gq|buzz|top|icu|pw|cc)$', '', domain)
    # Remover todo después de /
    domain = domain.split('/')[0]
    # Remover números y separadores al final para comparar base
    domain = re.sub(r'[\d\-]+$', '', domain)
    return domain


def calculate_similarity(domain1: str, domain2: str) -> float:
    """
    Calcula similitud entre 0.0 y 1.0.
    1.0 = idénticos, 0.0 = completamente diferentes.
    """
    d1 = normalize_domain(domain1)
    d2 = normalize_domain(domain2)

    if d1 == d2:
        return 1.0

    max_len = max(len(d1), len(d2))
    if max_len == 0:
        return 1.0

    distance = levenshtein_distance(d1, d2)
    return 1.0 - (distance / max_len)


def detect_homoglyph(url: str, threshold: float = 0.7) -> List[dict]:
    """
    Detecta si una URL contiene homoglyphs que suplantan dominios conocidos.

    Args:
        url: URL a verificar
        threshold: Similitud mínima (0.0-1.0) para considerar coincidencia. Default 0.7

    Returns:
        Lista de diccionarios con {domain, matched_known, similarity, warning}
    """
    matches = []

    # Extraer dominio de la URL
    match = re.search(r'https?://([^/]+)', url)
    if not match:
        return matches

    domain = match.group(1).lower()

    for known in KNOWN_DOMAINS:
        similarity = calculate_similarity(domain, known)

        if similarity >= threshold:
            warning = generate_warning(domain, known, similarity)
            matches.append({
                "domain": domain,
                "matched_known": known,
                "similarity": round(similarity, 3),
                "warning": warning,
                "is_suspicious": similarity >= 0.85
            })

    # Ordenar por similitud descendente
    matches.sort(key=lambda x: x["similarity"], reverse=True)
    return matches


def generate_warning(domain: str, known: str, similarity: float) -> str:
    """Genera mensaje de advertencia según el nivel de similitud."""
    if similarity >= 0.95:
        return f"ALERTA: '{domain}' es casi idéntico a '{known}' — posible suplantación"
    elif similarity >= 0.85:
        return f"ADVERTENCIA: '{domain}' se parece mucho a '{known}' — verifique la URL"
    else:
        return f"NOTA: '{domain}' tiene similitud con '{known}' ({int(similarity*100)}%)"


def check_url_homoglyphs(urls: List[str]) -> dict:
    """
    Analiza múltiples URLs y retorna resumen de homoglyphs detectados.

    Returns:
        dict con: {total_urls, urls_with_homoglyphs, warnings: [], high_risk: []}
    """
    warnings = []
    high_risk = []

    for url in urls:
        matches = detect_homoglyph(url)
        for m in matches:
            entry = {**m, "url": url}
            warnings.append(entry)
            if m["is_suspicious"]:
                high_risk.append(entry)

    return {
        "total_urls": len(urls),
        "urls_with_homoglyphs": len(set(w["url"] for w in warnings)),
        "warnings": warnings,
        "high_risk": high_risk,
        "homoglyph_detected": len(high_risk) > 0
    }