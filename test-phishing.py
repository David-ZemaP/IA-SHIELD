#!/usr/bin/env python3
"""
Script de prueba para testing de detección de phishing
Genera emails de phishing controlados para verificar el sistema
"""
import requests
import json

API_BASE = "http://localhost:8000"

# Email de phishing clásico - debería detectarse como phishing
PHISHING_EMAIL = {
    "email_id": "test-phishing-001",
    "email_subject": "URGENTE: Tu cuenta de banco ha sido bloqueda",
    "email_sender": "soporte@banc0-seguro.xyz",
    "email_body": """
Estimado cliente,

Hemos detectado actividad sospechosa en su cuenta bancaria.
Su cuenta ha sido temporalment bloqueada por seguridad.

Para desbloquear su cuenta, haga clic en el enlace siguiente:
https://banc0-seguro.xyz/login/verify?user=12345

Tiene 24 horas para verificar su identidad o su cuenta será cerrada.

Si no actúa inmediatamente, perderá acceso a todos sus fondos.

Atentamente,
Equipo de Seguridad del Banco
""",
    "check_urls": True
}

# Email seguro - debería detectarse como safe
SAFE_EMAIL = {
    "email_id": "test-safe-001",
    "email_subject": "Re: Documentación del proyecto",
    "email_sender": "juan@empresa.com",
    "email_body": """
Hola,

Te envío la documentación del proyecto que me pediste.

Adjunto encontrarás el archivo PDF con todas las especificaciones.

Saludos,
Juan
""",
    "check_urls": True
}

# Email con URL sospechosa - debería detectarse como suspicious
SUSPICIOUS_EMAIL = {
    "email_id": "test-suspicious-001",
    "email_subject": "Ganaste un premio de $1000!",
    "email_sender": "premios@gana-ahora.xyz",
    "email_body": """
FELICIDADES!

Has sido seleccionado para ganar un premio de $1000!

Para reclamar tu premio, visita:
http://gana-ahora.xyz/winner/claim?id=123456

Solo tienes que confirmar tus datos personales y bancarios.

Gana-Ahora.com
""",
    "check_urls": True
}


def test_analysis(email_data, label):
    """Envía un email al endpoint de análisis"""
    print(f"\n{'='*50}")
    print(f"🧪 Test: {label}")
    print(f"{'='*50}")

    try:
        response = requests.post(
            f"{API_BASE}/analyze",
            json=email_data,
            headers={"Content-Type": "application/json"}
        )

        if response.status_code == 200:
            result = response.json()
            print(f"\n📧 Email: {email_data['email_subject']}")
            print(f"📬 From: {email_data['email_sender']}")
            print(f"\n🔍 RESULTADO:")
            print(f"   Veredicto: {result['verdict'].upper()}")
            print(f"   Confianza: {result['confidence']*100:.0f}%")
            print(f"   Razón: {result['reason']}")
            print(f"   Indicadores: {result['indicators']}")
            print(f"   URLs analizadas: {len(result['urls_analyzed'])}")

            for url in result['urls_analyzed']:
                print(f"      - {url['url'][:60]}... → malicious: {url['malicious']}")

            return result
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            return None

    except Exception as e:
        print(f"❌ Exception: {e}")
        return None


def main():
    print("🧪 IA-SEGURIDAD - TEST DE DETECCIÓN DE PHISHING")
    print("="*50)

    # Test 1: Phishing clásico
    result1 = test_analysis(PHISHING_EMAIL, "Phishing clásico (debería ser phishing)")

    # Test 2: Email seguro
    result2 = test_analysis(SAFE_EMAIL, "Email seguro (debería ser safe)")

    # Test 3: Email sospechoso
    result3 = test_analysis(SUSPICIOUS_EMAIL, "Email sospechoso (debería ser suspicious)")

    # Resumen
    print("\n" + "="*50)
    print("📊 RESUMEN DE TESTS")
    print("="*50)

    tests = [
        ("Phishing clásico", result1, "phishing"),
        ("Email seguro", result2, "safe"),
        ("Email sospechoso", result3, "suspicious"),
    ]

    for name, result, expected in tests:
        if result:
            status = "✅" if result['verdict'] == expected else "⚠️"
            print(f"{status} {name}: esperado={expected}, obtenido={result['verdict']}")
        else:
            print(f"❌ {name}: Error en la solicitud")

    print("\n🏁 Tests completados")


if __name__ == "__main__":
    main()