import logging
import os

from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.scorer import ScoringResult

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Eres un analista experto en Threat Intelligence y ciberseguridad blue team. "
    "Recibes datos consolidados de múltiples fuentes de inteligencia sobre un indicador "
    "de compromiso (IOC) y debes generar un resumen ejecutivo en español de 3 a 5 frases. "
    "El resumen debe: indicar el nivel de amenaza, destacar los hallazgos más relevantes "
    "de cada fuente, y terminar con una recomendación accionable. "
    "Sé directo y técnico, sin introducciones ni despedidas."
)

_VERDICT_ES = {
    "clean":      "LIMPIO",
    "suspicious": "SOSPECHOSO",
    "malicious":  "MALICIOSO",
    "critical":   "CRÍTICO",
}

_IOC_TYPE_ES = {
    "ipv4":   "La IP",
    "ipv6":   "La dirección IPv6",
    "md5":    "El hash MD5",
    "sha1":   "El hash SHA1",
    "sha256": "El hash SHA256",
    "domain": "El dominio",
    "url":    "La URL",
}


# ---------------------------------------------------------------------------
# Análisis local — se usa cuando no hay ANTHROPIC_API_KEY configurada.
# Genera el mismo tipo de texto que produciría Claude a partir de los datos.
# ---------------------------------------------------------------------------

def _local_analysis(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
) -> str:
    verdict_label = _VERDICT_ES.get(scoring.verdict, scoring.verdict.upper())
    prefix = _IOC_TYPE_ES.get(ioc_type, "El indicador")
    sentences: list[str] = []

    sentences.append(
        f"{prefix} {ioc_value} ha sido clasificado como {verdict_label} "
        f"con un score de amenaza de {scoring.score}/100."
    )

    # VirusTotal
    vt = results.get("virustotal")
    if vt and vt.success:
        malicious = vt.data.get("malicious", 0)
        total = vt.data.get("total", 0)
        if malicious > 0:
            sentences.append(
                f"VirusTotal registra detecciones activas en {malicious} de {total} "
                f"motores antivirus."
            )
        elif total > 0:
            sentences.append(
                f"VirusTotal no registra detecciones en {total} motores antivirus consultados."
            )

    # AbuseIPDB
    ab = results.get("abuseipdb")
    if ab and ab.success:
        confidence = ab.data.get("confidence", 0)
        reports = ab.data.get("total_reports", 0)
        isp = ab.data.get("isp", "")
        if confidence > 0:
            sentences.append(
                f"AbuseIPDB acumula {reports} reportes con un índice de confianza "
                f"del {confidence}%"
                + (f", asociados principalmente al proveedor {isp}" if isp else "")
                + "."
            )

    # Shodan
    sh = results.get("shodan")
    if sh and sh.success:
        ports = sh.data.get("open_ports", [])
        sensitive = [p for p in ports if p in {22, 3389, 445, 1433, 4444}]
        if sensitive:
            sentences.append(
                f"Shodan detecta los puertos sensibles {', '.join(str(p) for p in sensitive)} "
                f"abiertos."
            )

    # OTX
    otx = results.get("otx")
    if otx and otx.success:
        pulses = otx.data.get("pulse_count", 0)
        if pulses > 0:
            sentences.append(
                f"AlienVault OTX lo incluye en {pulses} pulso{'s' if pulses > 1 else ''} "
                f"de amenaza activos."
            )

    # MalwareBazaar
    mb = results.get("malwarebazaar")
    if mb and mb.success and mb.data.get("found"):
        sentences.append("MalwareBazaar confirma que el hash está catalogado como malware conocido.")

    # GreyNoise
    gn = results.get("greynoise")
    if gn and gn.success:
        cls = gn.data.get("classification", "")
        if cls == "malicious":
            sentences.append("GreyNoise lo clasifica como origen de tráfico malicioso activo.")
        elif cls == "benign":
            sentences.append(
                "GreyNoise lo clasifica como tráfico benigno conocido, "
                "lo que reduce la probabilidad de amenaza real."
            )

    # Recomendación final
    if scoring.verdict == "critical":
        sentences.append(
            "Recomendación: bloquear inmediatamente en firewall perimetral y revisar "
            "los logs internos en busca de conexiones hacia este indicador en las últimas 72 horas."
        )
    elif scoring.verdict == "malicious":
        sentences.append(
            "Recomendación: bloquear en firewall e investigar los sistemas que hayan "
            "tenido contacto con este indicador."
        )
    elif scoring.verdict == "suspicious":
        sentences.append(
            "Recomendación: monitorizar activamente y elevar el nivel de alerta "
            "para conexiones relacionadas con este indicador."
        )
    else:
        sentences.append(
            "No se detectan indicadores de amenaza significativos. "
            "Se recomienda mantener la supervisión rutinaria."
        )

    return " ".join(sentences)


# ---------------------------------------------------------------------------
# Análisis vía API de Claude — se usa cuando ANTHROPIC_API_KEY está configurada
# ---------------------------------------------------------------------------

def _build_user_prompt(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
) -> str:
    lines = [
        f"IOC: {ioc_value} (tipo: {ioc_type})",
        f"Score de amenaza: {scoring.score}/100 — Veredicto: {scoring.verdict.upper()}",
        f"Contribución por fuente: {scoring.breakdown}",
        "",
        "Resultados por conector:",
    ]
    for name, r in results.items():
        status = "OK" if r.success else f"ERROR ({r.error})"
        lines.append(f"  [{name}] {status} — {r.summary}")
        if r.success and r.data:
            lines.append(f"    Datos: {r.data}")
    return "\n".join(lines)


async def _claude_api_analysis(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
    api_key: str,
) -> str:
    from anthropic import AsyncAnthropic  # import tardío para no fallar si no está instalado

    client = AsyncAnthropic(api_key=api_key)
    user_prompt = _build_user_prompt(ioc_value, ioc_type, scoring, results)

    message = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text.strip()


# ---------------------------------------------------------------------------
# Punto de entrada público
# ---------------------------------------------------------------------------

async def generate_summary(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
) -> str:
    """Genera el resumen ejecutivo del IOC en español.

    Si ANTHROPIC_API_KEY está configurada, llama a la API de Claude.
    Si no, genera el análisis localmente con la misma lógica.
    En cualquier caso, nunca lanza excepción: devuelve siempre un string.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()

    if api_key:
        try:
            return await _claude_api_analysis(ioc_value, ioc_type, scoring, results, api_key)
        except Exception as exc:
            logger.warning(
                "ai_analyst: fallo en Claude API, usando análisis local — %s", exc
            )

    return _local_analysis(ioc_value, ioc_type, scoring, results)
