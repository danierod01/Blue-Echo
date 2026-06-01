import logging
import os

from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.scorer import ScoringResult

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "Eres un analista experto en Threat Intelligence y ciberseguridad blue team. "
    "Recibes datos consolidados de múltiples fuentes de inteligencia sobre un indicador "
    "de compromiso (IOC) y debes generar un informe estructurado en español con las "
    "siguientes secciones exactas, usando este formato Markdown:\n\n"
    "## Resumen\n"
    "Una o dos frases indicando el tipo de IOC, el nivel de amenaza y el score.\n\n"
    "## Hallazgos por fuente\n"
    "Para cada fuente que haya devuelto datos relevantes, una línea con el formato:\n"
    "- **NombreFuente**: hallazgo clave con datos concretos (números, porcentajes, nombres).\n"
    "Omite las fuentes que no aportaron datos o fallaron.\n\n"
    "## Contexto de amenaza\n"
    "Dos o tres frases explicando qué tipo de actor o actividad maliciosa sugieren los datos: "
    "¿es infraestructura de C2, nodo Tor, scanner masivo, malware conocido, phishing...? "
    "Relaciona los hallazgos entre fuentes para construir el contexto.\n\n"
    "## Recomendaciones\n"
    "Lista de 2 a 4 acciones concretas y priorizadas que debe tomar el equipo de seguridad, "
    "adaptadas al nivel de amenaza y al tipo de IOC.\n\n"
    "Sé directo y técnico. No añadas introducciones, despedidas ni texto fuera de las secciones."
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
    sections: list[str] = []

    # --- Resumen ---
    sections.append(
        f"## Resumen\n"
        f"{prefix} `{ioc_value}` ha sido clasificado como **{verdict_label}** "
        f"con un score de amenaza de {scoring.score}/100."
    )

    # --- Hallazgos por fuente ---
    findings: list[str] = []

    vt = results.get("virustotal")
    if vt and vt.success:
        malicious = vt.data.get("malicious", 0)
        total = vt.data.get("total", 0)
        if malicious > 0:
            findings.append(f"- **VirusTotal**: {malicious} de {total} motores lo detectan como malicioso.")
        elif total > 0:
            findings.append(f"- **VirusTotal**: sin detecciones en {total} motores consultados.")

    ab = results.get("abuseipdb")
    if ab and ab.success:
        confidence = ab.data.get("confidence", 0)
        reports = ab.data.get("total_reports", 0)
        isp = ab.data.get("isp", "")
        if confidence > 0:
            line = f"- **AbuseIPDB**: {reports} reportes, confianza del {confidence}%"
            if isp:
                line += f", proveedor: {isp}"
            findings.append(line + ".")

    sh = results.get("shodan")
    if sh and sh.success:
        ports = sh.data.get("open_ports", [])
        sensitive = [p for p in ports if p in {22, 3389, 445, 1433, 4444}]
        if ports:
            line = f"- **Shodan**: {len(ports)} puertos abiertos"
            if sensitive:
                line += f", sensibles: {', '.join(str(p) for p in sensitive)}"
            findings.append(line + ".")

    otx = results.get("otx")
    if otx and otx.success:
        pulses = otx.data.get("pulse_count", 0)
        if pulses > 0:
            findings.append(f"- **AlienVault OTX**: presente en {pulses} pulso{'s' if pulses > 1 else ''} de amenaza activos.")

    mb = results.get("malwarebazaar")
    if mb and mb.success and mb.data.get("found"):
        findings.append("- **MalwareBazaar**: hash catalogado como malware conocido.")

    tf = results.get("threatfox")
    if tf and tf.success and tf.data.get("found"):
        malware = tf.data.get("malware", "")
        findings.append(f"- **ThreatFox**: asociado a {malware}." if malware else "- **ThreatFox**: IOC conocido en la base de datos.")

    ip = results.get("ipinfo")
    if ip and ip.success:
        flags = [f for f, v in [("Tor", ip.data.get("is_tor")), ("VPN", ip.data.get("is_vpn")), ("Proxy", ip.data.get("is_proxy"))] if v]
        if flags:
            findings.append(f"- **IPinfo**: identificado como {', '.join(flags)}.")

    ha = results.get("hybrid_analysis")
    if ha and ha.success and ha.data.get("found"):
        family = ha.data.get("vx_family", "")
        findings.append(f"- **Hybrid Analysis**: muestra encontrada{f', familia: {family}' if family else ''}.")

    pd = results.get("pulsedive")
    if pd and pd.success and pd.data.get("found"):
        risk = pd.data.get("risk", "")
        findings.append(f"- **Pulsedive**: riesgo evaluado como {risk}." if risk else "- **Pulsedive**: IOC encontrado en la base de datos.")

    if findings:
        sections.append("## Hallazgos por fuente\n" + "\n".join(findings))

    # --- Contexto de amenaza ---
    context_parts: list[str] = []
    if scoring.verdict in ("critical", "malicious"):
        if results.get("abuseipdb") and results["abuseipdb"].success and results["abuseipdb"].data.get("confidence", 0) > 80:
            context_parts.append("El alto índice de confianza de AbuseIPDB junto con el volumen de reportes sugiere actividad maliciosa sostenida y conocida por la comunidad.")
        if results.get("otx") and results["otx"].success and results["otx"].data.get("pulse_count", 0) > 0:
            context_parts.append("Su presencia en múltiples pulsos de OTX indica que este IOC forma parte de campañas de amenaza documentadas.")
        if not context_parts:
            context_parts.append("La convergencia de señales negativas en múltiples fuentes independientes confirma la naturaleza maliciosa de este indicador.")
    elif scoring.verdict == "suspicious":
        context_parts.append("Los datos disponibles muestran señales de alerta pero sin confirmación definitiva de actividad maliciosa. Podría tratarse de infraestructura comprometida o en proceso de uso por actores maliciosos.")
    else:
        context_parts.append("No se han encontrado indicadores de compromiso significativos en las fuentes consultadas. El indicador parece legítimo.")

    sections.append("## Contexto de amenaza\n" + " ".join(context_parts))

    # --- Recomendaciones ---
    recs: list[str] = []
    if scoring.verdict == "critical":
        recs = [
            "1. Bloquear inmediatamente en firewall perimetral (regla de denegación explícita).",
            "2. Revisar logs internos de las últimas 72 horas en busca de conexiones hacia este indicador.",
            "3. Si se detectan conexiones previas, iniciar proceso de respuesta a incidentes.",
            "4. Añadir el IOC a la lista de bloqueo del SIEM y activar alertas.",
        ]
    elif scoring.verdict == "malicious":
        recs = [
            "1. Bloquear en firewall e IDS/IPS.",
            "2. Investigar qué sistemas internos han tenido contacto con este indicador.",
            "3. Añadir a feeds de bloqueo del SIEM.",
        ]
    elif scoring.verdict == "suspicious":
        recs = [
            "1. Monitorizar activamente el tráfico relacionado con este indicador.",
            "2. Elevar el nivel de alerta para conexiones futuras.",
            "3. Programar revisión en 24-48 horas para reevaluar con nuevos datos.",
        ]
    else:
        recs = [
            "1. Mantener supervisión rutinaria.",
            "2. Revisar si el contexto de uso justifica monitorización adicional.",
        ]

    sections.append("## Recomendaciones\n" + "\n".join(recs))

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Construcción del prompt de usuario (compartida por todos los proveedores)
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


# ---------------------------------------------------------------------------
# Proveedor 1 — Groq (LLaMA 3.3 70B, tier gratuito)
# ---------------------------------------------------------------------------

async def _groq_analysis(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
    api_key: str,
) -> str:
    from groq import AsyncGroq  # import tardío para no fallar si no está instalado

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    client = AsyncGroq(api_key=api_key)
    user_prompt = _build_user_prompt(ioc_value, ioc_type, scoring, results)

    response = await client.chat.completions.create(
        model=model,
        max_tokens=1024,
        messages=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
    )
    return response.choices[0].message.content.strip()


# ---------------------------------------------------------------------------
# Proveedor 2 — Anthropic Claude (fallback si ANTHROPIC_API_KEY está definida)
# ---------------------------------------------------------------------------

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
        max_tokens=1024,
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text.strip()


# ---------------------------------------------------------------------------
# Punto de entrada público
# Orden de prioridad: Groq → Anthropic → análisis local
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Análisis de tráfico PCAP
# ---------------------------------------------------------------------------

_PCAP_SYSTEM_PROMPT = (
    "Eres un analista forense de red experto en ciberseguridad blue team. "
    "Recibes estadísticas de tráfico extraídas de un fichero PCAP y debes generar "
    "un informe estructurado en español con estas secciones exactas en Markdown:\n\n"
    "## Resumen del tráfico\n"
    "Dos o tres frases sobre volumen, protocolos dominantes y perfil general del capture.\n\n"
    "## Indicadores sospechosos\n"
    "Lista de IPs, dominios o patrones que llaman la atención, con el motivo concreto "
    "(alto volumen de conexiones, puerto inusual, dominio DGA, patrón de beacon, "
    "tráfico no cifrado sensible, etc.).\n\n"
    "## Vector de ataque probable\n"
    "Dos o tres frases sobre qué tipo de actividad maliciosa sugieren los datos: "
    "C2 callback, exfiltración, lateral movement, escaneo, malware dropper, phishing...\n\n"
    "## Recomendaciones de respuesta\n"
    "Lista de 3 a 5 acciones inmediatas ordenadas por prioridad.\n\n"
    "Sé directo y técnico. Basa todo en los datos concretos. "
    "Si el tráfico parece limpio, dilo en el Resumen. "
    "No añadas texto fuera de las secciones."
)


def _build_pcap_user_prompt(filename: str, stats: dict) -> str:
    lines = [
        f"Fichero PCAP: {filename}",
        f"Paquetes capturados: {stats['total_packets']:,}",
        f"Bytes totales: {stats['total_bytes']:,}",
        f"Distribución de protocolos: {stats.get('protocols', {})}",
    ]
    if stats.get("unique_src_ips"):
        lines.append(f"\nIPs origen (top {len(stats['unique_src_ips'])}): {', '.join(stats['unique_src_ips'][:15])}")
    if stats.get("unique_dst_ips"):
        lines.append(f"IPs destino (top {len(stats['unique_dst_ips'])}): {', '.join(stats['unique_dst_ips'][:15])}")
    if stats.get("top_connections"):
        lines.append(f"\nConexiones más activas (top {min(10, len(stats['top_connections']))}):")
        for c in stats["top_connections"][:10]:
            lines.append(f"  {c['src']} → {c['dst']}: {c['packets']} paquetes")
    if stats.get("dns_queries"):
        lines.append(f"\nConsultas DNS ({len(stats['dns_queries'])} únicas):")
        for q in stats["dns_queries"][:25]:
            lines.append(f"  - {q}")
    if stats.get("http_hosts"):
        lines.append(f"\nHosts HTTP ({len(stats['http_hosts'])} únicos):")
        for h in stats["http_hosts"][:15]:
            lines.append(f"  - {h}")
    if stats.get("tls_sni"):
        lines.append(f"\nSNI TLS ({len(stats['tls_sni'])} únicos):")
        for s in stats["tls_sni"][:15]:
            lines.append(f"  - {s}")
    return "\n".join(lines)


async def _groq_pcap_analysis(filename: str, stats: dict, api_key: str) -> str:
    from groq import AsyncGroq

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    client = AsyncGroq(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        max_tokens=1500,
        messages=[
            {"role": "system", "content": _PCAP_SYSTEM_PROMPT},
            {"role": "user",   "content": _build_pcap_user_prompt(filename, stats)},
        ],
    )
    return response.choices[0].message.content.strip()


async def _claude_pcap_analysis(filename: str, stats: dict, api_key: str) -> str:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=api_key)
    message = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=1500,
        system=_PCAP_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_pcap_user_prompt(filename, stats)}],
    )
    return message.content[0].text.strip()


def _local_pcap_analysis(filename: str, stats: dict) -> str:
    total_pkts  = stats.get("total_packets", 0)
    total_bytes = stats.get("total_bytes", 0)
    protos      = stats.get("protocols", {})
    proto_str   = ", ".join(f"{k}: {v}" for k, v in sorted(protos.items(), key=lambda x: -x[1]))
    sections: list[str] = []

    sections.append(
        f"## Resumen del tráfico\n"
        f"El capture `{filename}` contiene **{total_pkts:,} paquetes** "
        f"({total_bytes / 1024:.1f} KB). "
        f"Distribución de protocolos: {proto_str or 'no determinada'}."
    )

    indicators: list[str] = []
    top_conns = stats.get("top_connections", [])
    if top_conns:
        top = top_conns[0]
        indicators.append(f"- **{top['dst']}**: destino con mayor tráfico ({top['packets']} paquetes desde {top['src']}).")
    if stats.get("dns_queries"):
        indicators.append(f"- **DNS**: {len(stats['dns_queries'])} dominios únicos consultados.")
    if stats.get("tls_sni"):
        indicators.append(f"- **TLS**: conexiones cifradas a {len(stats['tls_sni'])} hosts distintos.")
    if stats.get("http_hosts"):
        indicators.append(f"- **HTTP**: tráfico no cifrado hacia {len(stats['http_hosts'])} hosts.")
    sections.append(
        "## Indicadores sospechosos\n"
        + ("\n".join(indicators) if indicators else "Sin análisis de IA no es posible determinar indicadores con certeza.")
    )

    sections.append(
        "## Vector de ataque probable\n"
        "Sin análisis de IA disponible, no es posible determinar el vector. "
        "Revisar manualmente los indicadores listados, especialmente conexiones de mayor "
        "volumen y consultas DNS a dominios desconocidos."
    )

    sections.append(
        "## Recomendaciones de respuesta\n"
        "1. Investigar las IPs destino más activas en fuentes de Threat Intelligence.\n"
        "2. Analizar las consultas DNS en busca de dominios DGA o recién registrados.\n"
        "3. Revisar conexiones HTTP no cifradas en busca de exfiltración.\n"
        "4. Configurar alertas en el SIEM para las IPs identificadas."
    )

    return "\n\n".join(sections)


async def generate_pcap_summary(filename: str, stats: dict) -> str:
    """Genera el análisis forense de tráfico de red para un PCAP.

    Prueba los proveedores de IA en orden y siempre devuelve un string.
    """
    groq_key      = os.getenv("GROQ_API_KEY",      "").strip()
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()

    if groq_key:
        try:
            return await _groq_pcap_analysis(filename, stats, groq_key)
        except Exception as exc:
            logger.warning("ai_analyst: fallo en Groq para PCAP — %s", exc)

    if anthropic_key:
        try:
            return await _claude_pcap_analysis(filename, stats, anthropic_key)
        except Exception as exc:
            logger.warning("ai_analyst: fallo en Anthropic para PCAP — %s", exc)

    return _local_pcap_analysis(filename, stats)


# ---------------------------------------------------------------------------
# Punto de entrada público — IOC individual
# ---------------------------------------------------------------------------

async def generate_summary(
    ioc_value: str,
    ioc_type: str,
    scoring: ScoringResult,
    results: dict[str, ConnectorResult],
) -> str:
    """Genera el resumen ejecutivo del IOC en español.

    Prueba los proveedores en orden hasta obtener respuesta.
    Nunca lanza excepción: devuelve siempre un string.
    """
    groq_key      = os.getenv("GROQ_API_KEY",      "").strip()
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()

    if groq_key:
        try:
            return await _groq_analysis(ioc_value, ioc_type, scoring, results, groq_key)
        except Exception as exc:
            logger.warning("ai_analyst: fallo en Groq API — %s", exc)

    if anthropic_key:
        try:
            return await _claude_api_analysis(ioc_value, ioc_type, scoring, results, anthropic_key)
        except Exception as exc:
            logger.warning("ai_analyst: fallo en Anthropic API — %s", exc)

    return _local_analysis(ioc_value, ioc_type, scoring, results)
