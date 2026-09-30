"""Generación de reglas de detección a partir de un IOC.

Convierte inteligencia (un IOC ya analizado) en detección desplegable:
  - **Sigma**   (YAML, agnóstico de SIEM): IP / dominio / URL / hash.
  - **Suricata/Snort** (IDS de red): IP / dominio / URL.
  - **YARA**    (ficheros/EDR): hashes.

Es generación de texto determinista (sin LLM ni dependencias): las mismas
entradas dan siempre la misma regla, con IDs estables (uuid5 para Sigma, SID
derivado para Suricata), de modo que reimportar no duplica. Esto también lo
hace trivialmente testeable y evita que un fallo de red rompa la función.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ioc_correlator.utils.validators import IOCType, detect_ioc_type, refang

# Namespace propio para IDs Sigma deterministas (uuid5).
_NS = uuid.UUID("1b4e28ba-2fa1-11d2-883f-0016d3cca427")

# Rango de SIDs "locales" reservado para reglas propias (Suricata recomienda
# ≥ 1000000 para reglas de usuario).
_SID_BASE = 1_000_000
_SID_SPAN = 900_000


def _sigma_id(ioc_value: str) -> str:
    return str(uuid.uuid5(_NS, "sigma:" + ioc_value))


def _sid(ioc_value: str) -> int:
    return _SID_BASE + (uuid.uuid5(_NS, "sid:" + ioc_value).int % _SID_SPAN)


def _level(score: int | None) -> str:
    if score is None:
        return "high"
    if score >= 81:
        return "critical"
    if score >= 51:
        return "high"
    if score >= 21:
        return "medium"
    return "low"


def _yara_name(ioc_value: str) -> str:
    short = uuid.uuid5(_NS, ioc_value).hex[:8]
    return f"BlueEcho_{short}"


# ---------------------------------------------------------------------------
# Sigma
# ---------------------------------------------------------------------------

def _sigma(ioc_value: str, ioc_type: IOCType, score: int | None) -> str:
    sid = _sigma_id(ioc_value)
    level = _level(score)
    date = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    common = (
        f"title: Blue-Echo — IOC malicioso {ioc_value}\n"
        f"id: {sid}\n"
        f"status: experimental\n"
        f"description: Detecta actividad relacionada con el IOC {ioc_value}, "
        f"clasificado como malicioso por Blue-Echo IOC-Correlator.\n"
        f"references:\n"
        f"    - Blue-Echo IOC-Correlator\n"
        f"author: Blue-Echo\n"
        f"date: {date}\n"
        f"tags:\n"
        f"    - attack.command_and_control\n"
    )

    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        body = (
            "logsource:\n"
            "    category: firewall\n"
            "detection:\n"
            "    selection:\n"
            "        dst_ip:\n"
            f"            - '{ioc_value}'\n"
            "    condition: selection\n"
        )
    elif ioc_type == IOCType.DOMAIN:
        body = (
            "logsource:\n"
            "    category: dns_query\n"
            "detection:\n"
            "    selection:\n"
            "        query:\n"
            f"            - '{ioc_value}'\n"
            "    condition: selection\n"
        )
    elif ioc_type == IOCType.URL:
        body = (
            "logsource:\n"
            "    category: proxy\n"
            "detection:\n"
            "    selection:\n"
            "        c-uri|contains:\n"
            f"            - '{ioc_value}'\n"
            "    condition: selection\n"
        )
    else:  # hashes
        field = {IOCType.MD5: "MD5", IOCType.SHA1: "SHA1", IOCType.SHA256: "SHA256"}[ioc_type]
        body = (
            "logsource:\n"
            "    category: process_creation\n"
            "    product: windows\n"
            "detection:\n"
            "    selection:\n"
            "        Hashes|contains:\n"
            f"            - '{field}={ioc_value}'\n"
            "    condition: selection\n"
        )

    return common + body + f"level: {level}\n"


# ---------------------------------------------------------------------------
# Suricata / Snort
# ---------------------------------------------------------------------------

def _suricata(ioc_value: str, ioc_type: IOCType, score: int | None) -> str | None:
    sid = _sid(ioc_value)
    msg = f"Blue-Echo malicious {ioc_type.value} {ioc_value}"

    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        return (
            f'alert ip any any -> {ioc_value} any '
            f'(msg:"{msg}"; sid:{sid}; rev:1;)\n'
        )
    if ioc_type == IOCType.DOMAIN:
        return (
            f'alert dns any any -> any any '
            f'(msg:"{msg}"; dns.query; content:"{ioc_value}"; nocase; sid:{sid}; rev:1;)\n'
        )
    if ioc_type == IOCType.URL:
        from urllib.parse import urlparse
        host = urlparse(ioc_value).hostname or ioc_value
        path = urlparse(ioc_value).path or "/"
        return (
            f'alert http any any -> any any '
            f'(msg:"{msg}"; http.host; content:"{host}"; '
            f'http.uri; content:"{path}"; sid:{sid}; rev:1;)\n'
        )
    return None  # los hashes no se detectan en red


# ---------------------------------------------------------------------------
# YARA (hashes)
# ---------------------------------------------------------------------------

def _yara(ioc_value: str, ioc_type: IOCType) -> str | None:
    if ioc_type not in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return None
    func = {IOCType.MD5: "md5", IOCType.SHA1: "sha1", IOCType.SHA256: "sha256"}[ioc_type]
    name = _yara_name(ioc_value)
    return (
        'import "hash"\n\n'
        f"rule {name}\n"
        "{\n"
        "    meta:\n"
        '        description = "Blue-Echo — fichero con hash malicioso conocido"\n'
        '        author = "Blue-Echo"\n'
        f'        ioc = "{ioc_value}"\n'
        "    condition:\n"
        f'        hash.{func}(0, filesize) == "{ioc_value.lower()}"\n'
        "}\n"
    )


def generate_detection_rules(
    ioc_value: str,
    ioc_type: IOCType | str | None = None,
    *,
    verdict: str | None = None,
    score: int | None = None,
) -> dict[str, str]:
    """Devuelve {formato: regla} con las reglas de detección aplicables al IOC.

    - IP / dominio / URL → `sigma` + `suricata`.
    - Hash               → `sigma` + `yara`.
    """
    ioc_value = refang((ioc_value or "").strip())
    if isinstance(ioc_type, str):
        try:
            ioc_type = IOCType(ioc_type)
        except ValueError:
            ioc_type = None
    if ioc_type is None:
        ioc_type = detect_ioc_type(ioc_value)

    if ioc_type == IOCType.UNKNOWN or not ioc_value:
        return {}

    rules: dict[str, str] = {"sigma": _sigma(ioc_value, ioc_type, score)}
    suricata = _suricata(ioc_value, ioc_type, score)
    if suricata:
        rules["suricata"] = suricata
    yara = _yara(ioc_value, ioc_type)
    if yara:
        rules["yara"] = yara
    return rules
