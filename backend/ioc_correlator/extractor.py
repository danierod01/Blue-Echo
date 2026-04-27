import re
from dataclasses import dataclass

from ioc_correlator.utils.validators import IOCType, detect_ioc_type

# ---------------------------------------------------------------------------
# Patrones de extracción (anchos, la validación la hace detect_ioc_type)
# ---------------------------------------------------------------------------

# URLs completas — se extraen primero para evitar que el resto de patrones
# fragmenten su contenido (p.ej. sacar el dominio suelto de una URL).
_RE_URL = re.compile(r"https?://[^\s\"'<>\],;]+", re.IGNORECASE)

# IPv4 — cuatro octetos separados por puntos
_RE_IPV4 = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

# IPv6 — al menos dos grupos hex separados por ":"
_RE_IPV6 = re.compile(
    r"\b(?:[a-fA-F0-9]{1,4}:){1,7}[a-fA-F0-9]{0,4}"
    r"(?::[a-fA-F0-9]{1,4}){0,7}\b"
)

# Hashes de mayor a menor longitud para evitar que SHA1 capture el inicio de SHA256
_RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_RE_SHA1   = re.compile(r"\b[a-fA-F0-9]{40}\b")
_RE_MD5    = re.compile(r"\b[a-fA-F0-9]{32}\b")

# FQDN — dos o más etiquetas, TLD de 2+ letras
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Caracteres de puntuación que pueden aparecer pegados al final de un candidato
# en texto libre (comillas, paréntesis, etc.)
_TRAILING_JUNK = re.compile(r"[\"')\]>;,:.]+$")


@dataclass(frozen=True)
class ExtractedIOC:
    value: str
    ioc_type: IOCType


def _clean(candidate: str) -> str:
    return _TRAILING_JUNK.sub("", candidate).strip()


def extract_iocs(text: str) -> list[ExtractedIOC]:
    """Extrae IOCs únicos de un texto libre o fichero de log.

    Soporta: texto genérico, Apache/Nginx access log, syslog,
    Windows Event Log CSV y JSON lines.

    Estrategia de extracción por fases para evitar fragmentar URLs:
      1. Extraer URLs completas y borrarlas del texto.
      2. Extraer IPs (v4 y v6) del texto restante.
      3. Extraer hashes (SHA256 → SHA1 → MD5).
      4. Extraer dominios del texto ya limpio de IPs y hashes.
    """
    seen: set[str] = set()
    results: list[ExtractedIOC] = []

    def _add(candidate: str) -> None:
        value = _clean(candidate)
        if not value or value in seen:
            return
        ioc_type = detect_ioc_type(value)
        if ioc_type != IOCType.UNKNOWN:
            seen.add(value)
            results.append(ExtractedIOC(value=value, ioc_type=ioc_type))

    # --- Fase 1: URLs ---
    urls = _RE_URL.findall(text)
    for u in urls:
        _add(u)
    # Borra las URLs del texto para que el resto de fases no las fragmenten
    working = _RE_URL.sub(" ", text)

    # --- Fase 2: IPs ---
    for ip in _RE_IPV4.findall(working):
        _add(ip)
    for ip in _RE_IPV6.findall(working):
        _add(ip)
    working = _RE_IPV4.sub(" ", working)
    working = _RE_IPV6.sub(" ", working)

    # --- Fase 3: Hashes (orden: SHA256 → SHA1 → MD5) ---
    for h in _RE_SHA256.findall(working):
        _add(h)
    working = _RE_SHA256.sub(" ", working)

    for h in _RE_SHA1.findall(working):
        _add(h)
    working = _RE_SHA1.sub(" ", working)

    for h in _RE_MD5.findall(working):
        _add(h)
    working = _RE_MD5.sub(" ", working)

    # --- Fase 4: Dominios ---
    for d in _RE_DOMAIN.findall(working):
        _add(d)

    return results


def extract_iocs_from_bytes(content: bytes, encoding: str = "utf-8") -> list[ExtractedIOC]:
    """Wrapper para contenido binario (fichero subido vía multipart)."""
    try:
        text = content.decode(encoding)
    except UnicodeDecodeError:
        text = content.decode("latin-1", errors="replace")
    return extract_iocs(text)
