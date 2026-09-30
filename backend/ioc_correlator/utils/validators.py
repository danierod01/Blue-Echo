import ipaddress
import re
from enum import Enum


class IOCType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    DOMAIN = "domain"
    URL = "url"
    UNKNOWN = "unknown"


# Hashes: solo dígitos hexadecimales, longitud fija
_RE_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_RE_SHA1 = re.compile(r"^[a-fA-F0-9]{40}$")
_RE_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")

# FQDN: etiquetas separadas por puntos, TLD de al menos 2 letras.
# No valida IPs (se comprueba antes).
_RE_DOMAIN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# URL: esquema http/https obligatorio
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Refang: normalización de IOCs "neutralizados" (defanged)
# ---------------------------------------------------------------------------
# Los analistas copian IOCs de informes de amenazas, correos de phishing o
# feeds donde el indicador viene "desactivado" para que no sea clicable:
#   hxxp://1[.]2[.]3[.]4/x   evil[dot]com   user[at]host   8[.]8[.]8[.]8
# refang() lo revierte a su forma real. Es idempotente: aplicado sobre un IOC
# ya normal no lo modifica.
_DEFANG_PATTERNS = [
    (re.compile(r"h[xX]{2}p", re.IGNORECASE), "http"),   # hxxp/hxxps -> http/https
    (re.compile(r"fxp://", re.IGNORECASE), "ftp://"),
    (re.compile(r"\[\s*(?:dot|\.)\s*\]", re.IGNORECASE), "."),   # [dot] [.]
    (re.compile(r"\(\s*(?:dot|\.)\s*\)", re.IGNORECASE), "."),   # (dot) (.)
    (re.compile(r"\{\s*(?:dot|\.)\s*\}", re.IGNORECASE), "."),   # {dot} {.}
    (re.compile(r"\[\s*(?:at|@)\s*\]", re.IGNORECASE), "@"),     # [at] [@]
    (re.compile(r"\(\s*(?:at|@)\s*\)", re.IGNORECASE), "@"),     # (at) (@)
    (re.compile(r"\[\s*:\s*//\s*\]"), "://"),                    # [://]
    (re.compile(r"\[\s*:\s*\]"), ":"),                           # [:]
    (re.compile(r"\\\."), "."),                                  # \. (punto escapado)
]


def refang(value: str) -> str:
    """Revierte la notación 'defanged' de un IOC a su forma real.

    Ejemplos:
        hxxp://1[.]2[.]3[.]4  -> http://1.2.3.4
        evil[dot]com          -> evil.com
        8[.]8[.]8[.]8         -> 8.8.8.8
    """
    if not value:
        return value
    result = value.strip()
    for pattern, replacement in _DEFANG_PATTERNS:
        result = pattern.sub(replacement, result)
    return result.strip()


def detect_ioc_type(value: str) -> IOCType:
    """Devuelve el IOCType del string recibido.

    El orden de comprobación importa:
    URL → IP → Hash → Dominio → UNKNOWN

    Se aplica refang() primero, de modo que un IOC neutralizado
    (`1[.]2[.]3[.]4`, `hxxp://…`) se reconoce igual que su forma real.
    """
    value = refang(value.strip())

    if _RE_URL.match(value):
        return IOCType.URL

    # Intenta parsear como dirección IP (v4 o v6)
    try:
        addr = ipaddress.ip_address(value)
        return IOCType.IPV4 if addr.version == 4 else IOCType.IPV6
    except ValueError:
        pass

    if _RE_SHA256.match(value):
        return IOCType.SHA256

    if _RE_SHA1.match(value):
        return IOCType.SHA1

    if _RE_MD5.match(value):
        return IOCType.MD5

    if _RE_DOMAIN.match(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def is_valid_ioc(value: str) -> bool:
    """True si el IOC es de un tipo reconocido y procesable."""
    return detect_ioc_type(value) != IOCType.UNKNOWN
