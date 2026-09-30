"""Generación de reglas de bloqueo / acción de respuesta a partir de un IOC.

El análisis dice *qué* es un IOC; este módulo produce el *qué hacer con él*:
reglas listas para pegar en un firewall, un servidor DNS o un fichero hosts.
Cierra el ciclo detección → respuesta que el propio análisis de IA recomienda
("bloquear en firewall perimetral…").

Todo es generación de texto pura (sin dependencias ni E/S), de modo que es
trivial de testear y no puede romper un escaneo.

Reglas por tipo de IOC:
  - IP (v4/v6): iptables, nftables, pf (pfSense/OpenBSD), Cisco ACL,
    Windows Firewall (netsh).
  - Dominio: fichero hosts (sinkhole), Unbound/BIND RPZ, Pi-hole.
  - URL: se extrae el host y se aplican las reglas de dominio + ACL de proxy
    (Squid).
  - Hash: no se bloquea en red; se emite una nota indicando que va en EDR/AV,
    con el hash listo para importar.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlparse

from ioc_correlator.utils.validators import IOCType, detect_ioc_type, refang


def _header(ioc_value: str, verdict: str | None, score: int | None) -> str:
    """Comentario de cabecera común (procedencia + aviso de revisión)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta = f"veredicto={verdict} score={score}" if verdict is not None else ""
    return (
        f"# Blue-Echo IOC-Correlator — regla de bloqueo generada {ts}\n"
        f"# IOC: {ioc_value}  {meta}\n"
        f"# Revisa la regla antes de aplicarla en producción.\n"
    )


def _host_from_url(url: str) -> str:
    """Extrae el host de una URL; si falla, devuelve la cadena original."""
    try:
        host = urlparse(url).hostname
        return host or url
    except ValueError:
        return url


def _ip_rules(ip: str) -> dict[str, str]:
    """Reglas de bloqueo para una IP (entrante y saliente)."""
    v6 = ":" in ip
    ipt = "ip6tables" if v6 else "iptables"
    return {
        "iptables": (
            f"{ipt} -A INPUT  -s {ip} -j DROP\n"
            f"{ipt} -A OUTPUT -d {ip} -j DROP\n"
        ),
        "nftables": (
            f"nft add rule inet filter input  ip{'6' if v6 else ''} saddr {ip} drop\n"
            f"nft add rule inet filter output ip{'6' if v6 else ''} daddr {ip} drop\n"
        ),
        "pf": (
            f"block drop quick from {ip} to any\n"
            f"block drop quick from any to {ip}\n"
        ),
        "cisco": (
            f"access-list 100 deny ip host {ip} any\n"
            f"access-list 100 deny ip any host {ip}\n"
        ),
        "windows": (
            f'netsh advfirewall firewall add rule name="Blue-Echo block {ip}" '
            f"dir=in action=block remoteip={ip}\n"
            f'netsh advfirewall firewall add rule name="Blue-Echo block {ip} (out)" '
            f"dir=out action=block remoteip={ip}\n"
        ),
    }


def _domain_rules(domain: str) -> dict[str, str]:
    """Reglas de sinkhole / bloqueo DNS para un dominio."""
    return {
        "hosts": (
            f"0.0.0.0 {domain}\n"
            f"0.0.0.0 www.{domain}\n"
        ),
        "unbound": (
            f'local-zone: "{domain}." always_nxdomain\n'
        ),
        "bind_rpz": (
            f"{domain}     CNAME .\n"
            f"*.{domain}   CNAME .\n"
        ),
        "pihole": (
            f"# Añadir a la blacklist de Pi-hole:\n"
            f"pihole -b {domain}\n"
        ),
    }


def _url_rules(url: str) -> dict[str, str]:
    """Reglas para una URL: dominio del host + ACL de proxy Squid."""
    host = _host_from_url(url)
    rules: dict[str, str] = {}
    # Si el host es una IP, reglas de firewall; si es dominio, sinkhole DNS.
    if detect_ioc_type(host) in (IOCType.IPV4, IOCType.IPV6):
        rules.update(_ip_rules(host))
    else:
        rules.update(_domain_rules(host))
    rules["squid"] = (
        f'acl blue_echo_block dstdomain {host}\n'
        f"http_access deny blue_echo_block\n"
    )
    return rules


def _hash_rules(ioc_value: str, ioc_type: IOCType) -> dict[str, str]:
    """Un hash no se bloquea en red: se documenta para EDR/AV."""
    return {
        "note": (
            f"# Un {ioc_type.value.upper()} no se bloquea en firewall/DNS.\n"
            f"# Impórtalo en tu EDR/antivirus como indicador de fichero, o genera\n"
            f"# una regla YARA desde el botón 'Regla de detección'.\n"
            f"# Hash: {ioc_value}\n"
        ),
    }


def generate_block_rules(
    ioc_value: str,
    ioc_type: IOCType | str | None = None,
    *,
    verdict: str | None = None,
    score: int | None = None,
) -> dict[str, str]:
    """Devuelve {formato: contenido} con las reglas de bloqueo aplicables al IOC.

    Cada valor lleva su cabecera de procedencia. El tipo se detecta solo si no
    se pasa.
    """
    ioc_value = refang((ioc_value or "").strip())  # nunca meter un IOC neutralizado en una regla
    if isinstance(ioc_type, str):
        try:
            ioc_type = IOCType(ioc_type)
        except ValueError:
            ioc_type = None
    if ioc_type is None:
        ioc_type = detect_ioc_type(ioc_value)

    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        rules = _ip_rules(ioc_value)
    elif ioc_type == IOCType.DOMAIN:
        rules = _domain_rules(ioc_value)
    elif ioc_type == IOCType.URL:
        rules = _url_rules(ioc_value)
    elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        rules = _hash_rules(ioc_value, ioc_type)
    else:
        rules = {}

    header = _header(ioc_value, verdict, score)
    return {fmt: header + "\n" + body for fmt, body in rules.items()}
