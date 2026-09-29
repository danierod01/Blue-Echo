"""Extracción de entidades relacionadas para *pivoting* (escaneo encadenado).

A partir de los resultados de los conectores, deriva IOCs relacionados con el
indicador escaneado —la IP a la que resuelve un dominio, los hostnames de una
IP, los nameservers de un dominio, etc.— para que el analista pueda pivotar con
un clic y lanzar un nuevo escaneo sobre ellos. Es el flujo de trabajo real de
una investigación de Threat Intelligence.

La función es pura (no hace I/O): recibe los resultados ya calculados y devuelve
una lista de `{value, ioc_type, relation, source}`, deduplicada, validada y
acotada, excluyendo el propio IOC escaneado.
"""

from __future__ import annotations

from ioc_correlator.utils.validators import IOCType, detect_ioc_type

_MAX_PIVOTS = 12          # tope global para no saturar la UI
_MAX_PER_SOURCE = 6       # tope por conector (p.ej. hostnames vecinos)

# Tipos que tienen sentido como pivote (algo escaneable de nuevo).
_PIVOTABLE = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN}


def _norm(value: str) -> str:
    return (value or "").strip().strip(".").lower()


def extract_pivots(
    raw_results: dict,
    ioc_value: str,
    ioc_type: str,
    resolved_ip: str | None = None,
) -> list[dict]:
    """Devuelve las entidades relacionadas para pivotar."""
    self_norm = _norm(ioc_value)
    seen: set[str] = {self_norm}
    pivots: list[dict] = []

    def add(value: str, relation: str, source: str) -> None:
        v = _norm(value)
        if not v or v in seen:
            return
        t = detect_ioc_type(v)
        if t not in _PIVOTABLE:
            return
        seen.add(v)
        pivots.append({"value": v, "ioc_type": t.value, "relation": relation, "source": source})

    # 1) Dominio/URL → IP a la que resuelve (de la geolocalización).
    if resolved_ip and ioc_type in ("domain", "url"):
        add(resolved_ip, "Resuelve a esta IP", "dns")

    # 2) Recorre los datos de cada conector buscando relaciones conocidas.
    for name, result in raw_results.items():
        if name == "__pcap_data__":
            continue
        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            continue

        count = 0

        def add_capped(value: str, relation: str) -> None:
            nonlocal count
            if count >= _MAX_PER_SOURCE:
                return
            before = len(pivots)
            add(value, relation, name)
            if len(pivots) > before:
                count += 1

        # Shodan: hostnames asociados a la IP.
        for h in (data.get("hostnames") or []):
            add_capped(str(h), "Hostname de la IP")

        # IPinfo: hostname (PTR) de la IP.
        if data.get("hostname"):
            add_capped(str(data["hostname"]), "Hostname (PTR) de la IP")

        # RDAP: nameservers del dominio.
        for ns in (data.get("nameservers") or []):
            add_capped(str(ns), "Nameserver del dominio")

        # SecurityTrails: hostnames vecinos en el bloque /24.
        for h in (data.get("nearby_hostnames") or []):
            add_capped(str(h), "Host vecino en el bloque /24")

        if len(pivots) >= _MAX_PIVOTS:
            break

    return pivots[:_MAX_PIVOTS]
