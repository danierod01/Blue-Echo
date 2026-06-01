import asyncio
import logging
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

_IPWHO_URL = "https://ipwho.is/{ip}"
_TIMEOUT = 8.0

# Tipos de IOC que pueden tener geolocalización
_GEO_TYPES = {"ipv4", "ipv6", "domain", "url"}


@dataclass
class GeoLocation:
    lat: float
    lon: float
    city: str
    region: str
    country: str
    country_code: str
    org: Optional[str] = None
    resolved_ip: Optional[str] = None


async def _geolocate_ip(ip: str) -> Optional[GeoLocation]:
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_IPWHO_URL.format(ip=ip))
            resp.raise_for_status()
            data = resp.json()

        if not data.get("success"):
            return None

        lat = data.get("latitude")
        lon = data.get("longitude")
        if lat is None or lon is None:
            return None

        return GeoLocation(
            lat=float(lat),
            lon=float(lon),
            city=data.get("city", ""),
            region=data.get("region", ""),
            country=data.get("country", ""),
            country_code=data.get("country_code", ""),
            org=data.get("connection", {}).get("org"),
        )
    except Exception as exc:
        logger.debug("geolocator: error para IP %s — %s", ip, exc)
        return None


async def _resolve_ip(hostname: str) -> Optional[str]:
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, hostname)
        return ip
    except socket.gaierror:
        return None


async def geolocate(ioc_value: str, ioc_type: str) -> Optional[GeoLocation]:
    """Geolocaliza un IOC. Devuelve None si el tipo no es geolocatable o falla."""
    if ioc_type not in _GEO_TYPES:
        return None

    if ioc_type in ("ipv4", "ipv6"):
        return await _geolocate_ip(ioc_value)

    if ioc_type == "domain":
        ip = await _resolve_ip(ioc_value)
        if not ip:
            return None
        result = await _geolocate_ip(ip)
        if result:
            result.resolved_ip = ip
        return result

    if ioc_type == "url":
        hostname = urlparse(ioc_value).hostname
        if not hostname:
            return None
        ip = await _resolve_ip(hostname)
        if not ip:
            return None
        result = await _geolocate_ip(ip)
        if result:
            result.resolved_ip = ip
        return result

    return None
