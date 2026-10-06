"""Tests del geolocalizador: no debe reventar ante entradas mal formadas."""

import pytest

from ioc_correlator.geolocator import geolocate


@pytest.mark.asyncio
async def test_geolocate_malformed_url_returns_none():
    """Una URL con corchetes (IOC mal formado o defanged sin normalizar) rompía
    urlparse con ValueError → 500. Ahora se controla y devuelve None."""
    bad = "hxxp://testsafebrowsing[.]appspot[.]com/s/malware[.]html"
    assert await geolocate(bad, "url") is None


@pytest.mark.asyncio
async def test_geolocate_non_geolocatable_type():
    assert await geolocate("d41d8cd98f00b204e9800998ecf8427e", "md5") is None
