"""Tests del refang: normalización de IOCs neutralizados (defanged)."""

import pytest

from ioc_correlator.utils.validators import IOCType, detect_ioc_type, refang


@pytest.mark.parametrize(
    "defanged, expected",
    [
        ("1[.]2[.]3[.]4", "1.2.3.4"),
        ("8[.]8[.]8[.]8", "8.8.8.8"),
        ("evil[dot]com", "evil.com"),
        ("evil(dot)com", "evil.com"),
        ("evil{dot}com", "evil.com"),
        ("hxxp://malware.test/x", "http://malware.test/x"),
        ("hxxps://malware.test", "https://malware.test"),
        ("hXXp://malware.test", "http://malware.test"),
        ("hxxp[://]1[.]2[.]3[.]4", "http://1.2.3.4"),
        ("hxxp[:]//1[.]2[.]3[.]4", "http://1.2.3.4"),
        ("user[at]example[.]com", "user@example.com"),
        ("user(at)example.com", "user@example.com"),
        (r"evil\.com", "evil.com"),
        ("  1[.]2[.]3[.]4  ", "1.2.3.4"),   # con espacios sobrantes
    ],
)
def test_refang_variants(defanged, expected):
    assert refang(defanged) == expected


def test_refang_idempotent():
    """Aplicar refang sobre un IOC ya normal no lo cambia."""
    for value in ("1.2.3.4", "http://example.com", "example.com",
                  "d41d8cd98f00b204e9800998ecf8427e"):
        assert refang(value) == value
        assert refang(refang(value)) == value


def test_refang_empty():
    assert refang("") == ""
    assert refang("   ") == ""


@pytest.mark.parametrize(
    "defanged, expected_type",
    [
        ("1[.]2[.]3[.]4", IOCType.IPV4),
        ("evil[dot]com", IOCType.DOMAIN),
        ("hxxp://malware.test/x", IOCType.URL),
        ("hxxps://malware[.]test", IOCType.URL),
    ],
)
def test_detect_type_on_defanged(defanged, expected_type):
    """detect_ioc_type reconoce un IOC neutralizado igual que su forma real."""
    assert detect_ioc_type(defanged) == expected_type
