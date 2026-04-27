import pytest
from ioc_correlator.utils.validators import IOCType, detect_ioc_type, is_valid_ioc


@pytest.mark.parametrize("value, expected", [
    # IPv4
    ("1.2.3.4",           IOCType.IPV4),
    ("192.168.1.1",       IOCType.IPV4),
    ("0.0.0.0",           IOCType.IPV4),
    ("255.255.255.255",   IOCType.IPV4),
    # IPv6
    ("2001:db8::1",                           IOCType.IPV6),
    ("::1",                                   IOCType.IPV6),
    ("fe80::1",                               IOCType.IPV6),
    ("2606:4700:4700::1111",                  IOCType.IPV6),
    # MD5 (32 hex)
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5),
    ("44d88612fea8a8f36de82e1278abb02f", IOCType.MD5),
    # SHA1 (40 hex)
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.SHA1),
    ("adc83b19e793491b1c6ea0fd8b46cd9f32e592fc", IOCType.SHA1),
    # SHA256 (64 hex)
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.SHA256),
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", IOCType.SHA256),
    # Dominio / FQDN
    ("example.com",             IOCType.DOMAIN),
    ("sub.example.com",         IOCType.DOMAIN),
    ("malware.evil.co.uk",      IOCType.DOMAIN),
    ("xn--nxasmq6b.com",        IOCType.DOMAIN),  # IDN punycode
    # URL
    ("http://example.com",              IOCType.URL),
    ("https://malware.com/payload.exe", IOCType.URL),
    ("HTTP://UPPERCASE.COM/path",       IOCType.URL),
    # UNKNOWN
    ("not-an-ioc",          IOCType.UNKNOWN),
    ("localhost",            IOCType.UNKNOWN),
    ("",                     IOCType.UNKNOWN),
    ("  ",                   IOCType.UNKNOWN),
    ("256.256.256.256",      IOCType.UNKNOWN),   # IP inválida
    ("zzzzz",                IOCType.UNKNOWN),
])
def test_detect_ioc_type(value: str, expected: IOCType) -> None:
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize("value, expected", [
    ("1.2.3.4",           True),
    ("example.com",       True),
    ("http://x.com",      True),
    ("d41d8cd98f00b204e9800998ecf8427e", True),
    ("not-an-ioc",        False),
    ("",                  False),
    ("localhost",         False),
])
def test_is_valid_ioc(value: str, expected: bool) -> None:
    assert is_valid_ioc(value) == expected
