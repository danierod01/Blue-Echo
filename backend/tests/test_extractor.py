import pytest
from ioc_correlator.extractor import extract_iocs, extract_iocs_from_bytes
from ioc_correlator.utils.validators import IOCType


def _values(iocs):
    return [i.value for i in iocs]


def _types(iocs):
    return {i.value: i.ioc_type for i in iocs}


# ---------------------------------------------------------------------------
# Texto libre genérico
# ---------------------------------------------------------------------------

def test_extract_single_ipv4():
    result = extract_iocs("Conexión bloqueada desde 192.168.1.100")
    assert "192.168.1.100" in _values(result)
    assert _types(result)["192.168.1.100"] == IOCType.IPV4


def test_extract_single_domain():
    result = extract_iocs("El host malware.evil.com realizó el ataque")
    assert "malware.evil.com" in _values(result)
    assert _types(result)["malware.evil.com"] == IOCType.DOMAIN


def test_extract_url_does_not_fragment_domain():
    """La URL debe extraerse completa; el dominio dentro no debe aparecer suelto."""
    result = extract_iocs("Descarga desde https://malware.com/payload.exe")
    values = _values(result)
    assert "https://malware.com/payload.exe" in values
    assert "malware.com" not in values


def test_extract_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    result = extract_iocs(f"Hash del fichero: {h}")
    assert h in _values(result)
    assert _types(result)[h] == IOCType.SHA256


def test_extract_sha1():
    h = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    result = extract_iocs(f"SHA1={h}")
    assert h in _values(result)
    assert _types(result)[h] == IOCType.SHA1


def test_extract_md5():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    result = extract_iocs(f"md5: {h}")
    assert h in _values(result)
    assert _types(result)[h] == IOCType.MD5


def test_sha256_not_fragmented_into_md5_sha1():
    """Un SHA256 no debe aparecer también como MD5 (primeros 32 chars) o SHA1."""
    h256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    result = extract_iocs(h256)
    assert len(result) == 1
    assert result[0].ioc_type == IOCType.SHA256


def test_deduplication():
    text = "IP: 1.2.3.4 y otra vez 1.2.3.4 y más 1.2.3.4"
    result = extract_iocs(text)
    assert _values(result).count("1.2.3.4") == 1


def test_empty_text():
    assert extract_iocs("") == []


def test_no_iocs():
    assert extract_iocs("Nada que ver aquí, solo texto normal.") == []


# ---------------------------------------------------------------------------
# Formato Apache/Nginx access log
# ---------------------------------------------------------------------------

def test_apache_log_extracts_ip_and_domain():
    log = (
        '185.220.101.45 - - [27/Apr/2026:10:23:01 +0000] '
        '"GET /admin HTTP/1.1" 404 512 "-" "curl/7.68.0"'
    )
    result = extract_iocs(log)
    assert "185.220.101.45" in _values(result)


def test_nginx_log_with_url_referer():
    log = (
        '10.0.0.1 - - [27/Apr/2026:12:00:00 +0000] '
        '"POST /upload HTTP/1.1" 200 1024 '
        '"http://evil.com/c2" "Python-urllib/3.9"'
    )
    result = extract_iocs(log)
    values = _values(result)
    assert "10.0.0.1" in values
    assert "http://evil.com/c2" in values


# ---------------------------------------------------------------------------
# Formato syslog
# ---------------------------------------------------------------------------

def test_syslog_extracts_ip():
    log = "Apr 27 10:15:00 server sshd[1234]: Failed password from 203.0.113.42 port 22"
    result = extract_iocs(log)
    assert "203.0.113.42" in _values(result)


# ---------------------------------------------------------------------------
# JSON lines
# ---------------------------------------------------------------------------

def test_jsonlines_extracts_iocs():
    log = (
        '{"ts":"2026-04-27","src":"198.51.100.7","domain":"c2.malware.io"}\n'
        '{"ts":"2026-04-27","hash":"44d88612fea8a8f36de82e1278abb02f"}'
    )
    result = extract_iocs(log)
    values = _values(result)
    assert "198.51.100.7" in values
    assert "c2.malware.io" in values
    assert "44d88612fea8a8f36de82e1278abb02f" in values


# ---------------------------------------------------------------------------
# Múltiples IOCs mezclados
# ---------------------------------------------------------------------------

def test_mixed_iocs():
    text = """
    Reporte de incidente:
    - IP origen: 185.220.101.45
    - Dominio C2: badactor.com
    - Hash payload: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    - Descarga: https://badactor.com/dropper.exe
    """
    result = extract_iocs(text)
    values = _values(result)
    assert "185.220.101.45" in values
    assert "badactor.com" in values
    assert "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" in values
    assert "https://badactor.com/dropper.exe" in values
    # La URL ya captura badactor.com; puede aparecer suelto porque la URL
    # solo borra la ocurrencia de la URL, no todas las menciones del dominio
    assert len([v for v in values if v == "badactor.com"]) <= 1  # sin duplicados


# ---------------------------------------------------------------------------
# Bytes / fichero subido
# ---------------------------------------------------------------------------

def test_extract_from_bytes_utf8():
    content = b"Ataque desde 1.2.3.4 y hash d41d8cd98f00b204e9800998ecf8427e"
    result = extract_iocs_from_bytes(content)
    values = _values(result)
    assert "1.2.3.4" in values
    assert "d41d8cd98f00b204e9800998ecf8427e" in values


def test_extract_from_bytes_latin1_fallback():
    content = "IP: 10.0.0.1 \xe9\xe0\xfc".encode("latin-1")
    result = extract_iocs_from_bytes(content)
    assert "10.0.0.1" in _values(result)
