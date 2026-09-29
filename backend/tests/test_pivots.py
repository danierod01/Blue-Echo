"""Tests del pivoting (extracción de entidades relacionadas)."""

from ioc_correlator.pivots import extract_pivots


def _r(source, data):
    return {"source": source, "success": True, "verdict": "info", "summary": "", "data": data, "error": None}


def test_domain_resolves_to_ip():
    pivots = extract_pivots({}, "evil.com", "domain", resolved_ip="1.2.3.4")
    assert any(p["value"] == "1.2.3.4" and p["ioc_type"] == "ipv4" for p in pivots)
    assert pivots[0]["relation"] == "Resuelve a esta IP"


def test_ip_hostnames_from_shodan():
    raw = {"shodan": _r("shodan", {"hostnames": ["a.evil.com", "b.evil.com"]})}
    pivots = extract_pivots(raw, "1.2.3.4", "ipv4")
    values = {p["value"] for p in pivots}
    assert values == {"a.evil.com", "b.evil.com"}
    assert all(p["ioc_type"] == "domain" for p in pivots)


def test_rdap_nameservers_and_ipinfo_hostname():
    raw = {
        "rdap": _r("rdap", {"nameservers": ["ns1.dns.com", "ns2.dns.com"]}),
        "ipinfo": _r("ipinfo", {"hostname": "host.example.net"}),
    }
    pivots = extract_pivots(raw, "evil.com", "domain")
    rels = {p["value"]: p["relation"] for p in pivots}
    assert rels["ns1.dns.com"] == "Nameserver del dominio"
    assert rels["host.example.net"] == "Hostname (PTR) de la IP"


def test_excludes_self_and_dedups():
    raw = {
        "shodan": _r("shodan", {"hostnames": ["evil.com", "evil.com", "other.com"]}),
    }
    pivots = extract_pivots(raw, "evil.com", "ipv4")
    values = [p["value"] for p in pivots]
    assert "evil.com" not in values          # el propio IOC se excluye
    assert values.count("other.com") == 1    # sin duplicados


def test_invalid_candidates_filtered():
    raw = {"shodan": _r("shodan", {"hostnames": ["", "no es un dominio", "1.2.3.4"]})}
    pivots = extract_pivots(raw, "9.9.9.9", "ipv4")
    values = {p["value"] for p in pivots}
    assert values == {"1.2.3.4"}             # solo el candidato válido


def test_per_source_cap():
    many = [f"h{i}.evil.com" for i in range(20)]
    raw = {"securitytrails": _r("securitytrails", {"nearby_hostnames": many})}
    pivots = extract_pivots(raw, "1.2.3.4", "ipv4")
    assert len(pivots) == 6                   # _MAX_PER_SOURCE


def test_global_cap():
    raw = {
        "shodan": _r("shodan", {"hostnames": [f"a{i}.com" for i in range(6)]}),
        "securitytrails": _r("securitytrails", {"nearby_hostnames": [f"b{i}.com" for i in range(6)]}),
        "rdap": _r("rdap", {"nameservers": [f"ns{i}.com" for i in range(6)]}),
    }
    pivots = extract_pivots(raw, "1.2.3.4", "ipv4")
    assert len(pivots) == 12                  # _MAX_PIVOTS global
