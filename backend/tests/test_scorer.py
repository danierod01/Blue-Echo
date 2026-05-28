import pytest
from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.scorer import ScoringResult, compute_score


# ---------------------------------------------------------------------------
# Helpers para construir ConnectorResults de prueba
# ---------------------------------------------------------------------------

def vt_result(malicious: int = 0, suspicious: int = 0, success: bool = True) -> ConnectorResult:
    return ConnectorResult(
        source="virustotal",
        success=success,
        data={"malicious": malicious, "suspicious": suspicious, "total": 87},
        verdict="unknown",
    )


def abuse_result(confidence: int = 0, success: bool = True) -> ConnectorResult:
    return ConnectorResult(
        source="abuseipdb",
        success=success,
        data={"confidence": confidence, "total_reports": 10},
        verdict="unknown",
    )


def shodan_result(ports: list[int] = None, success: bool = True) -> ConnectorResult:
    return ConnectorResult(
        source="shodan",
        success=success,
        data={"open_ports": ports or []},
        verdict="unknown",
    )


def otx_result(pulse_count: int = 0, success: bool = True) -> ConnectorResult:
    return ConnectorResult(
        source="otx",
        success=success,
        data={"pulse_count": pulse_count},
        verdict="unknown",
    )


def malwarebazaar_result(found: bool = False, success: bool = True) -> ConnectorResult:
    return ConnectorResult(
        source="malwarebazaar",
        success=success,
        data={"found": found},
        verdict="unknown",
    )



# ---------------------------------------------------------------------------
# Tests de veredicto por score
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("score, expected", [
    (0,   "clean"),
    (20,  "clean"),
    (21,  "suspicious"),
    (50,  "suspicious"),
    (51,  "malicious"),
    (80,  "malicious"),
    (81,  "critical"),
    (100, "critical"),
])
def test_verdict_thresholds(score, expected):
    # Forzamos el score usando MalwareBazaar (40) + AbuseIPDB >80 (40) = 80 max con dos
    # Para valores exactos usamos directamente el helper de compute_score con mocks
    from ioc_correlator.scorer import _verdict
    assert _verdict(score) == expected


# ---------------------------------------------------------------------------
# Tests de reglas individuales — VirusTotal
# ---------------------------------------------------------------------------

def test_vt_more_than_5_gives_30():
    r = compute_score({"virustotal": vt_result(malicious=23)})
    assert r.breakdown["virustotal"] == 30


def test_vt_1_to_5_gives_15():
    r = compute_score({"virustotal": vt_result(malicious=3)})
    assert r.breakdown["virustotal"] == 15


def test_vt_suspicious_only_gives_15():
    r = compute_score({"virustotal": vt_result(malicious=0, suspicious=2)})
    assert r.breakdown["virustotal"] == 15


def test_vt_clean_gives_0():
    r = compute_score({"virustotal": vt_result(malicious=0, suspicious=0)})
    assert r.breakdown["virustotal"] == 0


def test_vt_failed_gives_0():
    r = compute_score({"virustotal": vt_result(malicious=99, success=False)})
    assert r.breakdown["virustotal"] == 0


# ---------------------------------------------------------------------------
# Tests de reglas individuales — AbuseIPDB
# ---------------------------------------------------------------------------

def test_abuse_above_80_gives_40():
    r = compute_score({"abuseipdb": abuse_result(confidence=95)})
    assert r.breakdown["abuseipdb"] == 40


def test_abuse_50_to_80_gives_25():
    r = compute_score({"abuseipdb": abuse_result(confidence=65)})
    assert r.breakdown["abuseipdb"] == 25


def test_abuse_below_50_gives_0():
    r = compute_score({"abuseipdb": abuse_result(confidence=30)})
    assert r.breakdown["abuseipdb"] == 0


def test_abuse_failed_gives_0():
    r = compute_score({"abuseipdb": abuse_result(confidence=99, success=False)})
    assert r.breakdown["abuseipdb"] == 0


# ---------------------------------------------------------------------------
# Tests de reglas individuales — Shodan
# ---------------------------------------------------------------------------

def test_shodan_one_sensitive_port_gives_10():
    r = compute_score({"shodan": shodan_result(ports=[22])})
    assert r.breakdown["shodan"] == 10


def test_shodan_three_sensitive_ports_gives_30():
    r = compute_score({"shodan": shodan_result(ports=[22, 3389, 445])})
    assert r.breakdown["shodan"] == 30


def test_shodan_capped_at_30():
    r = compute_score({"shodan": shodan_result(ports=[22, 3389, 445, 1433, 4444])})
    assert r.breakdown["shodan"] == 30


def test_shodan_non_sensitive_port_gives_0():
    r = compute_score({"shodan": shodan_result(ports=[80, 443, 8080])})
    assert r.breakdown["shodan"] == 0


# ---------------------------------------------------------------------------
# Tests de reglas individuales — OTX, MalwareBazaar, GreyNoise
# ---------------------------------------------------------------------------

def test_otx_with_pulses_gives_20():
    r = compute_score({"otx": otx_result(pulse_count=3)})
    assert r.breakdown["otx"] == 20


def test_otx_no_pulses_gives_0():
    r = compute_score({"otx": otx_result(pulse_count=0)})
    assert r.breakdown["otx"] == 0


def test_malwarebazaar_found_gives_40():
    r = compute_score({"malwarebazaar": malwarebazaar_result(found=True)})
    assert r.breakdown["malwarebazaar"] == 40


def test_malwarebazaar_not_found_gives_0():
    r = compute_score({"malwarebazaar": malwarebazaar_result(found=False)})
    assert r.breakdown["malwarebazaar"] == 0



# ---------------------------------------------------------------------------
# Tests de acumulación y acotamiento
# ---------------------------------------------------------------------------

def test_score_capped_at_100():
    results = {
        "virustotal":    vt_result(malicious=50),             # +30
        "abuseipdb":     abuse_result(confidence=95),         # +40
        "malwarebazaar": malwarebazaar_result(found=True),    # +40
        "otx":           otx_result(pulse_count=5),           # +20
        "shodan":        shodan_result(ports=[22, 3389, 445]), # +30
    }
    r = compute_score(results)
    assert r.score == 100
    assert r.verdict == "critical"


def test_score_floor_at_0():
    results = {
        "virustotal": vt_result(malicious=0),  # +0
    }
    r = compute_score(results)
    assert r.score == 0


def test_score_accumulates_correctly():
    results = {
        "virustotal": vt_result(malicious=3),   # +15
        "abuseipdb":  abuse_result(confidence=65),  # +25
    }
    r = compute_score(results)
    assert r.score == 40
    assert r.verdict == "suspicious"


def test_empty_results_gives_0():
    r = compute_score({})
    assert r.score == 0
    assert r.verdict == "clean"
    assert r.breakdown == {}


def test_missing_connector_not_in_breakdown():
    r = compute_score({"virustotal": vt_result(malicious=10)})
    assert "abuseipdb" not in r.breakdown


def test_breakdown_contains_all_present_connectors():
    results = {
        "virustotal": vt_result(malicious=10),
        "abuseipdb":  abuse_result(confidence=90),
    }
    r = compute_score(results)
    assert set(r.breakdown.keys()) == {"virustotal", "abuseipdb"}


def test_critical_verdict():
    results = {
        "virustotal": vt_result(malicious=50),   # +30
        "abuseipdb":  abuse_result(confidence=99),  # +40
        "otx":        otx_result(pulse_count=1),    # +20
    }
    r = compute_score(results)
    assert r.score == 90
    assert r.verdict == "critical"
