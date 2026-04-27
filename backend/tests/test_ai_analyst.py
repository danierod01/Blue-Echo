import pytest

from ioc_correlator.ai_analyst import _local_analysis, generate_summary
from ioc_correlator.connectors.base import ConnectorResult
from ioc_correlator.scorer import ScoringResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_scoring(score: int, verdict: str) -> ScoringResult:
    return ScoringResult(score=score, verdict=verdict, breakdown={})


def vt(malicious: int = 0, total: int = 87) -> ConnectorResult:
    return ConnectorResult(
        source="virustotal", success=True,
        data={"malicious": malicious, "total": total, "stats": {}},
        verdict="malicious" if malicious > 5 else "clean",
        summary=f"VT: {malicious}/{total}",
    )


def abuse(confidence: int = 0, reports: int = 0, isp: str = "") -> ConnectorResult:
    return ConnectorResult(
        source="abuseipdb", success=True,
        data={"confidence": confidence, "total_reports": reports, "isp": isp},
        verdict="malicious" if confidence > 80 else "clean",
        summary=f"AbuseIPDB: {confidence}%",
    )


def failed(source: str) -> ConnectorResult:
    return ConnectorResult(source=source, success=False, error="timeout",
                           verdict="unknown", summary="timeout")


# ---------------------------------------------------------------------------
# Tests de _local_analysis
# ---------------------------------------------------------------------------

def test_local_analysis_contains_ioc_value():
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(87, "critical"), {})
    assert "1.2.3.4" in r


def test_local_analysis_contains_score():
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(87, "critical"), {})
    assert "87" in r


def test_local_analysis_critical_verdict():
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(87, "critical"), {})
    assert "CRÍTICO" in r
    assert "bloquear inmediatamente" in r.lower()


def test_local_analysis_malicious_verdict():
    r = _local_analysis("evil.com", "domain", make_scoring(60, "malicious"), {})
    assert "MALICIOSO" in r
    assert "bloquear" in r.lower()


def test_local_analysis_suspicious_verdict():
    r = _local_analysis("evil.com", "domain", make_scoring(35, "suspicious"), {})
    assert "SOSPECHOSO" in r
    assert "monitorizar" in r.lower()


def test_local_analysis_clean_verdict():
    r = _local_analysis("1.1.1.1", "ipv4", make_scoring(0, "clean"), {})
    assert "LIMPIO" in r
    assert "rutinaria" in r.lower()


def test_local_analysis_vt_detections():
    results = {"virustotal": vt(malicious=23, total=87)}
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(87, "critical"), results)
    assert "23" in r and "87" in r


def test_local_analysis_vt_clean():
    results = {"virustotal": vt(malicious=0, total=87)}
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(0, "clean"), results)
    assert "no registra detecciones" in r.lower()


def test_local_analysis_abuseipdb_with_isp():
    results = {"abuseipdb": abuse(confidence=95, reports=142, isp="Tor Exit")}
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(87, "critical"), results)
    assert "95%" in r
    assert "142" in r
    assert "Tor Exit" in r


def test_local_analysis_failed_connector_skipped():
    results = {"virustotal": failed("virustotal")}
    r = _local_analysis("1.2.3.4", "ipv4", make_scoring(0, "clean"), results)
    # El conector fallido no debe aparecer en el análisis
    assert "VirusTotal" not in r


def test_local_analysis_hash_prefix():
    h = "d41d8cd98f00b204e9800998ecf8427e"
    r = _local_analysis(h, "md5", make_scoring(40, "suspicious"), {})
    assert "hash md5" in r.lower()


def test_local_analysis_returns_string():
    r = _local_analysis("x.com", "domain", make_scoring(0, "clean"), {})
    assert isinstance(r, str)
    assert len(r) > 20


# ---------------------------------------------------------------------------
# Tests de generate_summary (función async pública)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_summary_no_api_key_uses_local(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    scoring = make_scoring(87, "critical")
    results = {"virustotal": vt(malicious=23), "abuseipdb": abuse(confidence=95)}
    summary = await generate_summary("1.2.3.4", "ipv4", scoring, results)
    assert isinstance(summary, str)
    assert len(summary) > 20
    assert "1.2.3.4" in summary


@pytest.mark.asyncio
async def test_generate_summary_api_failure_falls_back_to_local(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")

    async def fake_claude(*args, **kwargs):
        raise RuntimeError("API no disponible")

    monkeypatch.setattr("ioc_correlator.ai_analyst._claude_api_analysis", fake_claude)

    scoring = make_scoring(70, "malicious")
    summary = await generate_summary("evil.com", "domain", scoring, {})
    assert isinstance(summary, str)
    assert len(summary) > 20


@pytest.mark.asyncio
async def test_generate_summary_with_api_key_calls_claude(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "real-key")

    async def fake_claude(ioc_value, ioc_type, scoring, results, api_key):
        assert api_key == "real-key"
        return "Análisis generado por Claude API."

    monkeypatch.setattr("ioc_correlator.ai_analyst._claude_api_analysis", fake_claude)

    scoring = make_scoring(50, "malicious")
    summary = await generate_summary("1.2.3.4", "ipv4", scoring, {})
    assert summary == "Análisis generado por Claude API."
