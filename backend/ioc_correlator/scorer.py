from dataclasses import dataclass, field

from ioc_correlator.connectors.base import ConnectorResult

# Puertos considerados sensibles para la regla de Shodan
_SENSITIVE_PORTS = {22, 3389, 445, 1433, 4444}


@dataclass
class ScoringResult:
    score: int                              # 0-100
    verdict: str                            # "clean" | "suspicious" | "malicious" | "critical"
    breakdown: dict[str, int] = field(default_factory=dict)  # puntos por conector


def _verdict(score: int) -> str:
    if score >= 81:
        return "critical"
    if score >= 51:
        return "malicious"
    if score >= 21:
        return "suspicious"
    return "clean"


def _score_virustotal(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    malicious: int = result.data.get("malicious", 0)
    suspicious: int = result.data.get("suspicious", 0)
    if malicious > 5:
        return 30
    if malicious >= 1 or suspicious > 0:
        return 15
    return 0


def _score_abuseipdb(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    confidence: int = result.data.get("confidence", 0)
    if confidence > 80:
        return 40
    if confidence > 50:
        return 25
    return 0


def _score_shodan(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    open_ports: list[int] = result.data.get("open_ports", [])
    hits = sum(1 for p in open_ports if p in _SENSITIVE_PORTS)
    return min(hits * 10, 30)


def _score_otx(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    return 20 if result.data.get("pulse_count", 0) > 0 else 0


def _score_malwarebazaar(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    return 40 if result.data.get("found", False) else 0


def _score_greynoise(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    classification = result.data.get("classification", "")
    if classification == "malicious":
        return 30
    if classification == "benign":
        return -10
    return 0


def _score_threatfox(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    return 30 if result.data.get("found", False) else 0


def _score_ipinfo(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    if result.data.get("is_tor"):
        return 20
    if result.data.get("is_vpn") or result.data.get("is_proxy"):
        return 10
    return 0


def _score_securitytrails(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    days_old = result.data.get("days_old")
    if days_old is not None and days_old < 30:
        return 20
    return 0


def _score_hybrid_analysis(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    if not result.data.get("found"):
        return 0
    threat_level: int = result.data.get("threat_level", 0)
    if threat_level >= 2:
        return 35
    if threat_level == 1:
        return 15
    return 0


def _score_netlas(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    sensitive: list = result.data.get("sensitive_ports", [])
    return min(len(sensitive) * 10, 20)


def _score_criminal_ip(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    worst: str = result.data.get("worst_score", result.data.get("score", ""))
    score_map = {"critical": 35, "dangerous": 30, "moderate": 15}
    return score_map.get(worst, 0)


def _score_malshare(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    return 35 if result.data.get("found", False) else 0


def _score_pulsedive(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    risk_map = {"high": 25, "critical": 35, "medium": 10}
    return risk_map.get(result.data.get("risk", ""), 0)


def _score_censys(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    sensitive: list = result.data.get("sensitive_ports", [])
    return min(len(sensitive) * 10, 20)


_RULES: dict[str, object] = {
    "virustotal":       _score_virustotal,
    "abuseipdb":        _score_abuseipdb,
    "shodan":           _score_shodan,
    "otx":              _score_otx,
    "malwarebazaar":    _score_malwarebazaar,
    "greynoise":        _score_greynoise,
    "threatfox":        _score_threatfox,
    "ipinfo":           _score_ipinfo,
    "securitytrails":   _score_securitytrails,
    "hybrid_analysis":  _score_hybrid_analysis,
    "netlas":           _score_netlas,
    "criminal_ip":      _score_criminal_ip,
    "malshare":         _score_malshare,
    "pulsedive":        _score_pulsedive,
    "censys":           _score_censys,
}


def compute_score(results: dict[str, ConnectorResult]) -> ScoringResult:
    """Calcula el score 0-100 a partir de los resultados de los conectores.

    Cada conector contribuye puntos según reglas fijas. Si un conector
    falló o no está disponible, contribuye 0 puntos (degradación graceful).
    El score se acota entre 0 y 100.
    """
    breakdown: dict[str, int] = {}
    total = 0

    for connector_name, rule_fn in _RULES.items():
        if connector_name in results:
            pts = rule_fn(results[connector_name])
            breakdown[connector_name] = pts
            total += pts

    score = max(0, min(100, total))
    return ScoringResult(score=score, verdict=_verdict(score), breakdown=breakdown)
