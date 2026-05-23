import logging

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_BASE_URL = "https://www.hybrid-analysis.com/api/v2"
# Hybrid Analysis exige un User-Agent específico en su API
_USER_AGENT = "Falcon Sandbox"


class HybridAnalysisConnector(BaseConnector):
    name = "hybrid_analysis"
    supported_types = [IOCType.MD5, IOCType.SHA1, IOCType.SHA256]
    api_key_env = "HYBRID_ANALYSIS_API_KEY"

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        async with self._make_client() as client:
            resp = await client.post(
                f"{_BASE_URL}/search/hash",
                headers={
                    "api-key": self.api_key,
                    "User-Agent": _USER_AGENT,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                content=f"hash={ioc_value}",
            )
            resp.raise_for_status()
            return self._parse(resp.json(), ioc_value)

    def _parse(self, body, ioc_value: str) -> ConnectorResult:
        try:
            results: list = body if isinstance(body, list) else []
            if not results:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="Hybrid Analysis: hash no encontrado en la base de datos.",
                    data={"found": False},
                )

            # Tomamos el resultado con más información (mayor threat_score)
            best = max(results, key=lambda r: r.get("threat_score") or 0)
            threat_score: int = best.get("threat_score") or 0
            verdict_raw: str = best.get("verdict") or "unknown"
            malware_family: str = best.get("vx_family") or ""
            av_detect: int = best.get("av_detect") or 0
            threat_level: int = best.get("threat_level") or 0

            if verdict_raw in ("malicious",) or threat_level >= 2:
                verdict = "malicious"
            elif verdict_raw in ("suspicious",) or threat_level == 1:
                verdict = "suspicious"
            else:
                verdict = "clean"

            summary = f"Hybrid Analysis: {verdict_raw}, threat score {threat_score}/100"
            if malware_family:
                summary += f", familia: {malware_family}"
            if av_detect:
                summary += f", {av_detect} detecciones AV"
            summary += "."

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=summary,
                data={
                    "found": True,
                    "threat_score": threat_score,
                    "verdict_raw": verdict_raw,
                    "malware_family": malware_family,
                    "av_detect": av_detect,
                    "threat_level": threat_level,
                    "total_results": len(results),
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("hybrid_analysis: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="Hybrid Analysis: respuesta inesperada de la API.",
                error="parse_error",
            )
