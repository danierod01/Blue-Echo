import logging
import os

from ioc_correlator.connectors.base import BaseConnector, ConnectorResult
from ioc_correlator.utils.validators import IOCType

logger = logging.getLogger(__name__)

_SEARCH_URL = "https://urlscan.io/api/v1/search/"


class URLScanConnector(BaseConnector):
    name = "urlscan"
    supported_types = [IOCType.URL, IOCType.DOMAIN]
    api_key_env = None  # La API de búsqueda es pública; la key sube el rate limit

    async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
        if ioc_type == IOCType.URL:
            query = f'page.url:"{ioc_value}"'
        else:
            query = f"domain:{ioc_value}"

        headers = {}
        optional_key = os.getenv("URLSCAN_API_KEY", "").strip()
        if optional_key:
            headers["API-Key"] = optional_key

        async with self._make_client() as client:
            resp = await client.get(
                _SEARCH_URL,
                params={"q": query, "size": 5},
                headers=headers,
            )
            resp.raise_for_status()
            return self._parse(resp.json())

    def _parse(self, body: dict) -> ConnectorResult:
        try:
            results = body.get("results", [])
            total = body.get("total", 0)

            if not results:
                return ConnectorResult(
                    source=self.name,
                    success=True,
                    verdict="clean",
                    summary="URLScan.io: sin escaneos previos.",
                    data={"found": False, "total_scans": 0, "malicious_count": 0,
                          "max_score": 0, "categories": []},
                )

            malicious_count = 0
            max_score = 0
            categories: set[str] = set()
            screenshot_url = None
            report_url = None

            for scan in results:
                overall = scan.get("verdicts", {}).get("overall", {})
                score = overall.get("score", 0)
                if overall.get("malicious", False):
                    malicious_count += 1
                max_score = max(max_score, score)
                for cat in overall.get("categories", []):
                    categories.add(cat)
                if screenshot_url is None:
                    screenshot_url = scan.get("task", {}).get("screenshotURL")
                    report_url = scan.get("task", {}).get("reportURL")

            if malicious_count > 0:
                verdict = "malicious"
                summary = (
                    f"URLScan.io: {malicious_count}/{len(results)} escaneos maliciosos"
                )
            elif max_score > 50:
                verdict = "suspicious"
                summary = f"URLScan.io: score máximo {max_score}/100 ({total} escaneos)"
            else:
                verdict = "clean"
                summary = f"URLScan.io: {total} escaneos, ninguno malicioso"

            if categories:
                summary += f". Categorías: {', '.join(sorted(categories))}"

            return ConnectorResult(
                source=self.name,
                success=True,
                verdict=verdict,
                summary=summary,
                data={
                    "found": True,
                    "total_scans": total,
                    "malicious_count": malicious_count,
                    "max_score": max_score,
                    "categories": sorted(categories),
                    "screenshot_url": screenshot_url,
                    "report_url": report_url,
                },
            )
        except (KeyError, TypeError, AttributeError) as exc:
            logger.warning("urlscan: error parseando respuesta — %s", exc)
            return ConnectorResult(
                source=self.name,
                success=False,
                verdict="unknown",
                summary="URLScan.io: respuesta inesperada de la API.",
                error="parse_error",
            )
