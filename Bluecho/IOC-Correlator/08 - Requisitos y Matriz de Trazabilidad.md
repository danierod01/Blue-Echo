# 08 — Requisitos y Matriz de Trazabilidad

> Alimenta los apartados **4 (Requisitos)** y **9 (Matriz de trazabilidad)** de la memoria de la Práctica 3.
>
> Los requisitos de la Práctica 1 no estaban numerados en el `Informe-BlueEcho.md`. El enunciado de la P3 exige numerarlos ahora (`RF-01…`, `RNF-01…`) y clasificarlos. Esta lista se ha **derivado del informe P1** (resumen ejecutivo, descripción del problema/solución, arquitectura y manual de uso), que es la línea base que el profesor evaluó.
>
> Leyenda de estado: **Cumplido** · **Parcial** · **Pendiente** · **A revisar** (reformulado con justificación) · **Descartado**.
> Columna "Evidencia (vídeo)": pendiente de rellenar con el minuto exacto al grabar el vídeo de demostración.

---

## 1. Requisitos funcionales (P1)

| ID | Requisito | Estado final |
|---|---|---|
| RF-01 | Detección automática del tipo de IOC (IPv4, IPv6, MD5, SHA1, SHA256, dominio, URL) sin que el usuario lo especifique | Cumplido |
| RF-02 | Consulta **en paralelo** a las fuentes de TI relevantes según el tipo de IOC | Cumplido |
| RF-03 | Integración de las 7 fuentes de la P1: VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, MalwareBazaar, URLhaus y GreyNoise | Cumplido (GreyNoise implementado en P3, ver nota) |
| RF-04 | Cálculo de un **score de amenaza 0-100** con reglas documentadas y transparentes | Cumplido |
| RF-05 | Clasificación en 4 veredictos por rango (LIMPIO 0-20 / SOSPECHOSO 21-50 / MALICIOSO 51-80 / CRÍTICO 81-100) | Cumplido |
| RF-06 | Análisis ejecutivo en lenguaje natural (español) generado con IA, con **fallback** si la IA falla | Cumplido (A revisar: motor, ver RF-06) |
| RF-07 | Extracción de IOCs desde ficheros de logs (`.log`, `.txt`, `.csv`, `.json`; Apache/Nginx, syslog, CSV Windows, JSON lines) | Cumplido |
| RF-08 | Persistencia del historial de escaneos en base de datos | Cumplido |
| RF-09 | Consulta del historial y del **detalle completo** de un escaneo anterior | Cumplido |
| RF-10 | Dashboard web con: barra de búsqueda, tarjeta de score, tabla de resultados por fuente, bloque de análisis IA, historial y estado de fuentes | Cumplido |
| RF-11 | Caché para evitar consultas duplicadas de un mismo IOC | Cumplido |
| RF-12 | Endpoints de estado: `/api/health` y `/api/sources` (qué conectores están activos) | Cumplido |

### Requisitos modificados / a revisar

- **RF-06 (A revisar — motor de IA).** Versión P1: *"análisis generado con la API de Claude (Anthropic)"*. Versión P3: el motor primario es **Groq (Llama 3.3 70B, tier gratuito)**, con **Claude (Anthropic) como fallback** y un **análisis local determinista** como último recurso. Justificación: coste cero en el tier gratuito de Groq y latencia menor, manteniendo la calidad con Claude cuando hay `ANTHROPIC_API_KEY`. El comportamiento (resumen ejecutivo en español + fallback que nunca rompe la respuesta) se conserva. Cerraba el estudio F7 del roadmap.

---

## 2. Requisitos no funcionales (P1)

| ID | Requisito | Estado final |
|---|---|---|
| RNF-01 | Arquitectura **asíncrona** respetando rate limits (semáforo que limita a 5 consultas simultáneas) | Cumplido |
| RNF-02 | Manejo robusto de errores HTTP en fuentes externas (timeout, 429, 403, respuestas vacías) sin propagar excepciones ni romper la respuesta | Cumplido |
| RNF-03 | Despliegue **reproducible con Docker Compose** desde cero en un VPS limpio | Cumplido (verificación `docker compose` pendiente esta sesión) |
| RNF-04 | Accesible desde internet vía Nginx como reverse proxy; único punto de entrada el puerto 80; backend con `expose`, no `ports` | Cumplido |
| RNF-05 | Secretos por variables de entorno, **nunca hardcodeados**; backend arranca como usuario no root | Cumplido |
| RNF-06 | Tests automatizados con `pytest` y mocks de las APIs externas | Cumplido |
| RNF-07 | Respuesta del escaneo en pocos segundos (objetivo < 10 s) | Parcial (medir y documentar) |

---

## 3. Mejoras sobre la P1 (roadmap del Informe §8, presentadas por primera vez en P3)

Estas no son requisitos originales de la P1 sino el roadmap prometido; se incluyen en la matriz porque el enunciado valora las mejoras siempre que lo original esté cumplido. Detalle y estado completo en `CLAUDE.md` → "Estado del roadmap prometido".

| ID | Mejora | Estado |
|---|---|---|
| MJ-S1..S4 | Auth X-API-Key, rate limiting (slowapi), HTTPS Let's Encrypt, validación tamaño de fichero | Cumplido |
| MJ-F1 | Bulk scan (múltiples IOCs) | Cumplido |
| MJ-F2 | Ampliación a 18 conectores (ThreatFox, URLScan, IPInfo, RDAP, SecurityTrails, Hybrid Analysis, Netlas, Criminal IP, MalShare, Pulsedive, Censys) | Cumplido |
| MJ-F3 | WHOIS/RDAP para dominios | Cumplido |
| MJ-F4 | Exportación a PDF del informe de escaneo | Cumplido (P3) |
| MJ-F5 | Alertas por webhook (Slack/Discord/Teams/genérico) | Cumplido (P3) |
| MJ-F6 | Mapping MITRE ATT&CK | Cumplido |
| MJ-F7 | Estudio y decisión de motor de IA (→ Groq + Claude fallback) | Cumplido (ver RF-06) |
| MJ-R1 | Paginación real en el historial | Cumplido |
| MJ-I1 | API pública documentada (OpenAPI `/docs`) + auth | Cumplido |
| MJ-R2/R3/I2/I3 | PostgreSQL, Celery+Redis, export SIEM, plugin navegador | Backlog (trabajo futuro justificado) |

**Extras fuera del roadmap:** análisis PCAP (scapy), geolocalización con mapa, login con X-API-Key, rediseño completo de la UI.

---

## 4. Matriz de trazabilidad

`Requisito | Implementación (ruta) | Prueba (fichero de test) | Evidencia`

| Req | Implementación | Prueba | Evidencia (memoria / vídeo) |
|---|---|---|---|
| RF-01 | `backend/ioc_correlator/utils/validators.py` (`detect_ioc_type`) | `tests/test_validators.py` | mem. §6 · vídeo `pend.` |
| RF-02 | `backend/ioc_correlator/enricher.py` (`enrich`, `asyncio.gather` + semáforo) | `tests/test_enricher_cache.py` | mem. §5 · vídeo `pend.` |
| RF-03 | `backend/ioc_correlator/connectors/` (virustotal, abuseipdb, shodan, otx, malwarebazaar, urlhaus, greynoise) | `tests/test_virustotal.py`, `test_abuseipdb.py`, `test_shodan.py`, `test_otx.py`, `test_malwarebazaar.py`, `test_urlhaus.py`, `test_greynoise.py` | mem. §6 · vídeo `pend.` |
| RF-04 | `backend/ioc_correlator/scorer.py` (`compute_score`) | `tests/test_scorer.py` | mem. §6 · vídeo `pend.` |
| RF-05 | `backend/ioc_correlator/scorer.py` (`_verdict`) | `tests/test_scorer.py` | mem. §6 · vídeo `pend.` |
| RF-06 | `backend/ioc_correlator/ai_analyst.py` (Groq → Anthropic → local) | `tests/test_ai_analyst.py` | mem. §6 · vídeo `pend.` |
| RF-07 | `backend/ioc_correlator/extractor.py` | `tests/test_extractor.py` | mem. §6 · vídeo `pend.` |
| RF-08 | `backend/ioc_correlator/database.py` (`save_scan`, modelo `ScanResult`) | `tests/test_database.py` | mem. §6 · vídeo `pend.` |
| RF-09 | `routes.py` `GET /api/history`, `GET /api/history/{id}` | `tests/test_scan_endpoint.py` | mem. §6 · vídeo `pend.` |
| RF-10 | `frontend/src/pages/Dashboard.tsx` + componentes (`SearchBar`, `ThreatScore`, `ResultsTable`, `AiSummary`, `HistoryList`, `SourcesStatus`) | (manual / e2e) | mem. §6 · vídeo `pend.` |
| RF-11 | `backend/ioc_correlator/utils/cache.py` + `enricher.py` | `tests/test_cache.py`, `test_enricher_cache.py` | mem. §6 · vídeo `pend.` |
| RF-12 | `routes.py` `GET /api/health`, `GET /api/sources` | `tests/test_scan_endpoint.py` | mem. §6 · vídeo `pend.` |
| RNF-01 | `enricher.py` (semáforo `MAX_CONCURRENT_REQUESTS`) | `tests/test_enricher_cache.py` | mem. §5 · vídeo `pend.` |
| RNF-02 | `connectors/base.py` (`query` + `_handle_http_error`) | `tests/test_base_connector.py` + tests por conector | mem. §5 · vídeo `pend.` |
| RNF-03 | `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `deploy.sh` | (verificación manual `docker compose up`) | mem. §7 · vídeo `pend.` |
| RNF-04 | `frontend/nginx.conf`, `docker-compose.yml` (`expose` backend) | (manual) | mem. §5 · vídeo `pend.` |
| RNF-05 | `connectors/base.py` (`api_key` desde env), `backend/Dockerfile` (`appuser`), `.gitignore` | (revisión) | mem. §7 · vídeo `pend.` |
| RNF-06 | `backend/tests/` (17 ficheros, 262 tests) | `pytest` | mem. §8 · vídeo `pend.` |
| RNF-07 | Async + caché; medir latencia real | (benchmark manual) | mem. §8 · vídeo `pend.` |

**Mejoras (extracto):**

| Req | Implementación | Prueba | Evidencia |
|---|---|---|---|
| MJ-F4 (PDF) | `backend/ioc_correlator/report_pdf.py`, `routes.py` `GET /api/history/{id}/pdf`, `frontend/src/api/client.ts` (`downloadScanPdf`) | `tests/test_scan_endpoint.py::test_history_detail_pdf` | mem. §6 · vídeo `pend.` |
| MJ-F5 (webhook) | `backend/ioc_correlator/alerting.py`, enganchado en `routes.py::_run_scan` | `tests/test_alerting.py` | mem. §6 · vídeo `pend.` |
| MJ-F6 (MITRE) | `backend/ioc_correlator/mitre_mapper.py`, `frontend/.../MitreAttack.tsx` | (tests scorer/enricher) | mem. §6 · vídeo `pend.` |
| MJ-S1/S2 (auth+rate) | `backend/ioc_correlator/api/auth.py`, `limiter.py` | `tests/test_scan_endpoint.py` | mem. §7 · vídeo `pend.` |

---

## 5. Pendientes de esta matriz

- Rellenar la columna **Evidencia (vídeo)** con el minuto exacto al grabar el vídeo.
- Medir y documentar la **latencia real** de un escaneo (RNF-07).
- Verificar **`docker compose up --build`** en limpio y anotar el resultado (RNF-03).
- Añadir capturas de pantalla a la memoria por cada RF con interfaz (RF-10, RF-09).
