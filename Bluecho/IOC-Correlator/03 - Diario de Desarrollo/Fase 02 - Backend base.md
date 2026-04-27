# Fase 02 — Backend base y API REST

## Qué se ha construido

### Módulo 2 — FastAPI base
Servidor FastAPI funcional con endpoint `/api/health` verificado. Incluye:
- `backend/requirements.txt` con todas las dependencias fijadas por versión.
- `backend/main.py` con la app FastAPI, middleware CORS y patrón `lifespan`.
- `backend/ioc_correlator/api/routes.py` con el router y todos los endpoints.
- `backend/ioc_correlator/api/schemas.py` con todos los modelos Pydantic.
- Entorno virtual Python en `backend/.venv/` (no trackeado).

### Módulo 10 — Endpoint `/api/scan` completo
Orquestador central que conecta todos los módulos previos en un único flujo:

```
POST /api/scan o /api/scan/json
        │
        ▼
detect_ioc_type()    → 422 si UNKNOWN
        │
        ▼
enrich()             → VT + AbuseIPDB en paralelo (asyncio.gather + Semaphore)
        │
        ▼
compute_score()      → score 0-100 + breakdown por conector
        │
        ▼
save_scan()          → persiste en SQLite
        │
        ▼
ScanResponse         → JSON con score, veredicto, resultados y resumen IA
```

## Endpoints implementados

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/api/health` | Estado del servicio |
| POST | `/api/scan` | Escanea IOC (Form o fichero de logs) |
| POST | `/api/scan/json` | Escanea IOC (JSON body) |
| GET | `/api/history` | Lista los últimos 50 escaneos |
| GET | `/api/history/{id}` | Detalle completo de un escaneo |
| GET | `/api/sources` | Estado de los conectores activos |

## Decisiones técnicas tomadas

**Patrón `lifespan` en lugar de `@app.on_event`.** A partir de FastAPI 0.93, `on_event("startup")` está deprecado. El patrón con `asynccontextmanager` inicializa la BD en el arranque.

**Dos variantes del endpoint de escaneo.** `/api/scan` acepta `multipart/form-data` (compatible con subida de ficheros desde el navegador). `/api/scan/json` acepta JSON puro (útil para integración desde código o Swagger UI). Ambos comparten el mismo núcleo `_run_scan()`.

**Enrich con `asyncio.gather` + `Semaphore`.** Los conectores se ejecutan en paralelo. El semáforo respeta `MAX_CONCURRENT_REQUESTS` del entorno (default 5). Cuando haya 7 conectores activos, los más lentos esperan sin bloquear el event loop.

**Inyección de dependencia de sesión de BD en tests.** `app.dependency_overrides[get_session]` permite substituir la BD real por una en memoria en los tests de integración, sin tocar el código de producción.

## Comandos clave utilizados

```bash
# Arrancar el servidor en modo desarrollo
cd backend
.venv/Scripts/uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Probar el endpoint de escaneo (requiere API keys en .env)
curl -X POST http://localhost:8000/api/scan/json \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.45"}'

# Ver historial
curl http://localhost:8000/api/history

# Ver estado de conectores
curl http://localhost:8000/api/sources

# Tests de integración
.venv/Scripts/python -m pytest tests/test_scan_endpoint.py -v  # 15 passed
.venv/Scripts/python -m pytest tests/ -q  # 150 passed
```

## Ejemplo de respuesta de /api/scan/json

```json
{
  "id": 1,
  "ioc_value": "185.220.101.45",
  "ioc_type": "ipv4",
  "score": 70,
  "verdict": "malicious",
  "breakdown": {"virustotal": 30, "abuseipdb": 40},
  "connector_results": {
    "virustotal": {
      "source": "virustotal",
      "success": true,
      "verdict": "malicious",
      "summary": "VirusTotal: 23/87 motores lo detectan como malicioso.",
      "data": {"malicious": 23, "total": 87}
    },
    "abuseipdb": {
      "source": "abuseipdb",
      "success": true,
      "verdict": "malicious",
      "summary": "AbuseIPDB: score de confianza 95%, 142 reportes totales.",
      "data": {"confidence": 95, "total_reports": 142}
    }
  },
  "ai_summary": "",
  "created_at": "2026-04-27T18:00:00Z"
}
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| FastAPI no puede mezclar JSON body y Form en el mismo endpoint | Se crearon dos endpoints: `/api/scan` (Form+File) y `/api/scan/json` (JSON) que comparten el núcleo `_run_scan()` |

## Estado al terminar esta fase

- [x] `GET /api/health` → `{"status":"ok","version":"1.0.0"}`
- [x] `POST /api/scan/json` → escaneo completo con VT + AbuseIPDB + score + BD
- [x] `POST /api/scan` → Form data + subida de fichero de logs
- [x] `GET /api/history` y `GET /api/history/{id}` funcionando
- [x] `GET /api/sources` muestra estado de cada conector
- [x] 15 tests de integración pasando con BD en memoria
- [x] Suite acumulada: 150 tests pasando
