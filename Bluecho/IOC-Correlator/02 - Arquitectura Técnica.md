# Arquitectura Técnica

## Diagrama de arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                        INTERNET                             │
└──────────────────────────┬──────────────────────────────────┘
                           │ :80 / :443
              ┌────────────▼────────────┐
              │        NGINX            │
              │  (reverse proxy + SPA)  │
              └──────┬──────────────────┘
                     │
        ┌────────────┼────────────────────┐
        │            │                    │
        ▼            ▼                    │
┌───────────┐  ┌───────────┐             │
│  React    │  │  FastAPI  │             │
│  (build   │  │  Backend  │             │
│  estático)│  │  :8000    │             │
└───────────┘  └─────┬─────┘             │
                     │                   │
        ┌────────────┼──────────┐        │
        │            │          │        │
        ▼            ▼          ▼        │
┌──────────┐  ┌──────────┐  ┌──────┐    │
│ SQLite   │  │Enricher  │  │ AI   │    │
│ (BD)     │  │(asyncio) │  │Analyst   │
└──────────┘  └────┬─────┘  └──┬───┘    │
                   │           │        │
                   ▼           ▼        │
         ┌─────────────────┐  ┌──────┐  │
         │  Conectores TI  │  │Claude│  │
         │ VT·AIPDB·Shodan │  │ API  │  │
         │ OTX·MB·URLhaus  │  └──────┘  │
         │ GreyNoise       │            │
         └─────────────────┘            │
```

## Flujo de una petición de escaneo

```
Usuario introduce IOC
       │
       ▼
[1] POST /api/scan
       │
       ▼
[2] Validators: detectar tipo IOC
       │
       ▼
[3] Enricher: lanzar conectores en paralelo (asyncio.gather)
       │
       ├──► VirusTotal
       ├──► AbuseIPDB
       ├──► Shodan
       ├──► OTX
       ├──► MalwareBazaar
       ├──► URLhaus
       └──► GreyNoise
       │
       ▼
[4] Scorer: calcular score 0-100
       │
       ▼
[5] AI Analyst: llamar a Claude API → resumen en español
       │
       ▼
[6] Database: guardar ScanResult
       │
       ▼
[7] Response: JSON con score + resultados + resumen IA
```

## Estructura del repositorio

```
ioc-correlator/
├── .gitignore
├── .env.example
├── README.md
├── docker-compose.yml
├── deploy.sh
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── main.py                         # App FastAPI + lifespan
│   ├── tests/
│   │   ├── test_validators.py
│   │   ├── test_extractor.py
│   │   ├── test_database.py
│   │   └── test_base_connector.py
│   └── ioc_correlator/
│       ├── api/
│       │   ├── routes.py               # Endpoints REST
│       │   └── schemas.py              # Pydantic models
│       ├── connectors/
│       │   ├── base.py                 # BaseConnector + ConnectorResult
│       │   ├── virustotal.py
│       │   ├── abuseipdb.py
│       │   ├── shodan.py
│       │   ├── otx.py
│       │   ├── malwarebazaar.py
│       │   ├── urlhaus.py
│       │   └── greynoise.py
│       ├── utils/
│       │   ├── validators.py           # Detección tipo IOC
│       │   └── cache.py               # Caché TTL en memoria
│       ├── extractor.py               # Parser de logs
│       ├── enricher.py               # Orquestador async
│       ├── scorer.py                  # Lógica de scoring
│       ├── ai_analyst.py             # Integración Claude
│       └── database.py               # SQLModel + SQLite
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    ├── vite.config.ts
    └── src/
        ├── api/client.ts
        ├── components/
        │   ├── SearchBar.tsx
        │   ├── ThreatScore.tsx
        │   ├── ResultsTable.tsx
        │   ├── AiSummary.tsx
        │   ├── HistoryList.tsx
        │   └── FileUpload.tsx
        └── pages/
            ├── Dashboard.tsx
            └── History.tsx
```

## API REST

| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/scan` | Escanea un IOC o fichero de logs |
| GET | `/api/history` | Lista los últimos 50 escaneos |
| GET | `/api/history/{id}` | Detalle completo de un escaneo |
| GET | `/api/health` | Estado del servicio |
| GET | `/api/sources` | Estado de los conectores activos |

## Reglas de Scoring

| Condición | Puntos |
|---|---|
| VT: >5 motores detectan | +30 |
| VT: 1-5 motores detectan | +15 |
| AbuseIPDB confidence >80% | +40 |
| AbuseIPDB confidence 50-80% | +25 |
| Shodan: puerto sensible abierto (22/3389/445/1433/4444) | +10 c/u, máx +30 |
| OTX: presente en pulsos activos | +20 |
| MalwareBazaar: hash conocido | +40 |
| GreyNoise: clasificado malicious | +30 |
| GreyNoise: clasificado benign | -10 |

Score máximo: 100. Veredicto: LIMPIO (0-20) · SOSPECHOSO (21-50) · MALICIOSO (51-80) · CRÍTICO (81-100).
