# Arquitectura Técnica

## Diagrama de arquitectura

```mermaid
flowchart TD
    Browser(["🌐 Navegador\n(Usuario)"])

    subgraph Docker["Docker Compose Network"]
        subgraph Frontend["Contenedor: frontend (nginx:1.27-alpine)"]
            Nginx["Nginx :80\n• Sirve React SPA (dist/)\n• Proxy /api/ → backend:8000"]
        end

        subgraph Backend["Contenedor: backend (python:3.11-slim)"]
            FastAPI["FastAPI\n(Uvicorn :8000)"]
            Cache["TTL Cache\n(en memoria, 1h)"]
            Enricher["Enricher\nasyncio.gather + Semaphore(5)"]
            Scorer["Scorer\n(reglas 0-100)"]
            AIAnalyst["AI Analyst\n(AsyncAnthropic)"]
            DB[("SQLite\n/app/data/ioc_correlator.db")]
        end

        Volume[("Volumen: db_data")]
    end

    subgraph TI["APIs Externas — Threat Intelligence"]
        VT["VirusTotal"]
        AIPDB["AbuseIPDB"]
        Shodan["Shodan"]
        OTX["AlienVault OTX"]
        MB["MalwareBazaar"]
        UH["URLhaus"]
        GN["GreyNoise"]
    end

    Anthropic["☁️ Anthropic Claude API\n(claude-sonnet-4-20250514)"]

    Browser -->|"HTTP :80"| Nginx
    Nginx -->|"GET/POST /api/*"| FastAPI

    FastAPI --> Cache
    Cache -->|"miss"| Enricher
    Enricher -->|"parallel"| VT
    Enricher -->|"parallel"| AIPDB
    Enricher -->|"parallel"| Shodan
    Enricher -->|"parallel"| OTX
    Enricher -->|"parallel"| MB
    Enricher -->|"parallel"| UH
    Enricher -->|"parallel"| GN
    Enricher -->|"hit → skip TI calls"| Cache

    Enricher --> Scorer
    Scorer --> AIAnalyst
    AIAnalyst -->|"opcional"| Anthropic
    Scorer --> FastAPI
    FastAPI --> DB
    DB --- Volume
```

## Flujo de una petición de escaneo

```mermaid
sequenceDiagram
    actor U as Usuario
    participant N as Nginx
    participant F as FastAPI
    participant C as TTL Cache
    participant E as Enricher
    participant TI as APIs TI (×7)
    participant AI as Claude API
    participant DB as SQLite

    U->>N: POST /api/scan { ioc }
    N->>F: proxy → /api/scan
    F->>F: validate_ioc_type()
    F->>C: get(cache_key)
    alt Cache HIT
        C-->>F: ConnectorResult map (cached)
    else Cache MISS
        F->>E: enrich(ioc, type)
        E->>TI: asyncio.gather (paralelo)
        TI-->>E: ConnectorResult × 7
        E->>C: set(cache_key, results, TTL=1h)
        E-->>F: ConnectorResult map
    end
    F->>F: score = compute_score(results)
    F->>AI: generate_summary(results, score)
    AI-->>F: análisis en español (o fallback)
    F->>DB: INSERT ScanResult
    F-->>N: JSON { score, verdict, sources, ai_summary }
    N-->>U: respuesta
```

## Estructura del repositorio

```
blue-echo/
├── .gitignore
├── .env.example
├── README.md
├── docker-compose.yml
├── deploy.sh
│
├── backend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── requirements.txt
│   ├── pytest.ini
│   ├── main.py                         # App FastAPI + lifespan
│   ├── tests/
│   │   ├── test_validators.py
│   │   ├── test_extractor.py
│   │   ├── test_database.py
│   │   ├── test_base_connector.py
│   │   ├── test_shodan.py
│   │   ├── test_otx.py
│   │   ├── test_malwarebazaar.py
│   │   ├── test_urlhaus.py
│   │   ├── test_greynoise.py
│   │   ├── test_cache.py
│   │   └── test_enricher_cache.py
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
│       ├── enricher.py               # Orquestador async + caché
│       ├── scorer.py                  # Lógica de scoring
│       ├── ai_analyst.py             # Integración Claude (AsyncAnthropic)
│       └── database.py               # SQLModel + SQLite
│
└── frontend/
    ├── Dockerfile
    ├── .dockerignore
    ├── nginx.conf
    ├── package.json
    ├── vite.config.ts
    └── src/
        ├── vite-env.d.ts
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

## Decisiones de diseño relevantes

| Decisión | Motivo |
|---|---|
| Nginx sirve tanto el SPA como el proxy | Un solo puerto expuesto (80). No hay CORS porque el browser ve siempre el mismo origen. |
| Backend `expose` en lugar de `ports` | El puerto 8000 solo es accesible desde la red Docker, no desde internet. |
| TTL Cache en memoria (no Redis) | Simplicidad para práctica universitaria. Para producción real se cambiaría a Redis. |
| `AsyncAnthropic` en lugar de `Anthropic` | FastAPI es async; un cliente síncroco bloquearía el event loop. |
| `depends_on: condition: service_healthy` | El frontend no arranca hasta que el backend responde `/api/health`. |
| Multi-stage Dockerfile (builder + runtime) | La imagen final no incluye compiladores ni pip — más ligera y menos superficie de ataque. |
