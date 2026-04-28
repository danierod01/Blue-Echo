# Blue-Echo

Plataforma web de correlación de Indicadores de Compromiso (IOCs) contra múltiples fuentes de Threat Intelligence, con análisis en lenguaje natural generado por IA.

Dado un IOC (IP, hash, dominio, URL) o un fichero de logs, la plataforma lo consulta en paralelo contra 7 fuentes de Threat Intelligence, calcula un score de amenaza (0-100) y genera un resumen ejecutivo en español.

---

## Índice

- [Qué hace](#qué-hace)
- [Fuentes de Threat Intelligence](#fuentes-de-threat-intelligence)
- [Requisitos previos](#requisitos-previos)
- [Instalación y arranque](#instalación-y-arranque)
- [Configuración de API Keys](#configuración-de-api-keys)
- [Uso de la herramienta](#uso-de-la-herramienta)
- [API REST](#api-rest)
- [Desarrollo local sin Docker](#desarrollo-local-sin-docker)
- [Despliegue en producción (Hetzner)](#despliegue-en-producción-hetzner)
- [Estructura del repositorio](#estructura-del-repositorio)

---

## Qué hace

1. Introduces un IOC (IP, hash MD5/SHA1/SHA256, dominio o URL) o subes un fichero de logs.
2. La plataforma extrae todos los IOCs únicos del input.
3. Los consulta en paralelo contra las 7 fuentes configuradas.
4. Calcula un **score de amenaza 0-100** según reglas fijas por fuente.
5. Genera un **resumen ejecutivo en español** con la API de Claude (o análisis local si no hay clave configurada).
6. Muestra todo en un dashboard con código de colores:
   - 🔴 **CRÍTICO** (81-100)
   - 🟠 **MALICIOSO** (51-80)
   - 🟡 **SOSPECHOSO** (21-50)
   - 🟢 **LIMPIO** (0-20)
7. Almacena el historial de escaneos en base de datos.

---

## Fuentes de Threat Intelligence

| Fuente | Tipos de IOC | API Key necesaria |
|---|---|---|
| VirusTotal | IP, Hash, Dominio, URL | Sí — `VT_API_KEY` |
| AbuseIPDB | IP | Sí — `ABUSEIPDB_API_KEY` |
| Shodan | IP | Sí — `SHODAN_API_KEY` |
| AlienVault OTX | IP, Hash, Dominio | Sí — `OTX_API_KEY` |
| MalwareBazaar | Hash | No (API pública) |
| URLhaus | URL, Dominio | No (API pública) |
| GreyNoise | IP | Sí — `GREYNOISE_API_KEY` |

Los conectores sin API key configurada se marcan como inactivos en el panel pero no impiden el arranque.

---

## Requisitos previos

### Con Docker (recomendado)

- [Docker Engine](https://docs.docker.com/engine/install/) 24.x o superior
- [Docker Compose](https://docs.docker.com/compose/) v2 (incluido en Docker Desktop y en instalaciones modernas)

Verificar:
```bash
docker --version        # Docker version 24.x.x
docker compose version  # Docker Compose version v2.x.x
```

### Sin Docker (desarrollo)

- Python 3.11 o superior
- Node.js 22.x LTS
- pip y npm

---

## Instalación y arranque

### 1. Clonar el repositorio

```bash
git clone https://github.com/danierod01/blue-echo.git
cd blue-echo
```

### 2. Crear el fichero de variables de entorno

```bash
cp .env.example .env
```

Edita `.env` con tu editor favorito y añade las API keys que tengas. Las fuentes sin clave simplemente no se consultarán.

### 3. Arrancar con Docker Compose

```bash
docker compose up -d --build
```

Este comando:
- Construye las imágenes del backend (Python + FastAPI) y del frontend (React + Nginx)
- Arranca los dos contenedores en segundo plano
- Crea el volumen `db_data` donde se almacena la base de datos

El primer arranque tarda 2-4 minutos mientras se descargan las imágenes base y se instalan las dependencias.

### 4. Verificar que todo funciona

```bash
curl http://localhost/api/health
# Respuesta esperada: {"status":"ok","version":"1.0.0"}
```

### 5. Abrir el panel web

Abre el navegador en **http://localhost**

---

## Configuración de API Keys

Edita el fichero `.env` que creaste en el paso anterior:

```dotenv
# ---- Threat Intelligence ----
VT_API_KEY=tu_clave_de_virustotal
ABUSEIPDB_API_KEY=tu_clave_de_abuseipdb
SHODAN_API_KEY=tu_clave_de_shodan
OTX_API_KEY=tu_clave_de_otx
GREYNOISE_API_KEY=tu_clave_de_greynoise

# ---- IA Generativa (opcional, pero recomendado) ----
# Sin esta clave, el análisis se genera localmente con los datos crudos.
ANTHROPIC_API_KEY=tu_clave_de_anthropic

# ---- Backend (valores por defecto válidos para desarrollo) ----
DATABASE_URL=sqlite:///./ioc_correlator.db
REQUEST_TIMEOUT=10
MAX_CONCURRENT_REQUESTS=5
CACHE_TTL_SECONDS=3600
```

Dónde conseguir las claves gratuitas:

| Servicio | URL de registro | Plan gratuito |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | 4 req/min, 500 req/día |
| AbuseIPDB | https://www.abuseipdb.com/register | 1.000 req/día |
| Shodan | https://account.shodan.io/register | 1 req/seg (cuenta gratuita) |
| AlienVault OTX | https://otx.alienvault.com/ | Sin límite publicado |
| GreyNoise | https://www.greynoise.io/plans/community | 1.000 req/día |
| Anthropic | https://console.anthropic.com/ | Créditos de prueba |

Tras modificar `.env`, recarga el backend:
```bash
docker compose restart backend
```

---

## Uso de la herramienta

### Escanear un IOC manualmente

1. Abre el panel en **http://localhost**
2. Escribe el IOC en la barra de búsqueda central:
   - IP: `185.220.101.45`
   - Dominio: `malware.example.com`
   - Hash MD5: `d41d8cd98f00b204e9800998ecf8427e`
   - Hash SHA256: `e3b0c44298fc1c149afbf4c8996fb924...`
   - URL: `https://evil.example.com/payload.exe`
3. Pulsa **Escanear** o la tecla Enter.
4. En unos segundos verás:
   - El **score de amenaza** (gauge circular 0-100 con color)
   - La **tabla de resultados** por fuente (veredicto, dato clave, puntos aportados al score)
   - El **análisis en lenguaje natural** generado por IA
5. El escaneo queda guardado automáticamente en el historial.

### Escanear desde un fichero de logs

1. Pulsa el botón **Subir fichero** (o arrastra el fichero sobre la zona de búsqueda).
2. Selecciona tu fichero de logs (cualquier formato: Apache, Nginx, syslog, CSV de Windows Event Log, JSON lines o texto libre).
3. La herramienta extrae automáticamente todos los IOCs únicos y los escanea.

### Ver el historial

- Haz clic en **Historial** en la barra de navegación superior.
- Verás la lista de todos los escaneos con IOC, score, veredicto y fecha.
- Haz clic en cualquier fila para recargar el resultado completo en el panel.

### Estado de los conectores

- Las pills de colores bajo la barra de búsqueda muestran qué conectores están activos (verde) y cuáles no tienen API key configurada (gris).

---

## API REST

La API está disponible en `http://localhost/api/`. Documentación interactiva (Swagger UI) en **http://localhost/api/docs**.

### POST /api/scan/json — Escanear un IOC por JSON

```bash
curl -X POST http://localhost/api/scan/json \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.45"}'
```

Respuesta:
```json
{
  "ioc": "185.220.101.45",
  "ioc_type": "ipv4",
  "score": 87,
  "verdict": "critical",
  "results": {
    "virustotal": { "verdict": "malicious", "summary": "VT: 23 motores detectaron amenaza." },
    "abuseipdb":  { "verdict": "malicious", "summary": "AbuseIPDB: confianza 95%, 142 reportes." }
  },
  "ai_summary": "La IP 185.220.101.45 ha sido clasificada como CRÍTICA con un score de 87/100...",
  "scan_id": 42,
  "created_at": "2026-04-28T14:30:00"
}
```

### POST /api/scan — Escanear un IOC o fichero (multipart)

```bash
# IOC por texto
curl -X POST http://localhost/api/scan \
  -F "ioc=185.220.101.45"

# Fichero de logs
curl -X POST http://localhost/api/scan \
  -F "file=@/ruta/a/mis.log"
```

### GET /api/history — Historial de escaneos

```bash
curl http://localhost/api/history
```

### GET /api/history/{id} — Detalle de un escaneo

```bash
curl http://localhost/api/history/42
```

### GET /api/sources — Estado de los conectores

```bash
curl http://localhost/api/sources
```

### GET /api/health — Health check

```bash
curl http://localhost/api/health
# {"status":"ok","version":"1.0.0"}
```

---

## Desarrollo local sin Docker

Si prefieres arrancar el backend y frontend por separado (más cómodo para desarrollo activo):

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Linux/Mac
# .venv\Scripts\activate           # Windows

pip install -r requirements.txt

# Arrancar el servidor
uvicorn main:app --reload --port 8000
# → http://localhost:8000
# → http://localhost:8000/api/docs  (Swagger UI)
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

El `vite.config.ts` ya tiene configurado un proxy que redirige `/api/*` a `localhost:8000`, así que el frontend de desarrollo se conecta al backend local automáticamente.

### Tests del backend

```bash
cd backend
python -m pytest -v
# Suite completa

python -m pytest tests/test_virustotal.py -v
# Un fichero específico
```

---

## Despliegue en producción (Hetzner)

Ver [deploy.sh](deploy.sh) para el script de despliegue automatizado sobre un VPS Hetzner Ubuntu 24.04 limpio.

Resumen del proceso:
1. Crear VPS Ubuntu 24.04 en Hetzner Cloud (CX22, 2 vCPU / 4 GB RAM es suficiente)
2. Conectarse por SSH y ejecutar `deploy.sh`
3. Editar `/opt/blue-echo/.env` con las API keys reales
4. Acceder desde el navegador a la IP pública del VPS

---

## Estructura del repositorio

```
blue-echo/
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   └── ioc_correlator/
│       ├── api/            # Endpoints REST y schemas Pydantic
│       ├── connectors/     # VirusTotal, AbuseIPDB, Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise
│       ├── utils/          # Validadores de IOC, caché TTL
│       ├── enricher.py     # Orquestador de conectores (asyncio + semáforo)
│       ├── scorer.py       # Lógica de scoring 0-100
│       ├── ai_analyst.py   # Integración Claude API con fallback local
│       ├── extractor.py    # Extracción de IOCs desde logs
│       └── database.py     # SQLite con SQLModel
├── frontend/
│   ├── Dockerfile
│   ├── nginx.conf
│   └── src/
│       ├── components/     # SearchBar, ThreatScore, ResultsTable, AiSummary, HistoryList, SourcesStatus
│       └── pages/          # Dashboard, History
├── docker-compose.yml
├── deploy.sh
├── .env.example
└── .gitignore
```

---

## Stack técnico

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 + FastAPI + httpx (async) + SQLModel + SQLite |
| IA | Anthropic Claude API (`claude-sonnet-4-20250514`) + fallback local |
| Frontend | React 18 + Vite + TypeScript + Tailwind CSS + TanStack Query |
| Infra | Docker Compose + Nginx + Hetzner Cloud VPS Ubuntu 24.04 |

---

Proyecto académico — Máster en Ciberseguridad 2025-2026.
