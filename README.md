# Blue-Echo

Plataforma web de correlación de Indicadores de Compromiso (IOCs) contra múltiples fuentes de Threat Intelligence, con análisis en lenguaje natural generado por IA.

Dado un IOC (IP, hash, dominio, URL) o un fichero de logs, la plataforma lo consulta en paralelo contra 7 fuentes de Threat Intelligence, calcula un score de amenaza (0-100) y genera un resumen ejecutivo en español.

---

## Índice

- [Qué hace](#qué-hace)
- [Fuentes de Threat Intelligence](#fuentes-de-threat-intelligence)
- [Requisitos previos](#requisitos-previos)
- [Instalación y arranque](#instalación-y-arranque)
  - [Opción A — Con Docker](#opción-a--con-docker-recomendada)
  - [Opción B — Sin Docker](#opción-b--sin-docker-desarrollo-local)
- [Configuración de API Keys](#configuración-de-api-keys)
- [Uso de la herramienta](#uso-de-la-herramienta)
- [API REST](#api-rest)
- [Despliegue en producción (Hetzner)](#despliegue-en-producción-hetzner)
  - [Opción C — VPS Hetzner con deploy.sh](#opción-c--vps-hetzner-con-deploysh)
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

### Opción A — Con Docker (recomendada)

#### 1. Clonar el repositorio

```bash
git clone https://github.com/danierod01/blue-echo.git
cd blue-echo
```

#### 2. Crear el fichero de variables de entorno

```bash
cp .env.example .env
```

Edita `.env` con tu editor y añade las API keys que tengas. Las fuentes sin clave se marcan como inactivas pero no impiden el arranque.

#### 3. Arrancar con Docker Compose

```bash
docker compose up -d --build
```

Este comando:
- Construye las imágenes del backend (Python + FastAPI) y del frontend (React + Nginx)
- Arranca los dos contenedores en segundo plano
- Crea el volumen `db_data` donde se almacena la base de datos de forma persistente

El primer arranque tarda 2-4 minutos mientras se descargan las imágenes base y se instalan las dependencias.

#### 4. Verificar que todo funciona

```bash
curl http://localhost/api/health
# Respuesta esperada: {"status":"ok","version":"1.0.0"}
```

#### 5. Abrir el panel web

Abre el navegador en **http://localhost**

#### Comandos útiles de Docker

```bash
# Ver logs en tiempo real
docker compose logs -f

# Ver logs solo del backend
docker compose logs -f backend

# Reconstruir tras cambios de código
docker compose up -d --build backend

# Recargar backend tras cambiar .env
docker compose restart backend

# Parar sin borrar datos
docker compose down

# Parar Y borrar la base de datos
docker compose down -v
```

---

### Opción B — Sin Docker (desarrollo local)

Más cómoda si quieres ver cambios en el código al instante sin reconstruir imágenes.

#### 1. Clonar el repositorio

```bash
git clone https://github.com/danierod01/blue-echo.git
cd blue-echo
```

#### 2. Crear el fichero de variables de entorno

```bash
cp .env.example .env
```

Edita `.env` y añade las API keys que tengas.

#### 3. Arrancar el backend

```bash
cd backend

# Crear entorno virtual
python -m venv .venv

# Activar el entorno virtual
source .venv/bin/activate        # Linux / Mac
.venv\Scripts\activate           # Windows (PowerShell)

# Instalar dependencias
pip install -r requirements.txt

# Arrancar el servidor en modo desarrollo (recarga automática)
uvicorn main:app --reload --port 8000
```

El backend quedará disponible en:
- API: **http://localhost:8000**
- Swagger UI: **http://localhost:8000/api/docs**

#### 4. Arrancar el frontend (en otra terminal)

```bash
cd frontend

# Instalar dependencias (solo la primera vez)
npm install

# Arrancar en modo desarrollo
npm run dev
```

El frontend quedará disponible en **http://localhost:5173**

> El `vite.config.ts` ya tiene un proxy configurado que redirige `/api/*` a `localhost:8000`, así que el frontend de desarrollo se conecta al backend local automáticamente sin problemas de CORS.

#### 5. Verificar que todo funciona

```bash
curl http://localhost:8000/api/health
# Respuesta esperada: {"status":"ok","version":"1.0.0"}
```

#### Ejecutar los tests

```bash
cd backend

# Suite completa
python -m pytest -v

# Un conector específico
python -m pytest tests/test_virustotal.py -v

# Con cobertura
python -m pytest --tb=short
```

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

## Despliegue en producción (Hetzner)

### Opción C — VPS Hetzner con deploy.sh

Pasos para desplegar en un servidor Ubuntu 24.04 limpio accesible desde internet.

#### 1. Crear el VPS en Hetzner Cloud

1. Entra en [console.hetzner.cloud](https://console.hetzner.cloud)
2. Crea un nuevo servidor con estas opciones:
   - **Imagen:** Ubuntu 24.04
   - **Tipo:** CX22 (2 vCPU / 4 GB RAM) — suficiente para el proyecto
   - **Red:** añade tu clave SSH pública para acceso sin contraseña
3. Anota la **IP pública** del servidor cuando se cree

#### 2. Conectarse por SSH

```bash
ssh root@<IP-DEL-SERVIDOR>
```

#### 3. Descargar y ejecutar el script de despliegue

```bash
# Descargar el script directamente desde el repositorio
curl -fsSL https://raw.githubusercontent.com/danierod01/blue-echo/main/deploy.sh -o deploy.sh
chmod +x deploy.sh

# Ejecutar (instala Docker, clona el repo y arranca los contenedores)
./deploy.sh
```

El script se detiene automáticamente si el `.env` no existe y te pide que lo edites:

#### 4. Configurar las API keys en el servidor

```bash
nano /opt/blue-echo/.env
```

Rellena las claves igual que en local. Guarda con `Ctrl+O`, sal con `Ctrl+X`.

#### 5. Arrancar la aplicación

```bash
cd /opt/blue-echo
docker compose up -d --build
```

#### 6. Verificar que funciona

```bash
curl http://localhost/api/health
# {"status":"ok","version":"1.0.0"}
```

Abre el navegador en **http://\<IP-DEL-SERVIDOR\>**

#### Comandos útiles en el servidor

```bash
# Ver logs en tiempo real
docker compose -C /opt/blue-echo logs -f

# Actualizar a la última versión del repositorio
git -C /opt/blue-echo pull
docker compose -C /opt/blue-echo up -d --build

# Parar la aplicación
docker compose -C /opt/blue-echo down
```

#### Añadir HTTPS con dominio propio (opcional, suma puntos)

Si tienes un dominio, apunta el DNS (registro A) a la IP del servidor y ejecuta:

```bash
apt-get install -y certbot python3-certbot-nginx
certbot --nginx -d tudominio.com
```

Certbot configura Nginx automáticamente y renueva el certificado cada 90 días.

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
