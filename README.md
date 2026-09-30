# Blue-Echo

![CI](https://github.com/danierod01/Blue-Echo/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

Plataforma web de correlación de Indicadores de Compromiso (IOCs) contra 18 fuentes de Threat Intelligence, con scoring automático, mapping a MITRE ATT&CK y análisis ejecutivo generado por IA.

Dado un IOC (IP, hash, dominio, URL) o un fichero de logs, consulta todas las fuentes en paralelo, calcula un score de amenaza 0-100, mapea las técnicas ATT&CK relevantes y genera un resumen ejecutivo en español.

---

## Índice

- [Qué hace](#qué-hace)
- [Fuentes de Threat Intelligence](#fuentes-de-threat-intelligence)
- [Requisitos previos](#requisitos-previos)
- [Instalación y arranque](#instalación-y-arranque)
  - [Con Docker (recomendado)](#con-docker-recomendado)
  - [Sin Docker (desarrollo local)](#sin-docker-desarrollo-local)
- [Autenticación](#autenticación)
- [Configuración de API Keys](#configuración-de-api-keys)
- [Uso de la herramienta](#uso-de-la-herramienta)
- [API REST](#api-rest)
- [Despliegue en producción](#despliegue-en-producción)
- [Estructura del repositorio](#estructura-del-repositorio)
- [Stack técnico](#stack-técnico)

---

## Qué hace

1. Introduces un IOC (IP, hash MD5/SHA1/SHA256, dominio o URL), subes un fichero de logs, o lanzas un escaneo masivo de hasta 20 IOCs a la vez.
2. La plataforma extrae y normaliza todos los IOCs únicos del input.
3. Los consulta en paralelo contra las 18 fuentes configuradas, respetando un semáforo de concurrencia configurable.
4. Calcula un **score de amenaza 0-100** según reglas fijas por fuente con acumulación acotada.
5. Mapea los hallazgos a **técnicas MITRE ATT&CK** (Initial Access, Execution, C2, Impact…).
6. Genera un **resumen ejecutivo en español** con Groq (LLaMA 3.3-70B, gratuito), con Anthropic Claude como fallback opcional.
7. Muestra todo en un dashboard con código de colores:
   - **CRÍTICO** (81-100) — rojo
   - **MALICIOSO** (51-80) — naranja
   - **SOSPECHOSO** (21-50) — amarillo
   - **LIMPIO** (0-20) — verde
8. Almacena el historial completo en base de datos con paginación y filtros.

---

## Fuentes de Threat Intelligence

### Fuentes originales

| Fuente | Tipos de IOC | API Key |
|---|---|---|
| VirusTotal | IP, Hash, Dominio, URL | Sí — `VT_API_KEY` |
| AbuseIPDB | IP | Sí — `ABUSEIPDB_API_KEY` |
| Shodan | IP | Sí — `SHODAN_API_KEY` |
| AlienVault OTX | IP, Hash, Dominio | Sí — `OTX_API_KEY` |
| GreyNoise | IP | Sí (free) — `GREYNOISE_API_KEY` |
| MalwareBazaar | Hash | No (pública) |
| URLhaus | URL, Dominio | No (pública) |

### Nuevas fuentes

| Fuente | Tipos de IOC | API Key | Cuota gratuita |
|---|---|---|---|
| ThreatFox (abuse.ch) | IP, Hash, Dominio, URL | Opcional — `THREATFOX_API_KEY` | Sin límite publicado |
| URLScan.io | URL, Dominio | Opcional — `URLSCAN_API_KEY` | Búsqueda pública; la key sube la cuota |
| IPinfo | IP | Sí — `IPINFO_API_KEY` | 50.000 req/mes |
| SecurityTrails | Dominio | Sí — `SECURITYTRAILS_API_KEY` | 50 req/mes |
| Hybrid Analysis | Hash | Sí — `HYBRID_ANALYSIS_API_KEY` | Tier "default" |
| Netlas | IP, Dominio | Sí — `NETLAS_API_KEY` | 50 req/día |
| Criminal IP | IP, Dominio | Sí — `CRIMINAL_IP_API_KEY` | Créditos limitados |
| MalShare | Hash | Sí — `MALSHARE_API_KEY` | Sin límite publicado |
| Pulsedive | IP, Hash, Dominio, URL | Sí — `PULSEDIVE_API_KEY` | **10 req/día** |
| Censys | IP, Dominio | Sí — `CENSYS_API_ID` + `CENSYS_API_SECRET` | **250 req/mes** |
| RDAP / WHOIS | Dominio | No (pública) | Sin límite |

Los conectores sin API key configurada se marcan como inactivos en el panel pero no impiden el arranque ni afectan al resto del escaneo.

---

## Requisitos previos

### Con Docker (recomendado)

- [Docker Engine](https://docs.docker.com/engine/install/) 24.x o superior
- Docker Compose v2 (incluido en Docker Desktop y en instalaciones modernas)

```bash
docker --version        # Docker version 24.x.x
docker compose version  # Docker Compose version v2.x.x
```

### Sin Docker (desarrollo local)

- Python 3.11 o superior
- Node.js 22.x LTS
- pip y npm

---

## Instalación y arranque

### Con Docker (recomendado)

#### 1. Clonar el repositorio

```bash
git clone https://github.com/danierod01/Blue-Echo.git
cd Blue-Echo
```

#### 2. Crear el fichero de variables de entorno

```bash
cp .env.example .env
```

Edita `.env` y añade las API keys que tengas. Los valores mínimos para el primer arranque son:

```dotenv
BLUE_ECHO_API_KEY=una_clave_segura_que_tu_elijas
GROQ_API_KEY=tu_clave_de_groq
```

Ver la sección [Configuración de API Keys](#configuración-de-api-keys) para el listado completo.

#### 3. Construir y arrancar

```bash
docker compose up -d --build
```

Este comando construye las imágenes y arranca tres contenedores en segundo plano: **PostgreSQL** (base de datos), **backend** (FastAPI) y **frontend** (Nginx + build de React). Los datos persisten en el volumen `pg_data`. El backend espera a que Postgres esté sano (`depends_on: service_healthy`) antes de arrancar. El primer arranque tarda 2-4 minutos.

> **Base de datos:** en Docker se usa PostgreSQL 16 (credenciales en las variables `POSTGRES_*` del `.env`). Fuera de Docker (desarrollo local directo o tests) el código usa SQLite por defecto, sin configuración extra.

#### 4. Verificar que todo funciona

```bash
curl http://localhost/api/health
# Respuesta esperada: {"status":"ok","version":"1.0.0"}
```

#### 5. Abrir el panel web

Abre el navegador en **http://localhost** e introduce la `BLUE_ECHO_API_KEY` que configuraste en `.env`.

#### Comandos útiles

```bash
# Ver logs en tiempo real
docker compose logs -f

# Ver logs solo del backend
docker compose logs -f backend

# Reconstruir tras cambios de código
docker compose up -d --build

# Recargar backend tras cambiar .env
docker compose restart backend

# Parar sin borrar datos
docker compose down

# Parar Y borrar la base de datos
docker compose down -v
```

---

### Sin Docker (desarrollo local)

Más cómodo para desarrollo, ya que Vite recarga el frontend al instante sin reconstruir imágenes.

#### 1. Clonar el repositorio

```bash
git clone https://github.com/danierod01/Blue-Echo.git
cd Blue-Echo
```

#### 2. Crear el fichero de variables de entorno

```bash
cp .env.example .env
```

Edita `.env` y añade las claves necesarias. En local puedes dejar `BLUE_ECHO_API_KEY` vacío para omitir la autenticación mientras desarrollas.

#### 3. Arrancar el backend

```bash
cd backend

# Crear y activar entorno virtual
python -m venv .venv
source .venv/bin/activate        # Linux / macOS
.venv\Scripts\activate           # Windows (PowerShell)

# Instalar dependencias
pip install -r requirements.txt

# Arrancar (recarga automática al guardar cambios)
uvicorn main:app --reload --port 8000
```

El backend queda disponible en:
- API: **http://localhost:8000**
- Swagger UI: **http://localhost:8000/docs**

#### 4. Arrancar el frontend

En **otra terminal**:

```bash
cd frontend

npm install        # Solo la primera vez
npm run dev
```

El frontend queda disponible en **http://localhost:5173**

> El `vite.config.ts` incluye un proxy que redirige `/api/*` a `localhost:8000` automáticamente, por lo que no hay conflictos de CORS en desarrollo.

#### 5. Verificar que todo funciona

```bash
curl http://localhost:8000/api/health
# {"status":"ok","version":"1.0.0"}
```

#### Ejecutar los tests

**Backend** (pytest — 281 tests):

```bash
cd backend

python -m pytest -v           # Suite completa
python -m pytest --tb=short   # Resumen de fallos sin traza
python -m pytest tests/test_virustotal.py -v   # Un conector específico
```

**Frontend** (Vitest + Testing Library):

```bash
cd frontend

npm test          # Ejecuta los tests una vez
npm run test:watch # Modo watch
```

Ambas suites se ejecutan automáticamente en cada push/PR mediante GitHub Actions.

---

## Autenticación

Blue-Echo protege todos sus endpoints (excepto `/api/health`) mediante una API key propia.

### Configurar la clave

En el fichero `.env`, define:

```dotenv
BLUE_ECHO_API_KEY=tu_clave_secreta_aqui
```

Si este valor está vacío, la autenticación se desactiva completamente (útil en desarrollo local). Al arrancar con la variable vacía, el backend muestra un warning en los logs:

```
WARNING  BLUE_ECHO_API_KEY no está configurada — todos los endpoints de la API están abiertos sin autenticación.
```

**En producción, definir siempre esta variable.**

### Iniciar sesión en el panel

1. Abre **http://localhost** (Docker) o **http://localhost:5173** (local)
2. Introduce la `BLUE_ECHO_API_KEY` en el formulario de login
3. La clave se almacena en `localStorage` del navegador y se envía automáticamente en todas las peticiones

### Usar la API directamente

Añade el header `X-API-Key` a todas las peticiones:

```bash
curl http://localhost/api/history \
  -H "X-API-Key: tu_clave_secreta_aqui"
```

### Invitaciones y tokens personales (multiusuario)

Además de la clave maestra, si defines `ADMIN_SECRET` puedes repartir **tokens de
acceso personales** sin compartir la clave maestra:

1. Ve a **http://localhost/invite**, introduce el `ADMIN_SECRET`, un **nombre**, un
   **rol** y (opcional) una **caducidad en días** → se genera un token.
2. Cada usuario entra con su token y ve **solo su propio historial** (aislamiento por
   token; el detalle de un escaneo ajeno responde `404`).
3. Desde la misma página, "Gestionar tokens" permite **listar y revocar** tokens.

**Roles (control de acceso):**

| Rol | Puede |
|---|---|
| `analyst` | Escanear, ver **su** historial, exportar sus escaneos |
| `admin` | Todo lo anterior **+ administrar tokens** (crear/listar/revocar) |

Las operaciones de administración se autorizan por **cualquiera** de estas vías:
un token con rol **admin** (o la master key) en la cabecera `X-API-Key`, **o** el
`ADMIN_SECRET` en el cuerpo (útil como *bootstrap* para crear el primer token admin).

**Rate limiting por token:** el límite de peticiones se aplica **por token** cuando la
petición viene autenticada (y por IP en caso contrario), de modo que un token no comparte
cupo con toda una red detrás de NAT. El login (`/api/auth/verify`) se limita por IP.

Endpoints: `POST /api/auth/invite` (crear, acepta `role`), `POST /api/auth/tokens`
(listar), `POST /api/auth/revoke` (revocar), `GET /api/auth/me` (nombre + rol de la sesión).

---

## Configuración de API Keys

Edita el fichero `.env`:

```dotenv
# ---- Autenticación ----
# Clave maestra para acceder al panel y a la API. Déjala vacía solo en desarrollo local.
BLUE_ECHO_API_KEY=
# Código de administración para generar/gestionar tokens de invitación en /invite.
# Si se deja vacío, el sistema de invitaciones queda deshabilitado.
ADMIN_SECRET=

# ---- IA Generativa ----
# Groq — proveedor principal, tier gratuito (registro en console.groq.com)
# Modelo por defecto: llama-3.3-70b-versatile
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile

# Anthropic Claude — fallback opcional (de pago)
ANTHROPIC_API_KEY=

# ---- Threat Intelligence — fuentes originales ----
VT_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=

# ---- Threat Intelligence — nuevas fuentes ----
THREATFOX_API_KEY=
URLSCAN_API_KEY=
IPINFO_API_KEY=
SECURITYTRAILS_API_KEY=
HYBRID_ANALYSIS_API_KEY=
NETLAS_API_KEY=
CRIMINAL_IP_API_KEY=
MALSHARE_API_KEY=
PULSEDIVE_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=

# ---- Backend ----
DATABASE_URL=sqlite:///./ioc_correlator.db
REQUEST_TIMEOUT=10
MAX_CONCURRENT_REQUESTS=5
CACHE_TTL_SECONDS=3600
MAX_UPLOAD_SIZE_MB=10
CORS_ORIGINS=*

# ---- Rate limiting (peticiones por IP y minuto) ----
RATE_LIMIT_SCAN=10
RATE_LIMIT_DEFAULT=60

# ---- Alertas por webhook (opcional) ----
# Si se configura una URL, se envía una notificación cuando un escaneo
# supera el umbral de score. Déjalo vacío para desactivar las alertas.
ALERT_WEBHOOK_URL=
ALERT_SCORE_THRESHOLD=70
ALERT_WEBHOOK_TYPE=slack   # slack | discord | teams | generic
```

### Dónde conseguir las claves (todas tienen plan gratuito)

| Servicio | Registro | Plan gratuito |
|---|---|---|
| Groq | https://console.groq.com | 14.400 req/día, 30 RPM |
| VirusTotal | https://www.virustotal.com/gui/join-us | 4 req/min, 500 req/día |
| AbuseIPDB | https://www.abuseipdb.com/register | 1.000 req/día |
| Shodan | https://account.shodan.io/register | 1 req/seg |
| AlienVault OTX | https://otx.alienvault.com/ | Sin límite publicado |
| GreyNoise | https://viz.greynoise.io/signup | Community API gratuita |
| IPinfo | https://ipinfo.io/signup | 50.000 req/mes |
| SecurityTrails | https://securitytrails.com/app/signup | 50 req/mes |
| Hybrid Analysis | https://hybrid-analysis.com | Solicitar tier "default" |
| Netlas | https://netlas.io/register | 50 req/día |
| Criminal IP | https://criminalip.io/register | Créditos limitados |
| MalShare | https://malshare.com/register.php | Sin límite publicado |
| Pulsedive | https://pulsedive.com/register | **10 req/día** |
| Censys | https://censys.io/register | **250 req/mes** |
| Anthropic | https://console.anthropic.com/ | Créditos de prueba |

> MalwareBazaar, URLhaus, ThreatFox, URLScan y RDAP son **APIs públicas** — funcionan sin clave desde el primer arranque (una key opcional en ThreatFox/URLScan solo sube la cuota).

Tras modificar `.env`:
```bash
docker compose restart backend
```

---

## Uso de la herramienta

### Iniciar sesión

La primera vez que accedes al panel verás un formulario de login. Introduce la `BLUE_ECHO_API_KEY` que configuraste en `.env`. Si la variable está vacía (modo dev), puedes entrar con cualquier valor.

### Escanear un IOC (modo individual)

1. Abre el panel en **http://localhost** (Docker) o **http://localhost:5173** (local)
2. Asegúrate de que el modo **Individual** esté seleccionado (por defecto)
3. Escribe el IOC en la barra de búsqueda y pulsa Enter o el botón Escanear:
   - IP: `185.220.101.45`
   - Dominio: `malware.example.com`
   - Hash MD5: `d41d8cd98f00b204e9800998ecf8427e`
   - Hash SHA256: `e3b0c44298fc1c149afbf4c8996fb924...`
   - URL: `https://evil.example.com/payload.exe`
4. En unos segundos verás:
   - **Score de amenaza** (0-100 con código de color)
   - **Tabla de resultados por fuente** — veredicto, hallazgo clave, puntos aportados
   - **Técnicas MITRE ATT&CK** mapeadas a partir de los hallazgos
   - **Entidades relacionadas** (pivoting): la IP a la que resuelve un dominio, los
     hostnames de una IP, los nameservers, etc. — cada una es **clicable** y lanza un
     escaneo encadenado, como en una investigación real de Threat Intelligence
   - **Análisis en lenguaje natural** generado por IA
5. El escaneo queda guardado automáticamente en el historial.
6. Con el botón **Descargar PDF** obtienes un informe del escaneo (score, veredicto, tabla de fuentes, análisis IA y técnicas MITRE) listo para adjuntar a un ticket o parte de incidente. Los botones **STIX** y **MISP** exportan el mismo escaneo a formatos estándar de Threat Intelligence, importables en un SIEM/TIP.

### Escanear desde un fichero de logs

1. Pulsa el botón **Subir fichero** o arrastra el fichero sobre la barra de búsqueda (máx. 10 MB)
2. Formatos soportados: Apache/Nginx access log, syslog, CSV de Windows Event Log, JSON lines, texto libre
3. La herramienta extrae automáticamente los IOCs únicos y escanea el primero encontrado

### Escaneo masivo (hasta 20 IOCs)

1. Selecciona el modo **Masivo** en el toggle sobre la barra de búsqueda
2. Introduce un IOC por línea en el área de texto (máximo 20)
3. Pulsa **Iniciar escaneo masivo** — los IOCs se procesan en secuencia con una pausa de 2 segundos entre cada uno para respetar los rate limits de las APIs externas
4. Puedes detener el escaneo en cualquier momento con el botón **Detener**
5. Al terminar, la tabla muestra IOC, tipo, score y veredicto de cada uno, con enlace al detalle completo
6. Botón **Exportar CSV** para descargar los resultados

### Historial de escaneos

- Haz clic en **Historial** en la barra de navegación superior
- Filtra por **tipo de IOC** (IPv4, IPv6, Hash, Dominio, URL) y **veredicto** (Limpio, Sospechoso, Malicioso, Crítico)
- Busca un IOC concreto con el campo de búsqueda de texto
- Paginación de 20 resultados por página con navegación completa
- Haz clic en cualquier fila para ver el detalle completo del escaneo

### Alertas por webhook (opcional)

Si configuras `ALERT_WEBHOOK_URL` en el `.env`, la herramienta envía una notificación automática a Slack, Discord, Microsoft Teams o un endpoint propio cada vez que un escaneo supera el umbral de score (`ALERT_SCORE_THRESHOLD`, por defecto 70). El formato del mensaje se ajusta con `ALERT_WEBHOOK_TYPE` (`slack` | `discord` | `teams` | `generic`). El envío es *best-effort*: si el webhook falla, se registra pero nunca interrumpe el escaneo.

### Estado de los conectores

Las pills bajo la barra de búsqueda muestran qué fuentes están activas (tienen API key configurada) y cuáles no.

---

## API REST

La documentación interactiva (Swagger UI) está disponible en modo desarrollo en **http://localhost:8000/docs**

> En el despliegue con Docker, el backend no expone el puerto 8000 al exterior. Los docs solo son accesibles arrancando el backend en local sin Docker.

Todas las rutas protegidas requieren el header `X-API-Key`. Solo `/api/health` y `/api/auth/verify` son públicas.

### POST /api/auth/verify — Verificar API key

```bash
curl -X POST http://localhost/api/auth/verify \
  -H "Content-Type: application/json" \
  -d '{"api_key": "tu_clave"}'
# {"valid": true}
```

> Rate limit: 5 peticiones/minuto por IP.

### POST /api/scan/json — Escanear un IOC (JSON)

```bash
curl -X POST http://localhost/api/scan/json \
  -H "Content-Type: application/json" \
  -H "X-API-Key: tu_clave" \
  -d '{"ioc": "185.220.101.45"}'
```

Respuesta:
```json
{
  "id": 42,
  "ioc_value": "185.220.101.45",
  "ioc_type": "ipv4",
  "score": 87,
  "verdict": "critical",
  "breakdown": { "virustotal": 30, "abuseipdb": 40, "shodan": 10, "otx": 20 },
  "connector_results": {
    "virustotal": { "verdict": "malicious", "summary": "VT: 23/87 motores.", "success": true },
    "abuseipdb":  { "verdict": "malicious", "summary": "AbuseIPDB: 95%, 142 reportes.", "success": true }
  },
  "mitre_techniques": [
    { "id": "T1071.001", "name": "Web Protocols (HTTP/S)", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/001/", "source": "AlienVault OTX: presente en pulsos activos" }
  ],
  "ai_summary": "La IP 185.220.101.45 ha sido clasificada como CRÍTICA con un score de 87/100...",
  "created_at": "2026-05-25T14:30:00Z"
}
```

### POST /api/scan — Escanear IOC o fichero (multipart)

```bash
# IOC por campo de formulario
curl -X POST http://localhost/api/scan \
  -H "X-API-Key: tu_clave" \
  -F "ioc=185.220.101.45"

# Fichero de logs
curl -X POST http://localhost/api/scan \
  -H "X-API-Key: tu_clave" \
  -F "file=@/ruta/a/access.log"
```

### POST /api/scan/async — Escaneo en segundo plano (cola Celery)

Encola el escaneo en un worker (Celery + Redis) y responde al instante con un
identificador de tarea, sin bloquear la petición. Útil para escaneos largos o
de muchas fuentes.

```bash
# Encolar
curl -X POST http://localhost/api/scan/async \
  -H "X-API-Key: tu_clave" -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.45"}'
# → {"task_id": "…", "status": "queued"}

# Consultar estado / resultado
curl http://localhost/api/tasks/<task_id> -H "X-API-Key: tu_clave"
# → {"task_id": "…", "status": "SUCCESS", "result": {"id": 42, "verdict": "critical", "score": 87}}
```

Requiere el worker y Redis (ambos se levantan con `docker compose`). El escaneo
síncrono (`POST /api/scan`) sigue disponible y no depende de la cola.

### GET /api/history — Historial paginado con filtros

```bash
# Página 1, 20 resultados
curl "http://localhost/api/history" \
  -H "X-API-Key: tu_clave"

# Filtrar por tipo de IOC y veredicto
curl "http://localhost/api/history?ioc_type=ipv4&verdict=critical&limit=10&offset=0" \
  -H "X-API-Key: tu_clave"

# Buscar por valor
curl "http://localhost/api/history?search=185.220&limit=20" \
  -H "X-API-Key: tu_clave"
```

Parámetros:

| Parámetro | Tipo | Rango | Descripción |
|---|---|---|---|
| `limit` | int | 1-100 | Resultados por página (default: 20) |
| `offset` | int | ≥ 0 | Desplazamiento (default: 0) |
| `ioc_type` | string | — | Uno o varios separados por coma: `ipv4`, `ipv6`, `md5`, `sha1`, `sha256`, `domain`, `url` |
| `verdict` | string | — | `clean`, `suspicious`, `malicious`, `critical` |
| `search` | string | — | Búsqueda parcial en el valor del IOC |

### GET /api/history/{id} — Detalle completo de un escaneo

```bash
curl http://localhost/api/history/42 \
  -H "X-API-Key: tu_clave"
```

### GET /api/history/{id}/pdf — Informe del escaneo en PDF

```bash
curl http://localhost/api/history/42/pdf \
  -H "X-API-Key: tu_clave" -o informe-42.pdf
```

Devuelve `application/pdf` con el informe del escaneo (score, veredicto, tabla de fuentes, análisis IA y técnicas MITRE).

### GET /api/history/{id}/export — Exportación a SIEM/TIP (STIX 2.1 / MISP)

```bash
# Bundle STIX 2.1 (indicador + attack-patterns MITRE + relaciones)
curl "http://localhost/api/history/42/export?format=stix" \
  -H "X-API-Key: tu_clave" -o ioc-42-stix.json

# Evento MISP (atributo + tags + threat level)
curl "http://localhost/api/history/42/export?format=misp" \
  -H "X-API-Key: tu_clave" -o ioc-42-misp.json
```

Serializa el escaneo a formatos interoperables que consumen las plataformas de
seguridad reales (Splunk/QRadar/OpenCTI vía STIX, o MISP directamente). El patrón
STIX se adapta al tipo de IOC (`ipv4-addr`, `domain-name`, `file:hashes`, …) y
cada técnica MITRE detectada se incluye como `attack-pattern` con su relación
`indicates`. Los IDs STIX son deterministas, de modo que reexportar el mismo IOC
produce el mismo identificador (el receptor lo trata como actualización).

### Watchlist — monitorización continua

```bash
# Añadir un IOC a la watchlist
curl -X POST http://localhost/api/watchlist \
  -H "X-API-Key: tu_clave" -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.45"}'

curl http://localhost/api/watchlist            -H "X-API-Key: tu_clave"   # listar
curl -X POST http://localhost/api/watchlist/1/check -H "X-API-Key: tu_clave"  # comprobar ya
curl http://localhost/api/watchlist/alerts     -H "X-API-Key: tu_clave"   # alertas de cambio
```

Un **worker Celery con scheduler (beat)** re-escanea periódicamente los IOCs de la
watchlist (enrich + score, sin IA) y **genera una alerta cuando el veredicto cambia**
(p. ej. una IP que pasa de `clean` a `malicious`); si el score supera el umbral,
además dispara el webhook de alertas. Frecuencia configurable con
`WATCHLIST_BEAT_SECONDS` y `WATCHLIST_CHECK_INTERVAL_MINUTES`.

### GET /api/stats — Métricas para el dashboard analítico

```bash
curl http://localhost/api/stats -H "X-API-Key: tu_clave"
```

Devuelve el total de escaneos, la distribución por veredicto y por tipo de IOC, la
serie temporal de los últimos 14 días, el top de amenazas y un resumen de la
watchlist. Alimenta la página **Analítica** (gráficas con Recharts).

### GET /api/sources — Estado de los conectores

```bash
curl http://localhost/api/sources \
  -H "X-API-Key: tu_clave"
```

### GET /api/health — Health check (público)

```bash
curl http://localhost/api/health
# {"status":"ok","version":"1.0.0"}
```

---

## Despliegue en producción

Esta sección describe cómo publicar Blue-Echo en internet desde un VPS Ubuntu 24.04 limpio.

### 1. Crear el VPS en Hetzner Cloud

1. Entra en [console.hetzner.cloud](https://console.hetzner.cloud)
2. Crea un nuevo servidor:
   - **Imagen:** Ubuntu 24.04
   - **Tipo:** CX22 (2 vCPU / 4 GB RAM) — suficiente para uso personal
   - **Red:** añade tu clave SSH pública para acceso sin contraseña
3. Anota la **IP pública** del servidor

### 2. Conectarse por SSH

```bash
ssh root@<IP-DEL-SERVIDOR>
```

### 3. Ejecutar el script de despliegue

```bash
curl -fsSL https://raw.githubusercontent.com/danierod01/Blue-Echo/main/deploy.sh -o deploy.sh
chmod +x deploy.sh
./deploy.sh
```

El script instala Docker, clona el repositorio en `/opt/blue-echo` y detiene la ejecución para que configures las variables de entorno antes de arrancar.

### 4. Configurar las variables de entorno

```bash
nano /opt/blue-echo/.env
```

Rellena como mínimo estas variables antes de continuar:

```dotenv
# OBLIGATORIO — protege el acceso al panel y a la API
BLUE_ECHO_API_KEY=una_clave_larga_y_aleatoria

# OBLIGATORIO para el análisis IA (gratuito)
GROQ_API_KEY=tu_clave_de_groq

# Restringe CORS al dominio del frontend en producción
CORS_ORIGINS=https://tudominio.com

# Threat Intelligence (añade las que tengas)
VT_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
IPINFO_API_KEY=
# ... resto de claves
```

Guarda con `Ctrl+O`, `Ctrl+X`.

### 5. Arrancar la aplicación

```bash
cd /opt/blue-echo
docker compose up -d --build
```

### 6. Verificar y acceder

```bash
curl http://localhost/api/health
# {"status":"ok","version":"1.0.0"}
```

Abre el navegador en **http://\<IP-DEL-SERVIDOR\>** e introduce la `BLUE_ECHO_API_KEY` en el login.

### Comandos útiles en el servidor

```bash
# Ver logs en tiempo real
cd /opt/blue-echo && docker compose logs -f

# Ver solo el backend
cd /opt/blue-echo && docker compose logs -f backend

# Actualizar a la última versión
cd /opt/blue-echo
git pull
docker compose up -d --build

# Recargar variables de entorno sin reconstruir
cd /opt/blue-echo && docker compose restart backend

# Parar sin borrar datos
cd /opt/blue-echo && docker compose down

# Parar y borrar la base de datos
cd /opt/blue-echo && docker compose down -v
```

### HTTPS con dominio propio

Si tienes un dominio, apunta el registro A a la IP del servidor y ejecuta:

```bash
apt-get install -y certbot python3-certbot-nginx
certbot --nginx -d tudominio.com
```

Certbot modifica la configuración de Nginx automáticamente y renueva el certificado cada 90 días. Recuerda actualizar `CORS_ORIGINS` en `.env` con el dominio HTTPS y reiniciar:

```bash
cd /opt/blue-echo && docker compose restart backend
```

---

## Estructura del repositorio

```
Blue-Echo/
├── backend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── requirements.txt
│   ├── main.py                     # FastAPI app, CORS, rate limit handler
│   └── ioc_correlator/
│       ├── api/
│       │   ├── auth.py             # Autenticación por API key (X-API-Key)
│       │   ├── limiter.py          # slowapi — rate limiting por IP real
│       │   ├── routes.py           # Endpoints REST (/scan, /history, /sources, /health)
│       │   └── schemas.py          # Modelos Pydantic de request/response
│       ├── connectors/
│       │   ├── base.py             # Clase abstracta BaseConnector
│       │   ├── virustotal.py
│       │   ├── abuseipdb.py
│       │   ├── shodan.py
│       │   ├── otx.py
│       │   ├── malwarebazaar.py
│       │   ├── urlhaus.py
│       │   ├── threatfox.py
│       │   ├── ipinfo.py
│       │   ├── securitytrails.py
│       │   ├── hybrid_analysis.py
│       │   ├── netlas.py
│       │   ├── criminal_ip.py
│       │   ├── malshare.py
│       │   ├── pulsedive.py
│       │   ├── censys.py
│       │   └── rdap.py             # RDAP/WHOIS público para dominios
│       ├── utils/
│       │   ├── validators.py       # Detección de tipo IOC (IPv4/6, hashes, dominio, URL)
│       │   └── cache.py            # Caché en memoria con TTL configurable
│       ├── enricher.py             # Orquestador async (asyncio.gather + semáforo)
│       ├── scorer.py               # Scoring 0-100 por reglas por fuente
│       ├── mitre_mapper.py         # Mapping estático hallazgos → técnicas ATT&CK
│       ├── ai_analyst.py           # Groq → Anthropic → análisis local (fallback en cadena)
│       ├── extractor.py            # Extracción de IOCs desde logs (regex multifase)
│       └── database.py             # SQLite con SQLModel, paginación y filtros
├── frontend/
│   ├── Dockerfile
│   ├── .dockerignore
│   ├── nginx.conf                  # Proxy al backend, cabeceras de seguridad, gzip
│   └── src/
│       ├── api/
│       │   └── client.ts           # Funciones fetch tipadas, gestión de sesión
│       ├── components/
│       │   ├── SearchBar.tsx
│       │   ├── ThreatScore.tsx
│       │   ├── ResultsTable.tsx    # Tabla de fuentes con hallazgo clave por conector
│       │   ├── AiSummary.tsx
│       │   ├── HistoryList.tsx
│       │   ├── SourcesStatus.tsx
│       │   ├── BulkScanPanel.tsx   # Escaneo masivo hasta 20 IOCs + exportar CSV
│       │   ├── MitreAttack.tsx     # Técnicas ATT&CK agrupadas por táctica
│       │   └── ProtectedRoute.tsx
│       └── pages/
│           ├── Dashboard.tsx       # Modo individual y masivo
│           ├── History.tsx         # Historial con filtros y paginación
│           ├── ScanDetail.tsx      # Detalle completo de un escaneo histórico
│           └── Login.tsx
├── docker-compose.yml
├── deploy.sh
├── .env.example
└── .gitignore
```

---

## Stack técnico

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 + FastAPI + httpx (async) + SQLModel + PostgreSQL (Docker) / SQLite (dev) |
| IA (principal) | Groq API — LLaMA 3.3-70B Versatile (tier gratuito) |
| IA (fallback) | Anthropic Claude API — `claude-sonnet-4-20250514` (opcional) |
| Frontend | React 18 + Vite + TypeScript + Tailwind CSS + shadcn/ui + TanStack Query |
| Infra | Docker Compose + Nginx + Hetzner Cloud VPS Ubuntu 24.04 |

---

## Integración continua (CI)

Cada push y pull request dispara el workflow de **GitHub Actions** (`.github/workflows/ci.yml`):

- **Backend:** `pytest` (batería completa) + `pip-audit` de dependencias.
- **Frontend:** `npm ci` + `npm run build` (TypeScript + Vite) + `npm audit`.

Las auditorías de dependencias se ejecutan como aviso (no bloquean el build) para que un
CVE nuevo aguas arriba no impida integrar, pero quede registrado en el log del job.

## Licencia

Publicado bajo licencia **MIT** — ver [`LICENSE`](LICENSE).

---

Proyecto académico — Máster en Ciberseguridad 2025-2026.
