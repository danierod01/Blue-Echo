<div style="page-break-after: always; text-align: center; padding-top: 38vh;">

<h1 style="font-size: 2.8em; margin-bottom: 0.3em;">Blue-Echo</h1>

<h2 style="font-size: 1.2em; font-weight: normal; color: #555; margin-bottom: 3em;">Plataforma de Correlación de Indicadores de Compromiso<br>con Threat Intelligence e IA Generativa</h2>

<hr style="width: 60%; margin: 0 auto 2em auto;">

<p style="font-size: 1em; line-height: 2em;">
<strong>Módulo:</strong> Ciberseguridad Avanzada — Práctica 1<br>
<strong>Autores:</strong> Daniel Muñoz Rodríguez &amp; Marta Fernández Plaza<br>
<strong>Fecha de entrega:</strong> 25 de mayo de 2026<br>
<strong>Línea de trabajo:</strong> Blue Team — Defensa y Monitorización<br>
<strong>Repositorio:</strong> https://github.com/danierod01/Blue-Echo<br>
<strong>Herramienta desplegada:</strong> http://138.199.205.221
</p>

</div>

## Índice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Descripción del problema y justificación de la solución](#2-descripción-del-problema-y-justificación-de-la-solución)
3. [Arquitectura técnica](#3-arquitectura-técnica)
4. [Proceso de desarrollo](#4-proceso-de-desarrollo)
5. [Guía de despliegue](#5-guía-de-despliegue)
6. [Manual de uso](#6-manual-de-uso)
7. [Conclusiones y lecciones aprendidas](#7-conclusiones-y-lecciones-aprendidas)
8. [Road map de mejora — Práctica 2](#8-road-map-de-mejora--práctica-2)

<div style="page-break-after: always;"></div>

## 1. Resumen ejecutivo

Blue-Echo es una plataforma web de correlación de Indicadores de Compromiso (IOCs) que automatiza el proceso de consulta a múltiples fuentes de Threat Intelligence y genera un análisis ejecutivo en lenguaje natural usando la API de Claude (Anthropic). Dado un IOC —una dirección IP, un hash de fichero, un dominio o una URL—, la herramienta lanza en paralelo hasta siete consultas a fuentes externas como VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, MalwareBazaar, URLhaus y GreyNoise, consolida los resultados en un score de amenaza de 0 a 100, y presenta todo en un dashboard web accesible desde internet.

El problema que resuelve es concreto: un analista de un equipo blue team que necesita evaluar un IOC hoy tiene que abrir al menos cinco pestañas distintas, copiar y pegar el mismo valor en cada una, interpretar formatos de respuesta heterogéneos y redactar manualmente un resumen para el informe de incidente. Blue-Echo colapsa ese flujo en una única operación que tarda menos de diez segundos.

La herramienta está construida con FastAPI en el backend (Python 3.11), React 18 con TypeScript en el frontend, y se despliega mediante Docker Compose en un VPS de Hetzner Cloud. El desarrollo se ha llevado a cabo íntegramente con el apoyo de Claude Code como asistente de programación, y la integración de IA generativa en la propia herramienta utiliza el SDK oficial de Anthropic.

---

## 2. Descripción del problema y justificación de la solución

### El problema

Cuando un analista de seguridad detecta un comportamiento anómalo —una conexión saliente a una IP desconocida, un hash que aparece en un log de endpoint, un dominio referenciado en un correo de phishing— el siguiente paso es determinar si ese indicador está asociado a actividad maliciosa conocida. Para eso existen las plataformas de Threat Intelligence: bases de datos mantenidas por la comunidad y por empresas especializadas que recogen reportes de IPs maliciosas, hashes de malware, dominios de phishing y otros indicadores.

El problema es que no existe una única fuente de verdad. VirusTotal agrega los resultados de más de ochenta motores antivirus y es la referencia para hashes y URLs. AbuseIPDB recoge denuncias de la comunidad sobre IPs abusivas. Shodan indexa dispositivos expuestos en internet y permite ver qué puertos tiene abiertos una IP. AlienVault OTX agrega inteligencia de amenazas en forma de "pulsos" creados por investigadores de todo el mundo. MalwareBazaar y URLhaus, ambas de Abuse.ch, son bases de datos especializadas en hashes de malware y URLs maliciosas respectivamente. GreyNoise distingue entre tráfico de internet ruidoso benigno (escáneres legítimos, crawlers) y tráfico genuinamente malicioso.

Un analista que quiera hacer bien su trabajo consulta todas estas fuentes para cada IOC. Si trabaja en un SOC con volumen medio, puede necesitar evaluar decenas de IOCs por turno. El tiempo que pierde en tareas mecánicas —copiar, pegar, interpretar, resumir— es tiempo que no dedica a analizar.

### La solución

Blue-Echo automatiza exactamente ese flujo. La plataforma acepta un IOC como entrada, detecta automáticamente su tipo (IPv4, IPv6, MD5, SHA1, SHA256, dominio o URL), consulta en paralelo todas las fuentes relevantes para ese tipo de indicador, calcula un score de amenaza con reglas transparentes y documentadas, y genera un resumen ejecutivo en español usando Claude como modelo de lenguaje.

La elección de construir esto como plataforma web —y no como script de línea de comandos— tiene una razón concreta: en un entorno SOC, la herramienta la usan analistas con distintos niveles técnicos, y nadie quiere tener que instalar dependencias de Python para consultar un hash. El historial de consultas persistido en base de datos permite además reutilizar resultados anteriores y construir una memoria de amenazas del entorno.

---

## 3. Arquitectura técnica

### Visión general

La aplicación se compone de dos contenedores Docker orquestados con Docker Compose y un volumen persistente para la base de datos. Toda la comunicación externa pasa por el contenedor de frontend, que actúa como reverse proxy hacia el backend.

![[Infra.svg]]

### El contenedor frontend

Utiliza la imagen oficial `nginx:1.27-alpine`. Durante el build de Docker, una etapa intermedia basada en `node:22-alpine` compila el proyecto React con Vite y genera el directorio `dist/`. La imagen final de Nginx recoge ese directorio estático y lo sirve directamente para cualquier ruta que no empiece por `/api/`. Las rutas de la API las reenvía al servicio `backend` en el puerto 8000 mediante una directiva `proxy_pass`.

```nginx
location /api/ {
    proxy_pass         http://backend:8000;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
}

location / {
    try_files $uri $uri/ /index.html;
}
```

Este diseño tiene una ventaja importante: el navegador siempre ve el mismo origen para el HTML, los assets de React y las llamadas a la API. No hay CORS, no hay cookies de terceros, no hay configuraciones especiales en el cliente. Todo llega desde `http://servidor:80`.

### El contenedor backend

La imagen sigue un patrón multi-stage. La primera etapa (`builder`) instala todas las dependencias Python en un entorno virtual aislado. La segunda etapa copia solo ese entorno virtual y el código fuente, sin compiladores ni pip, lo que reduce el tamaño final y la superficie de ataque. El proceso arranca como usuario no root (`appuser`).

Internamente, el backend está organizado en capas bien delimitadas. Las peticiones entran por los `routes.py` de FastAPI. Antes de lanzar cualquier consulta a fuentes externas, el `enricher.py` comprueba si el resultado ya está en la caché TTL en memoria con un tiempo de expiración de una hora. Si no está, lanza todas las consultas disponibles para ese tipo de IOC usando `asyncio.gather` con un semáforo que limita a cinco peticiones simultáneas —respetando así los rate limits de las APIs gratuitas—. Los resultados pasan por el `scorer.py`, que aplica reglas documentadas para calcular el score, y luego por el `ai_analyst.py`, que construye un prompt estructurado y llama a la API de Claude para generar el resumen.

### Por qué `expose` en lugar de `ports`

El backend declara `expose: ["8000"]` en el `docker-compose.yml`, no `ports`. La diferencia es que `expose` hace el puerto accesible solo dentro de la red Docker interna, sin publicarlo en el host. El único punto de entrada desde internet es el puerto 80 del contenedor de Nginx. Esto significa que un atacante que encuentre la IP del servidor no puede acceder directamente a la API de FastAPI; tiene que pasar por Nginx, que aplica su propia configuración de seguridad.

### La base de datos

SQLite vive en el volumen `db_data` montado en `/app/data/` dentro del contenedor. Esto garantiza que los datos persisten aunque el contenedor se destruya y se vuelva a crear. SQLModel, que actúa como ORM, crea las tablas automáticamente en el arranque del backend mediante el evento `lifespan` de FastAPI.

### El script deploy.sh

El script automatiza el aprovisionamiento completo de un VPS Ubuntu 24.04 limpio. Verifica que se ejecuta como root, actualiza los paquetes del sistema, instala Docker si no está presente, clona el repositorio en `/opt/blue-echo` (o hace `git pull` si ya existe), crea el `.env` a partir del `.env.example` y abre `nano` automáticamente para que el operador introduzca las API keys antes de continuar. Una vez guardado el fichero, lanza `docker compose up -d --build` y espera activamente a que el endpoint `/api/health` responda antes de mostrar el resumen con la URL pública del servidor.

### Stack tecnológico

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11, FastAPI, Uvicorn, httpx (async), SQLModel, anthropic SDK |
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, TanStack Query, Recharts |
| Infraestructura | Docker, Docker Compose, Nginx, SQLite |
| IA generativa | Claude Sonnet (claude-sonnet-4-20250514) vía API de Anthropic |
| Despliegue | Hetzner Cloud VPS CX23 (Ubuntu 24.04) |
| CI/CD | GitHub (control de versiones + ramas por funcionalidad) |

---

## 4. Proceso de desarrollo

El desarrollo se ha estructurado en módulos secuenciales siguiendo un orden que minimiza el trabajo en falso: primero la capa de datos y validación, luego los conectores, después la lógica de negocio (scoring e IA), y finalmente el frontend. En ningún momento se ha intentado construir todo de golpe.

### Fase 1 — Setup inicial y estructura del proyecto

El primer paso fue definir la estructura de directorios completa antes de escribir una sola línea de código funcional. Se crearon los ficheros `CLAUDE.md` (instrucciones para el agente de desarrollo), `.gitignore`, `.env.example` y la distribución de carpetas `backend/ioc_correlator/` y `frontend/src/`. La decisión de separar completamente frontend y backend —con sus propios `Dockerfile` y `.dockerignore`— se tomó desde el principio para evitar acoplamientos innecesarios.

### Fase 2 — Backend base

Se implementó la aplicación FastAPI mínima con el endpoint `/api/health` y el middleware CORS. El patrón `lifespan` de FastAPI gestiona el ciclo de vida de la aplicación, creando las tablas de la base de datos en el arranque. Se optó por FastAPI sobre Flask por su soporte nativo de `async/await`, la validación automática con Pydantic y la generación de documentación Swagger sin configuración adicional.

```
GET /api/health
```

```json
{
  "status": "ok",
  "version": "1.0.0"
}
```

### Fase 3 — Validadores y extractor de logs

El módulo `validators.py` detecta el tipo de IOC mediante expresiones regulares ordenadas por especificidad: primero URLs completas, luego hashes (SHA256 antes que SHA1 antes que MD5, para evitar falsos positivos por longitud), luego IPs y finalmente dominios. El `extractor.py` aplica estos validadores sobre el contenido de ficheros de log en distintos formatos —Apache/Nginx, syslog, CSV de Windows Event Log, JSON lines y texto libre— extrayendo todos los IOCs únicos que aparezcan.

### Fase 4 — Modelo de base de datos

`ScanResult` es el único modelo de la aplicación. Almacena el valor del IOC, su tipo, el score, el veredicto, el JSON completo de los resultados por conector, el desglose de puntuación y el análisis generado por IA. SQLModel combina la definición del modelo SQLAlchemy con el esquema Pydantic en una sola clase, evitando duplicación.

### Fase 5 — Conectores de Threat Intelligence

Todos los conectores heredan de `BaseConnector`, una clase abstracta que implementa el método `query()` con manejo centralizado de errores: timeouts, errores HTTP 429 (rate limit), 403 (API key inválida), respuestas vacías o malformadas. El método abstracto que cada conector implementa es `_fetch()`, que contiene solo la lógica específica de esa API. El patrón Template Method hace que si un conector falla —timeout, API caída, respuesta malformada—, el fallo queda contenido y el resto de conectores sigue funcionando con normalidad.

```python
async def query(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
    if not self.is_available():
        return ConnectorResult(
            source=self.name, success=False, verdict="unknown",
            summary=f"{self.name}: conector no disponible (falta API key).",
            error="missing_api_key",
        )
    if not self.supports(ioc_type):
        return ConnectorResult(
            source=self.name, success=False, verdict="unknown",
            summary=f"{self.name}: no soporta el tipo {ioc_type.value}.",
            error="unsupported_ioc_type",
        )
    try:
        return await self._fetch(ioc_value, ioc_type)
    except httpx.TimeoutException:
        return ConnectorResult(
            source=self.name, success=False, verdict="unknown",
            summary=f"{self.name}: timeout al contactar la API.", error="timeout",
        )
    except httpx.HTTPStatusError as exc:
        return self._handle_http_error(exc)
    except Exception as exc:
        return ConnectorResult(
            source=self.name, success=False, verdict="unknown",
            summary=f"{self.name}: error interno.", error=str(exc),
        )

@abstractmethod
async def _fetch(self, ioc_value: str, ioc_type: IOCType) -> ConnectorResult:
    ...
```

Se implementaron siete conectores:

**VirusTotal** — Es la fuente con más peso del proyecto, tanto en el scoring como en términos prácticos. El conector selecciona el endpoint correspondiente según el tipo de IOC (`/files/{hash}`, `/ip-addresses/{ip}`, `/domains/{domain}` o `/urls/{url_id}`) y extrae del campo `last_analysis_stats` el número de motores que han clasificado el indicador como `malicious` o `suspicious` sobre el total que lo han analizado. Lo que se muestra en el dashboard es esa proporción: por ejemplo, 23/87.

El dato hay que leerlo con criterio. Un hash con 2/70 puede ser un falso positivo de un motor poco fiable o puede ser una muestra nueva que aún no ha llegado a todos los motores. Un hash con 45/70 es otra cosa. El scoring diferencia ambos casos: más de cinco detecciones suman treinta puntos; entre una y cinco, quince.

La restricción del tier gratuito es el rate limit de cuatro peticiones por minuto. Para el caso de uso normal —un IOC a la vez— no supone ningún problema. En un escenario de bulk scan sería necesario añadir una cola con delay entre peticiones.

**AbuseIPDB** — Solo para IPs. Devuelve un porcentaje de confianza de abuso calculado sobre los reportes de los últimos treinta días y el número total de reportes. Es especialmente útil para detectar IPs de exit nodes Tor, servidores de spam y escáneres masivos.

**Shodan** — También exclusivo para IPs. La respuesta incluye los puertos abiertos indexados por Shodan, la organización a la que pertenece la IP y los servicios identificados. El scoring penaliza especialmente la apertura de los puertos 22, 3389, 445, 1433 y 4444, que históricamente se asocian a explotación o comando y control.

**AlienVault OTX** — Consulta si el IOC aparece en algún "pulso" activo de la plataforma. Los pulsos son colecciones de IOCs relacionados con una campaña o familia de malware específica, creados por investigadores de la comunidad. La ausencia de un IOC en OTX no significa que sea benigno; significa que nadie ha creado aún un pulso que lo incluya.

**MalwareBazaar** — Abuse.ch. Si el hash está en la base de datos suma cuarenta puntos al score directamente; no hay escala de grises. La respuesta incluye la familia de malware cuando está disponible, lo que permite al análisis IA mencionar el nombre concreto. No requiere API key.

**URLhaus** — También de Abuse.ch, especializada en URLs y dominios usados para distribuir malware. La consulta devuelve el estado de la URL (online, offline, desconocido) y las etiquetas asociadas.

**GreyNoise** — Clasifica IPs en tres categorías: `malicious` (actividad ofensiva confirmada), `benign` (actividad de internet ruidosa legítima, como escáneres de investigación) y `unknown` (no observada por GreyNoise). Una IP clasificada como `benign` por GreyNoise resta diez puntos al score, ya que su presencia en otras fuentes probablemente se debe a que es un escáner legítimo.

El orquestador de conectores lanza todas las consultas compatibles con el tipo de IOC en paralelo, usando un semáforo configurable para respetar los rate limits de las APIs gratuitas:

```python
async def enrich(ioc_value: str, ioc_type: IOCType) -> dict[str, ConnectorResult]:
    key = f"{ioc_type.value}:{ioc_value}"
    cached = get_cache().get(key)
    if cached is not None:
        return cached

    sem = asyncio.Semaphore(int(os.getenv("MAX_CONCURRENT_REQUESTS", 5)))
    active = [c for c in _CONNECTORS if c.supports(ioc_type)]

    async def _run(connector) -> ConnectorResult:
        async with sem:
            return await connector.query(ioc_value, ioc_type)

    results: list[ConnectorResult] = await asyncio.gather(*[_run(c) for c in active])
    result_map = {r.source: r for r in results}
    get_cache().set(key, result_map)
    return result_map
```

El resultado final de todo el pipeline, devuelto por `POST /api/scan/json`, tiene este aspecto con la IP `185.220.101.45` (nodo de salida Tor conocido):

```json
{
  "id": 7,
  "ioc_value": "185.220.101.45",
  "ioc_type": "ipv4",
  "score": 87,
  "verdict": "critical",
  "breakdown": {
    "virustotal": 15,
    "abuseipdb": 40,
    "shodan": 20,
    "otx": 20,
    "greynoise": 0
  },
  "connector_results": {
    "virustotal": {
      "source": "virustotal",
      "success": true,
      "verdict": "suspicious",
      "summary": "VirusTotal: 4/87 motores lo marcan como malicioso o sospechoso.",
      "data": { "malicious": 3, "suspicious": 1, "total": 87 }
    },
    "abuseipdb": {
      "source": "abuseipdb",
      "success": true,
      "verdict": "malicious",
      "summary": "AbuseIPDB: confianza del 97% — 386 reportes en 30 días.",
      "data": { "confidence": 97, "total_reports": 386, "country": "DE" }
    },
    "shodan": {
      "source": "shodan",
      "success": true,
      "verdict": "suspicious",
      "summary": "Shodan: puertos abiertos — 22, 9001.",
      "data": { "open_ports": [22, 9001], "org": "Emerald Onion" }
    },
    "otx": {
      "source": "otx",
      "success": true,
      "verdict": "malicious",
      "summary": "OTX: presente en 12 pulsos activos.",
      "data": { "pulse_count": 12 }
    },
    "malwarebazaar": {
      "source": "malwarebazaar",
      "success": false,
      "verdict": "unknown",
      "summary": "MalwareBazaar: no soporta el tipo ipv4.",
      "error": "unsupported_ioc_type"
    },
    "greynoise": {
      "source": "greynoise",
      "success": true,
      "verdict": "malicious",
      "summary": "GreyNoise: clasificado como malicious.",
      "data": { "classification": "malicious", "name": "Tor Exit Node" }
    }
  },
  "ai_summary": "La IP 185.220.101.45 ha sido clasificada como CRÍTICA con un score de 87/100. AbuseIPDB acumula 386 reportes en los últimos 30 días con una confianza del 97%, principalmente asociados a tráfico Tor. OTX la sitúa en 12 pulsos activos relacionados con nodos de salida Tor, y GreyNoise confirma actividad maliciosa. Shodan muestra los puertos 22 y 9001 abiertos, patrón consistente con un nodo de salida Tor. Recomendación: bloquear en el firewall perimetral y revisar los registros de conexiones internas hacia esta IP en las últimas 72 horas.",
  "created_at": "2026-05-20T14:32:08"
}
```

### Fase 6 — Scorer

El módulo `scorer.py` aplica reglas independientes sobre el resultado de cada conector y acumula puntos hasta un máximo de cien. Las reglas están definidas como un diccionario de callables, lo que facilita añadir nuevas reglas sin modificar la lógica central. El veredicto final se determina por rangos: LIMPIO (0-20), SOSPECHOSO (21-50), MALICIOSO (51-80) y CRÍTICO (81-100).

| Condición | Puntos |
|---|---|
| VirusTotal: >5 motores detectan | +30 |
| VirusTotal: 1-5 motores detectan | +15 |
| AbuseIPDB: confianza >80% | +40 |
| AbuseIPDB: confianza 50-80% | +25 |
| Shodan: puerto sensible abierto | +10 c/u, máx +30 |
| OTX: presente en pulsos activos | +20 |
| MalwareBazaar: hash conocido | +40 |
| GreyNoise: clasificado malicious | +30 |
| GreyNoise: clasificado benign | -10 |

Las reglas están implementadas como funciones puras agrupadas en un diccionario, lo que permite añadir nuevas fuentes sin tocar la lógica central:

```python
_SENSITIVE_PORTS = {22, 3389, 445, 1433, 4444}

def _score_abuseipdb(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    confidence = result.data.get("confidence", 0)
    if confidence > 80:
        return 40
    if confidence > 50:
        return 25
    return 0

def _score_shodan(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    open_ports = result.data.get("open_ports", [])
    hits = sum(1 for p in open_ports if p in _SENSITIVE_PORTS)
    return min(hits * 10, 30)

def _score_greynoise(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    classification = result.data.get("classification", "")
    if classification == "malicious":
        return 30
    if classification == "benign":
        return -10
    return 0

_RULES: dict[str, object] = {
    "virustotal":    _score_virustotal,
    "abuseipdb":     _score_abuseipdb,
    "shodan":        _score_shodan,
    "otx":           _score_otx,
    "malwarebazaar": _score_malwarebazaar,
    "greynoise":     _score_greynoise,
}

def compute_score(results: dict[str, ConnectorResult]) -> ScoringResult:
    breakdown: dict[str, int] = {}
    total = 0
    for connector_name, rule_fn in _RULES.items():
        if connector_name in results:
            pts = rule_fn(results[connector_name])
            breakdown[connector_name] = pts
            total += pts
    score = max(0, min(100, total))
    return ScoringResult(score=score, verdict=_verdict(score), breakdown=breakdown)
```

### Fase 7 — Módulo de IA generativa

El `ai_analyst.py` es el componente diferenciador de la herramienta. Construye un prompt estructurado que incluye el tipo de IOC, el score calculado, el veredicto y un resumen de los hallazgos de cada conector, y llama a la API de Claude con un system prompt que lo posiciona como analista experto en Threat Intelligence del equipo azul.

Se optó por `AsyncAnthropic` (el cliente asíncrono del SDK oficial) porque FastAPI opera en un event loop de asyncio; usar el cliente síncrono bloquearía el loop durante la llamada a la API externa, degradando la capacidad de respuesta del servidor. Si la llamada falla por cualquier motivo —timeout, error de autenticación, fallo de la API—, la función devuelve un mensaje de fallback con los datos crudos en lugar de propagar la excepción.

### Fase 8 — Caché TTL

Para evitar consultar las mismas APIs externas con el mismo IOC en un intervalo corto, se implementó una caché en memoria con expiración por tiempo (TTL de una hora por defecto). La clave de caché combina el tipo y el valor del IOC: `"{tipo}:{valor}"`. La implementación es un singleton con lazy expiry: las entradas caducadas no se eliminan proactivamente, sino que se comprueban en el momento de la lectura.

### Fase 9 — Frontend

El frontend está construido con React 18, TypeScript y Vite. TanStack Query gestiona el estado de las peticiones asíncronas, el caché del cliente y la invalidación automática del historial tras cada escaneo. Los estilos usan Tailwind CSS de forma exhaustiva.

El componente principal es el Dashboard, que organiza la interfaz en dos columnas: la columna principal contiene la barra de búsqueda, el `ThreatScore` (un gauge SVG circular con animación de transición), la tabla de resultados por conector y el bloque de análisis IA; la columna lateral muestra los diez escaneos más recientes para navegación rápida.

La página de Historial muestra los últimos cincuenta escaneos en una tabla con score, veredicto, tipo de IOC y timestamp. Cada fila es clickable y navega a una página de detalle (`/history/:id`) que recarga el resultado completo desde la API y muestra los mismos componentes que el Dashboard.

### Fase 10 — Dockerización y despliegue

Los Dockerfiles de backend y frontend siguen el patrón multi-stage. El `docker-compose.yml` define el healthcheck del backend (petición HTTP a `/api/health` cada treinta segundos) y hace que el frontend espere a que el backend esté sano antes de arrancar (`depends_on: condition: service_healthy`). El volumen `db_data` garantiza la persistencia de la base de datos entre reinicios de contenedores.

---

## 5. Guía de despliegue

### Requisitos previos

- VPS con Ubuntu 24.04 (recomendado: Hetzner CX23, 2 vCPU, 4 GB RAM)
- Acceso SSH como root
- API keys de las fuentes de Threat Intelligence que se deseen activar
- API key de Anthropic (para el análisis IA)
- El repositorio de GitHub accesible públicamente o con token de acceso

### Paso 1 — Acceder al servidor

```bash
ssh root@<IP_DEL_SERVIDOR>
```

### Paso 2 — Ejecutar el script de despliegue

El script `deploy.sh` incluido en el repositorio automatiza todos los pasos siguientes. Se puede ejecutar directamente desde el repositorio:

```bash
curl -fsSL https://raw.githubusercontent.com/danierod01/Blue-Echo/main/deploy.sh | bash
```

O clonando primero el repositorio:

```bash
apt update && apt install -y git
git clone https://github.com/danierod01/Blue-Echo.git /opt/blue-echo
cd /opt/blue-echo
bash deploy.sh
```

### Paso 3 — Configurar las API keys

Cuando el script detecta que no existe un fichero `.env`, lo crea automáticamente a partir del `.env.example` y abre el editor `nano`. Hay que rellenar las variables correspondientes a las API keys disponibles:

```dotenv
VT_API_KEY=tu_api_key_de_virustotal
ABUSEIPDB_API_KEY=tu_api_key_de_abuseipdb
SHODAN_API_KEY=tu_api_key_de_shodan
OTX_API_KEY=tu_api_key_de_otx
GREYNOISE_API_KEY=tu_api_key_de_greynoise
ANTHROPIC_API_KEY=tu_api_key_de_anthropic
```

Los conectores para los que no se proporcione API key aparecerán como inactivos en el dashboard pero no impedirán el funcionamiento del resto. Se guarda con `Ctrl+O` y se cierra con `Ctrl+X`. El script continúa automáticamente.

### Paso 4 — Verificar el despliegue

El script espera activamente a que el backend responda antes de mostrar el resumen final. Una vez completado, se puede verificar manualmente:

```bash
curl http://localhost/api/health
# {"status":"ok","version":"1.0.0"}
```

La herramienta está accesible desde el navegador en `http://<IP_DEL_SERVIDOR>`.

### Comandos útiles en producción

```bash
# Ver logs en tiempo real
docker compose -f /opt/blue-echo/docker-compose.yml logs -f

# Reiniciar sin reconstruir
docker compose -f /opt/blue-echo/docker-compose.yml restart

# Actualizar a la última versión del repositorio
cd /opt/blue-echo && git pull && docker compose up -d --build

# Parar la aplicación
docker compose -f /opt/blue-echo/docker-compose.yml down

# Parar y borrar la base de datos (reset completo)
docker compose -f /opt/blue-echo/docker-compose.yml down -v
```

### Obtención de API keys gratuitas

| Fuente | URL de registro | Tier gratuito |
|---|---|---|
| VirusTotal | virustotal.com | 4 req/min, 500 req/día |
| AbuseIPDB | abuseipdb.com | 1.000 req/día |
| Shodan | shodan.io | 1 req/seg (cuenta básica) |
| AlienVault OTX | otx.alienvault.com | Sin límite publicado |
| GreyNoise | greynoise.io | 1.000 req/día (Community API) |
| Anthropic | console.anthropic.com | Créditos iniciales gratuitos |
| MalwareBazaar | bazaar.abuse.ch | Sin API key necesaria |
| URLhaus | urlhaus.abuse.ch | Sin API key necesaria |

---

## 6. Manual de uso

### Interfaz principal — Dashboard

Al acceder a la herramienta, la pantalla principal muestra la barra de búsqueda centrada y, debajo, el panel de fuentes activas con indicadores de qué conectores tienen API key configurada. En la columna derecha aparece el historial de los diez escaneos más recientes para referencia rápida.

### Escanear un IOC

Se escribe el IOC directamente en el campo de texto y se pulsa el botón "Escanear" o la tecla Enter. La herramienta acepta cualquiera de los siguientes formatos:

- **Dirección IP:** `185.220.101.45`, `2001:db8::1`
- **Hash MD5:** `d41d8cd98f00b204e9800998ecf8427e`
- **Hash SHA1:** `da39a3ee5e6b4b0d3255bfef95601890afd80709`
- **Hash SHA256:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **Dominio:** `malicious-domain.ru`, `update.windows.com`
- **URL:** `http://phishing.example.com/login`

La herramienta detecta automáticamente el tipo sin que el usuario tenga que especificarlo. Si la entrada no corresponde a ninguno de los formatos reconocidos, muestra un error descriptivo.

### Escanear un fichero de logs

El icono de subida de fichero, a la derecha de la barra de búsqueda, acepta ficheros `.log`, `.txt`, `.csv` y `.json`. El extractor analiza el contenido, identifica todos los IOCs únicos presentes y realiza el escaneo del primero encontrado. Los formatos de log soportados incluyen el formato de acceso de Apache y Nginx, syslog estándar, CSV exportado del Visor de Eventos de Windows y JSON lines.

### Interpretar los resultados

**Score y veredicto** — El número grande en el gauge circular indica la puntuación de amenaza calculada. El color y la etiqueta resumen la clasificación:

| Rango | Color | Veredicto | Interpretación |
|---|---|---|---|
| 0-20 | Verde | LIMPIO | Sin indicadores significativos de amenaza |
| 21-50 | Amarillo | SOSPECHOSO | Algunos indicadores, requiere revisión |
| 51-80 | Naranja | MALICIOSO | Múltiples fuentes confirman actividad maliciosa |
| 81-100 | Rojo | CRÍTICO | Alta confianza de amenaza activa |

**Tabla de resultados por fuente** — Cada fila corresponde a un conector. El icono verde indica consulta exitosa, el gris indica que el conector no está disponible (sin API key o tipo de IOC no soportado), y el rojo indica un error en la consulta. La columna "Puntos" muestra la contribución de ese conector al score total: los valores positivos en rojo representan puntos de riesgo añadidos, los negativos en verde representan factores mitigantes.

**Análisis IA** — El bloque azul en la parte inferior contiene el análisis generado por Claude. Resume en español los hallazgos más relevantes de todas las fuentes, contextualiza el nivel de riesgo y proporciona una recomendación de acción. Si la API key de Anthropic no está configurada o la llamada falla, el bloque no aparece.

### Historial de escaneos

La página "Historial" (enlace en la barra de navegación superior) muestra los últimos cincuenta escaneos con su IOC, tipo, score, veredicto y fecha. Haciendo clic en cualquier fila se accede a la vista de detalle completa de ese escaneo, que incluye la tabla de resultados por conector, el score y el análisis IA tal como se generaron en el momento del escaneo original.

---

## 7. Conclusiones y lecciones aprendidas

### Lo que funciona bien

La decisión de centralizar el manejo de errores en la clase base `BaseConnector` ha sido la más acertada del proyecto. Cuando se añade un nuevo conector, el desarrollador solo necesita implementar el método `_fetch()` con la lógica específica de esa API; el manejo de timeouts, errores HTTP y respuestas malformadas ya está resuelto. Esto ha permitido implementar los siete conectores con un nivel de robustez consistente sin repetir código.

El uso de `asyncio.gather` con semáforo para las consultas paralelas ha funcionado bien para este caso de uso sin añadir más infraestructura de la necesaria. Una solución más simple —consultas secuenciales— habría multiplicado por siete el tiempo de respuesta. Una solución más compleja —una cola de tareas como Celery— habría añadido una dependencia de infraestructura que no se justifica para este caso de uso. Con el semáforo de cinco peticiones simultáneas, el tiempo total de respuesta está limitado por el conector más lento, que en la práctica es VirusTotal con su rate limit de cuatro peticiones por minuto en el tier gratuito.

La arquitectura Docker con Nginx como punto de entrada único ha simplificado enormemente el despliegue. No hay que gestionar certificados SSL por separado para el backend, no hay configuraciones CORS complicadas, y el cambio de entorno (local a producción) es transparente porque la URL de la API siempre es relativa al mismo origen.

### Desafíos encontrados

**El cliente asíncrono de Anthropic.** El SDK tiene dos clientes, `Anthropic` y `AsyncAnthropic`. Se usó inicialmente el síncrono dentro de una función `async` de FastAPI porque aparentemente no hay ninguna restricción que lo impida — FastAPI lo acepta sin quejarse. El efecto es que cada llamada a Claude bloqueaba el event loop completo mientras esperaba respuesta, dejando el resto de peticiones colgadas. Lo que dificultó el diagnóstico es que el error no era un timeout explícito sino respuestas `Unauthorized` que no correspondían con ninguna configuración errónea de la API key. Una vez identificado, la solución fue cambiar a `AsyncAnthropic` y añadir `await` a la llamada `messages.create()`.

**La configuración de TypeScript con Vite.** La opción `baseUrl: "."` en `tsconfig.app.json` es incompatible con `moduleResolution: "bundler"` en TypeScript 5.5+. El error del compilador era críptico porque mencionaba `baseUrl` sin explicar la incompatibilidad con el modo de resolución. La solución fue eliminar `baseUrl` y mantener únicamente la configuración de `paths` para los alias `@/*`, que funciona sin necesidad de `baseUrl` en compiladores modernos.

**La cobertura real de las APIs de Threat Intelligence.** OTX y MalwareBazaar no tienen cobertura exhaustiva. Un hash que VirusTotal detecta como malicioso puede no aparecer en ningún pulso de OTX simplemente porque ningún investigador ha creado aún ese pulso. Esto es comportamiento esperado de las plataformas, no un bug del conector. En el contexto de esta herramienta, se ha documentado esta limitación en el análisis IA cuando corresponde.

### Valoración del uso de IA en el desarrollo

Claude Code ha actuado como par de programación durante todo el proyecto. La mayor parte del código está escrito por el asistente, pero las decisiones de fondo —qué arquitectura usar, qué patrones aplicar, qué compromisos aceptar— se tomaron con criterio propio antes de pedir implementación. La diferencia se nota en la capacidad de evaluar lo que el asistente propone y rechazarlo cuando no encaja. No siempre es fácil mantener ese control en sesiones largas, pero el resultado refleja las decisiones que se querían tomar, no las que el modelo habría tomado por defecto.

---

## 8. Road map de mejora — Práctica 2

Este road map recoge todas las mejoras identificadas tras la entrega de la Práctica 1. No todas llegarán a implementarse en la Práctica 2: la selección final dependerá del tiempo disponible, los recursos de infraestructura y los resultados de los estudios previos planificados (especialmente el de IA generativa). Las mejoras de alta prioridad son las candidatas naturales a la siguiente entrega; las de prioridad media y baja forman el backlog a largo plazo.

### Resumen por categorías

El enunciado organiza las mejoras en cuatro ejes. La tabla siguiente cubre todos ellos con una valoración de prioridad y coste para cada mejora:

| # | Categoría | Mejora | Prioridad | Coste adicional | Tiempo est. |
|---|---|---|---|---|---|
| S1 | Seguridad | Autenticación con API key propia | Alta | Ninguno | 4 h |
| S2 | Seguridad | Rate limiting por IP | Alta | Ninguno | 2 h |
| S3 | Seguridad | HTTPS con Let's Encrypt | Alta | ~1 €/año (dominio) | 3 h |
| S4 | Seguridad | Validación de tamaño de fichero en upload | Media | Ninguno | 1 h |
| F1 | Funcionalidad | Escaneo masivo (bulk scan) | Alta | Ninguno | 2 días |
| F2 | Funcionalidad | Conector ThreatFox (familias de malware) | Alta | Ninguno | 1 día |
| F3 | Funcionalidad | WHOIS/RDAP para dominios | Media | Ninguno | 4 h |
| F4 | Funcionalidad | Exportación a PDF del informe de escaneo | Media | Ninguno | 1 día |
| F5 | Funcionalidad | Alertas por webhook (Slack, Discord, Teams) | Media | Ninguno | 4 h |
| F6 | Funcionalidad | Mapping MITRE ATT&CK | Media-Alta | Ninguno | 4 días |
| F7 | Funcionalidad | Motor de IA: Anthropic vs Ollama local | Alta | Ver estudio | Incierto |
| R1 | Rendimiento | Paginación real en historial | Baja | Ninguno | 3 h |
| R2 | Rendimiento | Migración a PostgreSQL | Baja | 0-15 €/mes | 1 día |
| R3 | Rendimiento | Cola de tareas con Celery + Redis | Baja | 0 (mismo VPS) | 2 días |
| I1 | Integración | API pública con spec OpenAPI | Media | Ninguno | 4 h |
| I2 | Integración | Exportación de eventos a SIEM (Elastic/Wazuh) | Baja | Ninguno | 2 días |
| I3 | Integración | Plugin de navegador Chrome/Firefox | Baja | Ninguno | 1 semana |

---

### 1. Mejoras de seguridad de la herramienta

**S1 — Autenticación con API key propia**
Sin autenticación, cualquiera que encuentre la IP del servidor puede usar la herramienta y agotar las cuotas gratuitas de VirusTotal, AbuseIPDB y el resto de conectores. La solución es añadir una cabecera `X-API-Key` requerida en todos los endpoints de la API, configurable mediante variable de entorno. Es la mejora más urgente desde el punto de vista de seguridad operativa.

**S2 — Rate limiting por IP**
Complementario a la autenticación. Con la librería `slowapi` (un wrapper de `limits` para FastAPI), se puede limitar el número de peticiones por IP por minuto sin dependencias adicionales de infraestructura. Previene el abuso incluso cuando la API key está comprometida.

**S3 — HTTPS con Let's Encrypt**
Actualmente la herramienta sirve tráfico en HTTP plano. Certbot, integrado en el `deploy.sh`, obtiene y renueva automáticamente un certificado TLS gratuito. Requiere un dominio propio, cuyo coste es aproximadamente 1 €/año. Es un requisito implícito para cualquier despliegue profesional accesible desde internet.

**S4 — Validación de tamaño de fichero**
El endpoint de upload no limita actualmente el tamaño del fichero enviado. Un fichero de varios gigabytes podría consumir toda la memoria del servidor. Con una comprobación de tamaño máximo configurable en el endpoint de FastAPI se elimina este riesgo sin coste alguno.

---

### 2. Nuevas funcionalidades

**F1 — Escaneo masivo (bulk scan)**
La herramienta actual procesa un IOC por operación. En un contexto SOC real, el analista necesita evaluar listas de IOCs extraídas de alertas o feeds. La mejora consiste en añadir un textarea para pegar múltiples valores y procesarlos secuencialmente respetando los rate limits de las APIs externas. El backend ya tiene toda la infraestructura necesaria; es principalmente trabajo de frontend y cola de procesamiento.

**F2 — Ampliación de conectores de Threat Intelligence**
El número de fuentes consultadas es uno de los factores que más influye en la calidad del análisis. En la Práctica 2 se plantea incorporar nuevos conectores, siendo ThreatFox (base de datos pública de Abuse.ch que asocia IOCs a familias de malware concretas como Emotet, Cobalt Strike o Qakbot) el primero en la lista por no requerir API key y por cubrir un tipo de información —atribución a familia de malware— que ninguna de las fuentes actuales proporciona. Además de ThreatFox, se evaluarán otras fuentes públicas y con tier gratuito según disponibilidad y relevancia para los tipos de IOC soportados.

**F3 — WHOIS para dominios**
Para IOCs de tipo dominio, la fecha de registro es un indicador de riesgo en sí misma: un dominio registrado hace menos de treinta días es inherentemente sospechoso. Las APIs WHOIS/RDAP son públicas y sin coste.

**F4 — Exportación a PDF**
Un botón "Descargar informe" que genere un PDF del escaneo actual con el score, la tabla de fuentes y el análisis IA. La librería WeasyPrint en el backend no añade dependencias de infraestructura y es especialmente útil para documentar evidencias en respuesta a incidentes.

**F5 — Alertas por webhook**
Cuando el score supera un umbral configurable, enviar una notificación HTTP a una URL externa (Slack, Discord, Microsoft Teams). Sin infraestructura adicional, amplía la integración de la herramienta en flujos de trabajo SOC existentes.

**F6 — Mapping MITRE ATT&CK**
Cruzar los hallazgos de los conectores con el framework MITRE ATT&CK —tácticas, técnicas y procedimientos— contextualiza el IOC dentro de una cadena de ataque conocida. Los datos del framework son públicos y descargables. Es la mejora con mayor impacto en la calidad del análisis y en la diferenciación técnica de la herramienta.

**F7 — Estudio y decisión sobre el motor de IA generativa**
La integración de IA generativa es el componente más diferenciador de Blue-Echo y el único con potencial coste variable. Para la Práctica 2 se plantea evaluar dos alternativas antes de decidir cuál implementar de forma definitiva:

- **Opción A — API de Anthropic (Claude):** Mayor calidad de análisis en contextos de ciberseguridad. Coste por escaneo aproximado de 0,001-0,003 €. Asumible para uso esporádico; requiere presupuesto mensual en producción con volumen alto.

- **Opción B — Ollama con modelo local:** Servidor de LLMs que corre en el propio VPS y expone una API HTTP sin coste por token. Modelos como Llama 3.2 (3B) o Mistral 7B son viables en el CX23 actual (4 GB RAM) para modelos pequeños; modelos de mayor calidad requieren más memoria. Coste cero una vez desplegado.

La decisión se tomará tras un análisis comparativo de calidad de respuesta, coste operativo a largo plazo y viabilidad de recursos en el servidor actual.

---

### 3. Mejoras de rendimiento y escalabilidad

**R1 — Paginación real en el historial**
El endpoint `/api/history` devuelve un número fijo de resultados. Con paginación basada en cursor se puede navegar eficientemente sobre grandes volúmenes de registros sin coste adicional.

**R2 — Migración a PostgreSQL**
SQLite cubre perfectamente el caso de uso actual y no representa un cuello de botella hasta alcanzar cientos de usuarios concurrentes. PostgreSQL solo tiene sentido en un escenario multi-usuario de producción real. Si se implementa, puede correr en el mismo VPS (sin coste extra pero consumiendo RAM) o como servicio gestionado externo (~5-15 €/mes adicionales).

**R3 — Cola de tareas con Celery y Redis**
Necesario únicamente para el bulk scan a gran escala con procesamiento en background. Redis puede desplegarse en el mismo servidor sin coste adicional de infraestructura. Para una instancia única con uso moderado, el procesamiento síncrono actual es suficiente.

---

### 4. Integración con otras herramientas y APIs

**I1 — API pública documentada con OpenAPI**
Swagger UI ya está disponible en `/docs`. El paso siguiente es añadir autenticación y publicar la especificación para que otras herramientas del entorno SOC puedan integrarse programáticamente.

**I2 — Exportación de eventos a SIEM**
Envío de los resultados de cada escaneo como evento al índice de un SIEM existente (Elastic, Wazuh). Permite correlacionar los resultados de Blue-Echo con otros eventos de seguridad del entorno.

**I3 — Plugin de navegador**
Extensión para Chrome o Firefox que detecta IOCs en la página web activa y los envía directamente a Blue-Echo. Elimina el paso de copiar y pegar manualmente.

---

### Diagrama de fases — Práctica 2


![[Sprints.svg]]