# CLAUDE.md — IOC Correlator Agent

## Rol y contexto

Eres un agente de desarrollo especializado en ciberseguridad (blue team). Tu misión es ayudar a construir **IOC-Correlator**, una plataforma web full-stack que automatiza la correlación de Indicadores de Compromiso (IOCs) contra múltiples fuentes de Threat Intelligence, usa IA generativa para producir análisis en lenguaje natural, y presenta todo en un dashboard web accesible desde internet.

Este proyecto es una práctica universitaria de máster con entrega el **25 de mayo de 2026**. Los requisitos obligatorios son: panel web con dashboard, repositorio GitHub organizado, despliegue en Hetzner Cloud con Docker, informe PDF profesional y roadmap de mejoras.

El desarrollador tiene perfil técnico de ciberseguridad (OSCP/eJPTv2, HTB, TryHackMe, Kali Linux). Conoce bien el dominio pero está vibecodiando el proyecto con tu apoyo. **Explica las decisiones técnicas cuando no sean obvias. No generes todo el proyecto de una vez; construye módulo a módulo en el orden indicado.**

---

## Descripción del proyecto

### Qué hace IOC-Correlator

Dada una entrada (IP, hash, dominio, URL o fichero de logs), la plataforma:

1. Extrae y normaliza los IOCs del input.
2. Los consulta automáticamente y en paralelo contra múltiples fuentes de Threat Intelligence.
3. Consolida los resultados y calcula un **score de amenaza** (0-100).
4. Llama a la **API de Claude** para generar un resumen ejecutivo del IOC en lenguaje natural.
5. Presenta todo en un **dashboard web** visual y accesible desde internet.
6. Almacena el historial de consultas en base de datos.

### Fuentes de Threat Intelligence

| Fuente | Tipo de IOC | API Key |
|---|---|---|
| VirusTotal | IP, Hash, Dominio, URL | Sí |
| AbuseIPDB | IP | Sí |
| Shodan | IP | Sí |
| AlienVault OTX | IP, Hash, Dominio | Sí |
| MalwareBazaar (Abuse.ch) | Hash | No (pública) |
| URLhaus (Abuse.ch) | URL, Dominio | No (pública) |
| GreyNoise | IP | Sí (free tier) |

---

## Arquitectura completa del proyecto

```
ioc-correlator/
├── CLAUDE.md
├── README.md
├── docker-compose.yml
├── deploy.sh
├── .env.example
├── .env                        # Nunca subir a GitHub
├── .gitignore
│
├── backend/                    # FastAPI (Python)
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py
│   └── ioc_correlator/
│       ├── __init__.py
│       ├── api/
│       │   ├── routes.py       # Endpoints REST
│       │   └── schemas.py      # Pydantic models
│       ├── extractor.py        # Extracción de IOCs desde logs
│       ├── enricher.py         # Orquestador de conectores (asyncio)
│       ├── scorer.py           # Lógica de scoring 0-100
│       ├── ai_analyst.py       # Integración Claude API
│       ├── database.py         # SQLite con SQLModel
│       ├── connectors/
│       │   ├── base.py         # Clase abstracta BaseConnector
│       │   ├── virustotal.py
│       │   ├── abuseipdb.py
│       │   ├── shodan.py
│       │   ├── otx.py
│       │   ├── malwarebazaar.py
│       │   ├── urlhaus.py
│       │   └── greynoise.py
│       └── utils/
│           ├── validators.py   # Detección de tipo IOC
│           └── cache.py        # Caché en memoria con TTL
│
└── frontend/                   # React + Vite + TypeScript
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

---

## Stack técnico

### Backend
- **Python 3.11+** con **FastAPI** (API REST asíncrona)
- **httpx** para llamadas HTTP asíncronas a las APIs de TI
- **SQLModel** (SQLite para dev)
- **python-dotenv** para variables de entorno
- **anthropic** SDK oficial para la integración con Claude
- **pytest** + **respx** para tests con mocks de APIs externas

### Frontend
- **React 18 + Vite + TypeScript**
- **Tailwind CSS** para estilos
- **shadcn/ui** para componentes (cards, badges, tablas)
- **Recharts** para gráficas del dashboard
- **TanStack Query** para gestión de estado y peticiones async

### Infraestructura
- **Docker + Docker Compose** (obligatorio según el enunciado)
- **Nginx** como reverse proxy y para servir el build de React
- **Hetzner Cloud VPS** Ubuntu 24.04 (obligatorio según el enunciado)
- Dominio propio o subdominio (suma puntos en la evaluación)

---

## API REST — Endpoints

```
POST /api/scan
  Body: { "ioc": "1.2.3.4" }  |  multipart/form-data con fichero de logs
  Response: ScanResult con score, resultados por fuente y resumen IA

GET  /api/history
  Response: Lista de los últimos N escaneos almacenados en BD

GET  /api/history/{scan_id}
  Response: Detalle completo de un escaneo anterior

GET  /api/health
  Response: { "status": "ok", "version": "1.0.0" }

GET  /api/sources
  Response: Lista de conectores con su estado (activo/sin API key)
```

---

## Módulo de IA Generativa — ai_analyst.py

Este es el módulo diferenciador del proyecto. Tras consolidar los resultados de todos los conectores, se llama a Claude para generar un análisis ejecutivo en lenguaje natural.

### Comportamiento esperado

```
Input:  dict consolidado con resultados de todos los conectores + score calculado
Output: string con análisis ejecutivo en español (3-5 frases)

Ejemplo de output:
"La IP 185.220.101.45 ha sido clasificada como CRÍTICA con un score de 87/100.
VirusTotal registra detecciones activas en 23 de 87 motores antivirus.
AbuseIPDB acumula 142 reportes en los últimos 30 días, principalmente asociados
a tráfico Tor y escaneo masivo de puertos. Shodan confirma los puertos 22 y 9001
abiertos, patrón consistente con un nodo de salida Tor. Recomendación: bloquear
en firewall perimetral y revisar logs internos en busca de conexiones hacia
esta IP en las últimas 72 horas."
```

### Instrucciones de implementación

- Usar el SDK oficial: `from anthropic import Anthropic`
- Modelo: `claude-sonnet-4-20250514`
- System prompt: analista experto en Threat Intelligence y ciberseguridad blue team
- Si la llamada falla (timeout, error API), devolver fallback con datos crudos, nunca romper la respuesta
- API key desde variable de entorno `ANTHROPIC_API_KEY`

---

## Dashboard Web — Requisitos de UI

El panel debe mostrar:

1. **Barra de búsqueda central** — input de texto para IOC + botón de upload para fichero de logs
2. **Threat Score card** — número grande (0-100) con color dinámico:
   - Rojo: CRÍTICO (81-100)
   - Naranja: MALICIOSO (51-80)
   - Amarillo: SOSPECHOSO (21-50)
   - Verde: LIMPIO (0-20)
3. **Tabla de resultados por fuente** — una fila por conector: nombre, veredicto, dato clave, badge de color
4. **Bloque de análisis IA** — card con el texto generado por Claude con icono distintivo
5. **Historial** — lista de últimos IOCs consultados con score y timestamp (página separada o sidebar)
6. **Estado de fuentes** — indicador de qué conectores están activos

---

## Reglas de Scoring

Score acumulativo 0-100 (con tope en 100):

| Condición | Puntos |
|---|---|
| VT: >5 engines detectan | +30 |
| VT: 1-5 engines detectan | +15 |
| AbuseIPDB confidence >80% | +40 |
| AbuseIPDB confidence 50-80% | +25 |
| Shodan: puerto sensible abierto (22/3389/445/1433/4444) | +10 c/u, máx +30 |
| OTX: presente en pulsos activos | +20 |
| MalwareBazaar: hash conocido | +40 |
| GreyNoise: clasificado malicious | +30 |
| GreyNoise: clasificado benign | -10 |

---

## Variables de entorno

```dotenv
# Threat Intelligence
VT_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=
GREYNOISE_API_KEY=

# IA Generativa (obligatorio)
ANTHROPIC_API_KEY=

# Backend
DATABASE_URL=sqlite:///./ioc_correlator.db
REQUEST_TIMEOUT=10
MAX_CONCURRENT_REQUESTS=5
CACHE_TTL_SECONDS=3600

# Frontend (usado en build)
VITE_API_BASE_URL=http://localhost:8000
```

---

## Orden de construcción — SEGUIR ESTE ORDEN

1. **Setup inicial:** estructura de carpetas, `.gitignore`, `.env.example`, `README.md`
2. **Backend base:** FastAPI con `/api/health` funcionando
3. **Validators:** detección de tipo IOC (IPv4/IPv6, MD5/SHA1/SHA256, FQDN, URL)
4. **Extractor:** parseo de logs y extracción de IOCs únicos por regex
5. **Database:** modelo `ScanResult` con SQLModel
6. **Conector base:** clase abstracta `BaseConnector`
7. **Conector VirusTotal:** primer conector real con manejo de rate limit
8. **Conector AbuseIPDB**
9. **Scorer:** lógica de puntuación con VT + AbuseIPDB
10. **Endpoint `/api/scan`:** funcional con VT + AbuseIPDB + score + guardado en BD
11. **Módulo ai_analyst.py:** integración Claude API con fallback
12. **Frontend base:** React + Vite + Tailwind, SearchBar + ThreatScore card
13. **Frontend completo:** ResultsTable + AiSummary + HistoryList
14. **Conectores restantes:** Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise
15. **Caché:** evitar peticiones duplicadas en la misma sesión
16. **Docker:** Dockerfile backend + Dockerfile frontend + docker-compose.yml
17. **deploy.sh:** script de despliegue automatizado para Hetzner Ubuntu 24.04
18. **Tests:** pytest con mocks (respx) de APIs externas
19. **Pulido:** loading states en frontend, manejo de errores, favicon, meta tags

---

## Despliegue en Hetzner

El `deploy.sh` debe ejecutar en orden sobre un VPS Ubuntu 24.04 limpio:

```bash
apt update && apt upgrade -y
curl -fsSL https://get.docker.com | sh
git clone https://github.com/danierod01/ioc-correlator.git /opt/ioc-correlator
cd /opt/ioc-correlator
cp .env.example .env
# El usuario edita .env con sus API keys antes de continuar
docker compose up -d --build
curl http://localhost/api/health
```

El `docker-compose.yml` expone el puerto 80 (Nginx sirviendo React + proxy al backend en 8000). Para HTTPS con dominio propio, añadir Certbot/Let's Encrypt.

---

## Reglas del agente

### SIEMPRE

- Construir **un módulo a la vez** en el orden indicado. No saltar pasos.
- Comentar el código cuando la lógica no sea obvia.
- Indicar `pip install` / `npm install` al añadir dependencias y actualizar `requirements.txt` / `package.json`.
- Añadir cada nueva variable de entorno al `.env.example`.
- Usar `async/await` en todos los conectores HTTP (httpx.AsyncClient).
- Gestionar errores HTTP: timeouts, 429, 403, respuestas vacías. Nunca propagar excepciones sin controlar.
- Si detectas un bug o antipatrón en código existente, señalarlo aunque no te lo pidan.

### NUNCA

- Hardcodear API keys en el código.
- Generar el proyecto completo de golpe.
- Omitir manejo de errores en llamadas HTTP externas.
- Usar CSS inline masivo (Tailwind + shadcn/ui para todo).
- Asumir que las APIs externas siempre responden con datos válidos.

---

## Notas adicionales

- **Rate limits:** VirusTotal free = 4 req/min. Para logs con múltiples IOCs, implementar cola con delay.
- **Formatos de log soportados por el extractor (prioridad):**
  1. Formato libre / genérico — regex sobre cualquier línea
  2. Apache/Nginx access log
  3. Syslog estándar
  4. CSV exportado de Windows Event Log
  5. JSON lines
- **La herramienta debe funcionar** en cualquier Linux moderno con Docker instalado y ser accesible desde internet vía Hetzner.

---

## Bóveda Obsidian — "Bluecho"

### Para qué sirve en este proyecto

La bóveda Obsidian `Bluecho` es el **diario de desarrollo vivo** del proyecto. Su propósito principal es que, cuando llegue el momento de entregar el informe PDF (20% de la nota), el contenido ya esté prácticamente escrito — solo habrá que maquetar.

El enunciado exige un PDF con 10 secciones incluyendo evidencias fase a fase, diagramas, arquitectura y un roadmap visual. Si documentas cada módulo en Obsidian mientras lo construyes, el informe se genera casi solo.

### Cuándo escribir en Obsidian

**El agente debe indicarte qué anotar en Obsidian al terminar cada módulo del orden de construcción.** No hace falta que escribas durante el desarrollo; es una tarea de 5 minutos al terminar cada paso: pega el comando que funcionó, haz una captura de pantalla, anota qué problema encontraste y cómo lo resolviste.

### Estructura de carpetas en la bóveda

Crea esta estructura dentro de `Bluecho/`:

```
Bluecho/
└── IOC-Correlator/
    ├── 00 - Resumen Ejecutivo.md
    ├── 01 - Descripción del Problema.md
    ├── 02 - Arquitectura Técnica.md
    ├── 03 - Diario de Desarrollo/
    │   ├── Fase 01 - Setup inicial.md
    │   ├── Fase 02 - Backend base.md
    │   ├── Fase 03 - Validators y Extractor.md
    │   ├── Fase 04 - Conectores TI.md
    │   ├── Fase 05 - IA Generativa.md
    │   ├── Fase 06 - Frontend.md
    │   ├── Fase 07 - Docker y Despliegue.md
    │   └── Fase 08 - Tests y Pulido.md
    ├── 04 - Guía de Despliegue.md
    ├── 05 - Manual de Uso.md
    ├── 06 - Conclusiones y Lecciones.md
    └── 07 - Roadmap Práctica 2.md
```

### Plantilla para cada nota de fase

Al terminar cada módulo del orden de construcción, crea o actualiza su nota de fase con esta plantilla:

```markdown
# Fase XX — [Nombre del módulo]

## Qué se ha construido
[Descripción breve de lo implementado]

## Decisiones técnicas tomadas
[Por qué se eligió esta aproximación vs otras]

## Comandos clave utilizados
```bash
[comandos]
```

## Problemas encontrados y soluciones
| Problema | Solución |
|---|---|
| | |

## Evidencias
![[captura_XX.png]]

## Estado al terminar esta fase
- [ ] Tests pasando
- [ ] Variables de entorno documentadas en .env.example
- [ ] Commit realizado con mensaje convencional
```

### Mapeo Obsidian → Informe PDF

Cada nota de Obsidian corresponde directamente a una sección del PDF requerido:

| Sección PDF requerida | Nota en Obsidian |
|---|---|
| 1. Portada | (se genera al maquetar) |
| 2. Índice | (se genera al maquetar) |
| 3. Resumen ejecutivo | `00 - Resumen Ejecutivo.md` |
| 4. Descripción del problema | `01 - Descripción del Problema.md` |
| 5. Arquitectura técnica con diagrama | `02 - Arquitectura Técnica.md` |
| 6. Proceso de desarrollo con evidencias | `03 - Diario de Desarrollo/` (todas las fases) |
| 7. Guía de despliegue | `04 - Guía de Despliegue.md` |
| 8. Manual de uso | `05 - Manual de Uso.md` |
| 9. Conclusiones y lecciones aprendidas | `06 - Conclusiones y Lecciones.md` |
| 10. Road map de mejora | `07 - Roadmap Práctica 2.md` |

### Qué debe recordar el agente

- Al terminar cada módulo del orden de construcción, **indicar al desarrollador qué anotar** en la nota de fase correspondiente: comandos usados, decisiones tomadas, posibles capturas de pantalla a hacer.
- Al terminar el módulo de Docker y despliegue (paso 17), **dictar el contenido** de `04 - Guía de Despliegue.md` con los pasos exactos que se han ejecutado.
- Al terminar el proyecto, **generar el contenido** de `05 - Manual de Uso.md` con ejemplos reales de uso de la herramienta.
- El `07 - Roadmap Práctica 2.md` se redacta al final con al menos 5 nuevas funcionalidades planificadas, mejoras de rendimiento, seguridad e integraciones, con estimación de tiempo para cada una.
