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

---

## ⚙️ Protocolo de trabajo y continuidad entre ordenadores (LEER SIEMPRE)

> Este proyecto se desarrolla en **varios ordenadores**, sincronizados vía git
> (push desde uno, pull en otro). El `CLAUDE.md` es la **única memoria que viaja
> entre máquinas** — la memoria local del asistente NO se sincroniza. Por tanto:

**Reglas permanentes para el asistente (Claude):**

1. **Todo cambio o desarrollo se anota en este `CLAUDE.md`** antes de terminar la
   sesión: qué se ha implementado, dónde (rutas/ficheros), estado de tests, y qué
   queda pendiente. Actualizar las tablas de estado (roadmap, plan P3) y el
   "Registro de sesiones" de abajo.
2. **Al empezar cada sesión**, leer este fichero primero (sobre todo "Trabajo
   pendiente" y el último registro de sesión) para saber dónde se retoma.
3. **Commit + push al terminar** en la rama de trabajo activa, para que el otro
   ordenador reciba tanto el código como el contexto actualizado.
4. **Lo que Claude NO pueda hacer en la máquina actual, se anota explícitamente**
   en "Trabajo pendiente (manual / otra máquina)" para hacerlo donde sí se pueda.

**Qué puede hacer Claude en esta máquina cloud:** editar código backend/frontend,
ejecutar `pytest`, compilar el frontend (`npm run build`), crear/editar las notas
de Obsidian (son ficheros `.md` bajo `Bluecho/`), y commit/push.

**Qué NO puede hacer Claude aquí (requiere acción manual del desarrollador):**
capturas de pantalla y grabación del vídeo, ejecutar cosas en el VPS Hetzner por
SSH, verificar el navegador/UI real, y añadir imágenes/PNG a las notas de Obsidian.

### Trabajo pendiente (dónde seguimos)

Estado a fecha 2026-09-28 (rama `feat/invite-tokens`):

- [x] ~~**Verificar arranque en limpio** `docker compose up --build` (criterio nº1
      de P3, 30% de la nota)~~ ✅ (2026-09-29): verificado en Kali sobre la rama
      `design-soc-dashboard` (5 servicios sanos + `/api/health` ok + escaneo real de
      principio a fin). Ver registro de sesión y `Fase P3-04`.
- [x] ~~**Numerar requisitos** RF-/RNF- de la P1 y montar la **matriz de trazabilidad**~~ ✅ (2026-09-24): `Bluecho/IOC-Correlator/08 - Requisitos y Matriz de Trazabilidad.md` (12 RF + 7 RNF derivados del Informe P1 + mejoras, mapeados a código y tests). Falta rellenar minuto del vídeo y medir latencia (RNF-07).
- [x] ~~**Documentar en Obsidian**: F4, F5, GreyNoise, F7, limpieza de tests. Nota
      "Fase P3" en `03 - Diario de Desarrollo/`~~ ✅ (2026-09-24):
      `Fase P3-01 - Correcciones, GreyNoise, PDF y Webhooks.md`.
- [x] ~~Redactar apartado de **seguridad** (STRIDE)~~ ✅ (2026-09-28):
      `Bluecho/IOC-Correlator/09 - Seguridad del Producto.md` (STRIDE + secretos,
      auth, validación, dependencias, datos personales, y gaps). Auditoría de
      dependencias ✅ 2026-09-25: `pip-audit` 31→0 y `npm audit` 2→0.
      **Gaps a cerrar antes de entregar:** CORS `*`→dominio en prod; verificar que el
      historial de git no tiene secretos reales; (opcional) retención del historial.
- [x] ~~Rediseño UI pendiente~~ ✅ (2026-09-28): `AiSummary` renderiza Markdown,
      `SearchBar` placeholder rotatorio, `SourcesStatus` con GreyNoise visible.
      Pendiente menor: ajustes finales `Dashboard` (baja prioridad).
- [x] ~~README instala-desde-cero~~ ✅ (2026-09-28): actualizado a 18 fuentes
      (GreyNoise + URLScan), documentados endpoint PDF, alertas webhook y variables
      nuevas. Gap CORS mitigado (limpieza de espacios + guía en .env.example).
- [x] ~~Sistema de invitaciones + aislamiento de sesiones + sesión con nombre~~ ✅
      (2026-09-28, rama `feat/invite-tokens`): `POST /api/auth/invite` (nombre
      obligatorio, gated by `ADMIN_SECRET`), tokens en tabla `ApiKey`,
      `ScanResult.api_key` por usuario, historial y detalle filtrados por token
      (ajeno → 404), `GET /api/auth/me` + nombre en la UI, barra lateral plegable.
      Nota: `Fase P3-02`. **Pendiente en Kali: `pytest` (cambian firmas de
      `save_scan`/`get_history`/`require_api_key`) + build de frontend, luego mergear
      `feat/invite-tokens` a `main`.**
- [ ] Antes de entregar: tag `v1.0-practica3`.
- [ ] Cerrar en prod: `CORS_ORIGINS=https://blueecho.es` en el `.env` del VPS.
- [~] **Secretos en historial git** (2026-09-29): escaneado (`.env`, claves privadas,
      `.db/.pem/.key`, valores de API keys) → **limpio**, salvo que la clave `miapi2026`
      aparecía en una nota de Obsidian (ya **redactada** en HEAD, pero **sigue en el
      historial** de la rama). ACCIÓN [tú]: si `miapi2026` es/era una clave real,
      **cámbiala en el `.env` del VPS**; si quieres un historial 100% limpio, reescribir
      historial (git filter-repo) antes del tag — para una clave dev débil, rotar suele bastar.

### ⚠️ La memoria de la P3 es un documento NUEVO (no se reutiliza la de P1)

El enunciado de la P3 (Entregable 1) exige una **memoria técnica nueva** con su
**estructura obligatoria de 13 apartados** (varios inexistentes en la P1: Seguridad,
Matriz de trazabilidad, Uso de IA, Reparto del trabajo). El fichero se llama
`P3_GrupoXX_Memoria.pdf`. La memoria de la P1 (`Informe-BlueEcho.md`) es **material de
entrada** para el apartado 3 "Punto de partida", no el entregable.

Implicación para Obsidian: las notas nuevas de la P3 (`08 - Requisitos y Matriz…`,
`Fase P3-…`, y las de seguridad/pruebas que falten) alimentan la **memoria P3**, no la
tabla de mapeo antigua (que corresponde a la memoria de 10 apartados de la P1).
Al maquetar la memoria P3, seguir el orden de 13 apartados de la sección "Estructura
obligatoria de la memoria" de abajo.

### Grupo = 1 persona (el desarrollador)

El "grupo" de esta práctica es **una sola persona**. Implicaciones:
- Apartado 11 (Reparto del trabajo): una fila (el desarrollador) + Claude Code
  declarado como herramienta en el apartado 12.
- Vídeo: lo graba él solo; el "que intervengan todos los integrantes" se cumple con
  su intervención.
- Historial de un solo autor **no penaliza** aquí (es un grupo de uno).
- **Acción manual pendiente:** si el grupo quedó en una persona por bajas, comunicarlo
  al equipo docente (el enunciado ajusta el alcance esperado según nº de integrantes).

### Trabajo pendiente (manual / otra máquina)

- [ ] Capturas de pantalla de cada funcionalidad para la memoria y Obsidian.
- [ ] Grabar el vídeo de demostración (≥10 min) sobre el producto real.
- [ ] Probar el despliegue real en el VPS Hetzner (SSH) si se actualiza producción.
- [ ] (Si aplica) Comunicar al equipo docente que el grupo quedó en 1 persona.

### Registro de sesiones

- **2026-09-24** (cloud, rama `claude/awesome-franklin-79do5a`): leído enunciado
  P3 y anotado en CLAUDE.md. Arreglados 6 tests rojos + bug MalwareBazaar.
  Implementado GreyNoise (conector+scoring+tests). Implementado F4 (export PDF,
  fpdf2) y F5 (alertas webhook). De 6 tests rojos → **262 verdes**. Frontend
  compila. Todo commiteado y pusheado. Creada la matriz de trazabilidad
  (`08 - Requisitos y Matriz de Trazabilidad.md`) con requisitos RF/RNF
  numerados. Documentada la nota Obsidian "Fase P3-01". Confirmado que la
  memoria de la P3 es un documento NUEVO (13 apartados), no la de la P1.
  **Pendiente inmediato (otra máquina): verificar `docker compose`.**
- **2026-09-25** (cloud, misma rama): hardening de dependencias. `pip-audit` 31→0
  y `npm audit` 2→0. Subidas fastapi→0.141.1 (+starlette 1.7.0), python-multipart
  →0.0.32, python-dotenv→1.2.3, scapy→2.7.0, pytest→9.0.3/pytest-asyncio→1.4.0,
  react-router-dom→7.18.4. 262 tests verdes y build de frontend OK tras cada tanda.
  Commiteado y pusheado. **Siguiente aquí: redactar apartado de seguridad (STRIDE).**
  **OJO despliegue:** el salto fastapi 0.115→0.141 y react-router 6→7 hace aún más
  importante verificar `docker compose up --build` en limpio (RNF-03).
- **2026-09-28** (cloud, misma rama): rediseño/pulido UI. AiSummary ahora renderiza
  Markdown (antes mostraba ## y ** en crudo). Corregido bug: GreyNoise no aparecía en
  SourcesStatus (faltaba etiqueta+grupo). SearchBar: placeholder rota en vivo. Build
  de frontend verificado, commiteado y pusheado. Login ya estaba bien (no tocado).
  Añadido el pulido de UI a la nota Obsidian Fase P3-01 (addendum). Redactado el
  apartado de **seguridad STRIDE** (`09 - Seguridad del Producto.md`).
  **Sigue pendiente (tú): verificar `docker compose`. Siguiente aquí: README
  instala-desde-cero y, al final, tag `v1.0-practica3`. Cerrar gaps de seguridad
  (CORS en prod, revisar historial git por secretos).**
- **2026-09-28** (Windows, rama `feat/invite-tokens`): sistema multiusuario completo.
  (1) **Invitaciones**: `POST /api/auth/invite` genera tokens per-usuario con nombre
  obligatorio (requiere `ADMIN_SECRET`), guardados en tabla `ApiKey`. Página `/invite`.
  (2) **Aislamiento de sesiones**: `ScanResult.api_key` almacena el token creador;
  historial y detalle filtrados por token (escaneo ajeno → 404). Verificado
  inspeccionando la BD (no era bug: cada clave ve solo lo suyo). (3) **Sesión con
  nombre**: `GET /api/auth/me` devuelve el nombre; el frontend lo muestra en el menú
  (nombre + iniciales). `queryClient.clear()` en login/logout evita datos cacheados del
  usuario anterior. (4) **Barra lateral de historial plegable** en el dashboard (estado
  en localStorage). Nota Obsidian: `Fase P3-02 - Invitaciones, sesiones aisladas y
  UI.md`. **OJO: la BD necesita recrearse (`docker compose down -v`) por la columna
  `api_key` — SQLModel no migra en caliente. En local usar el override
  `-f docker-compose.dev.yml` (si no, Nginx crashea por el cert de blueecho.es).**
  **NO verificado esta sesión (Windows sin npm): `pytest` en Kali (cambian firmas de
  `save_scan`/`get_history` y `require_api_key`) y build de frontend vía Docker.**
  **Siguiente: verificar tests + build en Kali, luego mergear `feat/invite-tokens` a `main`.**
- **2026-09-29** (cloud, rama `feat/invite-tokens`): revisado el sistema de invitaciones
  y **verificados los tests que quedaron pendientes → 262 seguían verdes** (los cambios de
  firma no rompieron nada). **Añadidos 8 tests nuevos** (`tests/test_auth_invite.py`):
  invitación (503 sin `ADMIN_SECRET`, 403 secreto malo, 422 sin nombre, token usable),
  `/auth/me`, `/auth/verify` (master + token BD + inválida) y **aislamiento de historial
  por token** (cada token ve solo lo suyo; escaneo ajeno → 404). Total **270 verdes**.
  Actualizados matriz de trazabilidad (MJ-AUTH) y STRIDE (Repudiation con atribución por
  token; §4 control de acceso con tokens personales; gaps revisados). Todo commiteado y
  pusheado en `feat/invite-tokens`.
  **QUÉ FALTA (estado al 29/09):** [tú] `docker compose` en limpio + build frontend vía
  Docker en Kali; [tú] capturas + vídeo + memoria PDF; [decisión] mergear
  `feat/invite-tokens` a `main`; [prod] `CORS_ORIGINS` + recrear BD (`down -v`) por la
  columna `api_key`; [entrega] revisar historial git por secretos + tag `v1.0-practica3`.
- **2026-09-29** (cloud, `feat/invite-tokens`): decisión de dejar la app "a nivel
  producción" (última entrega, hay días). Escaneado historial git de secretos → limpio
  (salvo `miapi2026` redactado). Empezado el pulido en tandas ("todo, yo ordeno").
  **Tanda 1 (seguridad, gestión de tokens):** revocación + caducidad opcional de tokens.
  Backend: `ApiKey.active`/`expires_at`, `is_valid_api_key` valida estado+caducidad,
  `list_api_keys`/`revoke_api_key`, endpoints `POST /auth/tokens` (listar, key
  enmascarada) y `POST /auth/revoke` (ambos con `ADMIN_SECRET`); `/auth/invite` acepta
  `expires_in_days`. Frontend: panel "Gestionar tokens" en `/invite` (listar/revocar +
  campo caducidad). +7 tests → **277 verdes**; build frontend OK. STRIDE/matriz al día.
  **PENDIENTE en tandas siguientes:** CI GitHub Actions + healthchecks + LICENSE;
  UX (404, error boundary, favicon/meta, toasts); tests de frontend (Vitest).
  **OJO migración:** `ApiKey` ganó columnas → recrear BD (`down -v`) en el próximo despliegue.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Tanda 2 (seguridad, resto):** las
  cabeceras de seguridad de producción (`nginx.conf`) YA existían (HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CSP); **añadidas también al
  `nginx.dev.conf`** (todas salvo HSTS) para que se vean en la demo local. Añadido **log
  de auditoría** (`ioc_correlator/audit.py`, logger `blueecho.audit`): registra escaneos,
  invitaciones, revocaciones y accesos fallidos con token enmascarado; enganchado en
  `routes._run_scan` y en `auth.py`. +4 tests (`test_audit.py`) → **281 verdes**; build OK.
  STRIDE actualizado (Tampering=cabeceras, Repudiation=auditoría). CORS se deja
  configurable (default `*` solo dev; cierre real = `.env` de prod, ya documentado).
- **2026-09-29** (cloud, `feat/invite-tokens`) **Tanda 3 (CI/CD + producción):**
  healthchecks en `docker-compose.yml` YA existían (backend + `depends_on:
  service_healthy`). Añadido **CI de GitHub Actions** (`.github/workflows/ci.yml`):
  job backend (pytest + pip-audit) y job frontend (npm ci + build + npm audit); las
  auditorías con `continue-on-error` (avisan, no bloquean). Añadido **LICENSE** (MIT) +
  badges de CI y licencia en el README + secciones "Integración continua" y "Licencia".
  YAML validado. **PENDIENTE en tandas siguientes:** UX (404, error boundary,
  favicon/meta, toasts); tests de frontend (Vitest).
- **2026-09-29** (cloud, `feat/invite-tokens`) **Tanda 4 (UX):** corregido bug real:
  `index.html` referenciaba `/favicon.svg` pero `public/` estaba vacío (404) → creado
  `frontend/public/favicon.svg` (radar azul). Añadidas meta OG/Twitter + theme-color.
  Nueva página **404** (`pages/NotFound.tsx` + ruta `*` en App). **Error boundary**
  global (`components/ErrorBoundary.tsx`) envolviendo App en `main.tsx` (evita pantalla
  en blanco ante error de render, con botón recargar). Build OK. **PENDIENTE:** toasts
  (queda como micro-paso; toca muchos puntos de error inline, mejor con verificación
  visual); tests de frontend (Vitest, Tanda 5). Falta también consolidar una nota
  Obsidian "Fase P3-03" con las tandas 1-4 (hardening a producción) para la memoria.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Tanda 5 (tests de frontend):** montado
  **Vitest + Testing Library + jsdom** (`vitest.config.ts`, `src/test/setup.ts`, script
  `npm test`). 6 tests: `lib/utils` (cn, VERDICT_LABEL, formatDate), `AiSummary` (renderiza
  Markdown, sin `##`/`**` crudos) y `NotFound`. Tests excluidos del `tsc -b` de producción
  vía `tsconfig.app.json`. Añadido paso Vitest al CI. Build OK. **Deuda anotada:** (1)
  `react-markdown` está en dependencies pero AiSummary usa un mini-parser propio (revisar
  si algún otro componente lo usa; si no, se puede quitar). (2) El tooling de test dejó **2
  vulnerabilidades moderate DEV-ONLY** en `@vitest/mocker` (solo se corrigen en vitest 5,
  que arrastraría Vite 7); no afectan al producto y el CI usa `--audit-level=high`, así que
  no bloquean. **CON ESTO LAS 5 TANDAS DE HARDENING ESTÁN COMPLETAS.** Pendiente: nota
  Obsidian consolidada (Fase P3-03) + toasts (micro-paso opcional).
- **2026-09-29** (cloud, `feat/invite-tokens`) **Cierre del bloque:** creada la nota
  Obsidian **`Fase P3-03 - Hardening a produccion...`** consolidando las 5 tandas (para la
  memoria). Añadidos **toasts** (`components/Toast.tsx`: `ToastProvider` + `useToast`,
  auto-cierre 4s), envueltos en `main.tsx`, y usados para feedback transitorio: descarga de
  PDF (éxito/error) en Dashboard, y copiar/revocar token en `/invite`. Los errores en línea
  contextuales (login, formulario invite, errores de escaneo) se mantienen. Build OK, 6
  tests FE verdes. **BLOQUE DE HARDENING TERMINADO.** Pendiente solo del desarrollador:
  verificar en Kali (`docker compose`, `pytest`=281, `npm test`=6), mergear
  `feat/invite-tokens`→`main`, y entregables manuales (capturas/vídeo/memoria/tag).
- **2026-09-29** (cloud, **rama nueva `design-soc-dashboard`**, parte de `feat/invite-tokens`):
  **rediseño visual "SOC" (experimental, NO mergeado).** El usuario pidió una identidad tipo
  consola SOC / data-desk (paleta teal/cian sobre negro azulado, inspirada en una plantilla de
  landing de ciberseguridad) manteniendo el **layout de dashboard** existente. Cambios (solo
  frontend, sin tocar lógica ni API): (1) `index.css` — tokens SOC (`--soc-bg #05080e`,
  `--soc-accent #2dd4bf`), textura de rejilla de consola + viñeta radial en `body` (CSS, sin
  imágenes de stock), scrollbar/selección teal, y clases de componente `.soc-panel`,
  `.soc-label`, `.stat-tile`, `.soc-ticks` (marcas de esquina HUD). (2) `tailwind.config.js` —
  añadida escala de color `accent` (teal). (3) Retematizadas superficies a teal manteniendo los
  **colores de veredicto** (rojo/naranja/amarillo/verde) y los **semánticos/categóricos** intactos
  (info azul en Toast, táctica "Execution" de MITRE, badges de tipo IOC en PCAP): `App` (header +
  micro-tira "OPERATIVO" + avatar), `SearchBar`, `ThreatScore` (marco de consola + `soc-ticks`),
  `ResultsTable` envuelta en `.soc-panel` con cabecera, `SourcesStatus` (píldoras teal),
  `AiSummary`, `EmptyState` (radar teal), `Dashboard` (toggle/pill/loading/PDF/sidebar), `Login`,
  `Invite`, y swaps de acento en `BulkScanPanel`/`GeoMap`/`PcapAnalysisView`/`History`/`NotFound`/
  `ErrorBoundary`/`SkeletonResults`. Botones teal → texto negro (contraste). **Build OK + 6 tests
  FE verdes.** Backend intacto (no ejecuté pytest: sin cambios en backend).
  **PENDIENTE (tú):** verlo en navegador real (`docker compose ... dev`), decidir si gusta y si
  se aplica; si sí → mergear `design/soc-dashboard` (o cherry-pick) sobre la rama que toque.
  Es puramente estético y aislado; si no convence, se descarta la rama sin afectar a nada.
  **OJO entrega P3:** un rediseño a días de la entrega es opcional/bajo riesgo — la regla de oro
  es "que funcione bien > que sea vistoso"; no bloquear la entrega por esto.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Cierre de roadmap — I2 + I3:** el usuario
  decidió cerrar el roadmap pendiente entero (R2/R3/I2/I3), en orden de riesgo ascendente.
  **I2 · Export a SIEM ✅:** `siem_export.py` (STIX 2.1 con indicador + `attack-pattern`
  MITRE + relaciones e IDs deterministas; evento MISP; Python puro, sin deps nuevas).
  Endpoint `GET /api/history/{id}/export?format=stix|misp` (aislamiento por token → 404;
  formato inválido → 422). Frontend: `downloadScanExport` + botones STIX/MISP en el
  dashboard. 13 tests (`test_siem_export.py`) → **suite backend 294 verdes**; build FE OK;
  6 tests FE verdes. README actualizado (endpoint + manual). **I3 · Plugin de navegador ✅:**
  `browser-extension/` (Manifest V3): popup de escaneo, menú contextual (clic derecho sobre
  IOC), página de opciones (URL servidor + API key en `chrome.storage.sync`), icono radar
  teal SVG, README de instalación (Firefox/Chrome). Habla con `POST /api/scan/json`; usa
  `host_permissions` para no depender del CORS. Manifest validado (JSON OK).
  **PENDIENTE (tú):** cargar la extensión en un navegador real y probarla (yo no tengo
  navegador con extensiones aquí). **PENDIENTE roadmap:** R2 (PostgreSQL) y R3 (Celery+Redis)
  — los que tocan `docker compose`; se harán re-verificando el arranque limpio tras cada uno.
  Nota: durante esta sesión el clasificador de Bash estuvo caído un rato; I3 se escribió
  entero (solo ficheros) mientras tanto y se verificó al recuperarse el terminal.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Cierre de roadmap — R2 + R3 (¡ROADMAP COMPLETO!):**
  **R2 · PostgreSQL ✅:** servicio `db` (postgres:16-alpine) en compose con healthcheck +
  `depends_on: service_healthy`; backend → `postgresql+psycopg://`; driver `psycopg[binary]`;
  `pool_pre_ping`. **El código mantiene SQLite por defecto** (dev sin Docker + tests), así que
  la suite no cambió de backend. `.env.example` con `POSTGRES_*`. **R3 · Celery+Redis ✅:**
  `celery_app.py` (broker/result = Redis, `include=tasks`, eager por env para tests) +
  `tasks.py` (tarea `scan_ioc` = pipeline completo con su propia `Session(engine)`; por eso
  R2 va antes que R3: worker y API comparten la Postgres). Endpoints `POST /api/scan/async`
  y `GET /api/tasks/{id}`. Servicios `redis` + `worker` (mismo image del backend, `command:
  celery -A ioc_correlator.celery_app worker`) en compose. Deps `celery==5.4.0`/`redis==5.2.1`.
  6 tests (`test_tasks.py`, eager+mock, sin Redis real). **Suite backend: 300 verdes.** El
  escaneo síncrono clásico sigue intacto y no depende de la cola. README (sección async +
  nota de BD) y roadmap actualizados. **CON ESTO EL ROADMAP DEL INFORME P1 §8 QUEDA CERRADO
  salvo I2 que también se cerró hoy** (solo quedan como "trabajo futuro" ninguno de los que
  el usuario pidió — todos hechos).
  **⚠️ PENDIENTE (tú, requiere Docker; yo no levanto contenedores aquí):** verificar
  `docker compose up --build` en limpio con los 5 servicios (db/redis/worker/backend/frontend);
  el arranque limpio es el 30% de la nota. Recrear BD no aplica (Postgres nuevo desde cero).
  Probar el plugin I3 en un navegador real.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Tanda de seguridad — RBAC + rate limit por token:**
  el usuario pidió centrarse en seguridad tras cerrar el roadmap. (1) **Roles admin/analyst**:
  nueva columna `ApiKey.role` (default `analyst`); `create_api_key`/`get_api_key_role` en
  `database.py`. `invite` acepta `role` (valida admin|analyst → 422 si no); operaciones de
  administración (`invite`/`tokens`/`revoke`) ahora se autorizan por **token admin en la
  cabecera** (`_is_admin_key`: master key o rol admin) **o** por `ADMIN_SECRET` en el cuerpo
  (bootstrap) vía `_require_admin_access`. `GET /auth/me` devuelve nombre **+ rol**. (2)
  **Rate limiting por token**: `limiter._rate_key` usa `key:<sha256 corto>` si viene
  `X-API-Key`, si no `ip:<ip>` (login sigue por IP). (3) Frontend: selector de rol y badge
  admin en `/invite`, rol en el menú de usuario (`App.tsx`), tipos `MeResponse.role`/
  `TokenInfo.role`. +8 tests (`test_roles.py`) → **suite backend 308 verdes**; build FE OK +
  6 tests FE. README (tabla de roles + rate limit) y STRIDE (`09 - Seguridad…`: §4 RBAC,
  filas Spoofing/DoS/EoP, gaps — quitado el gap "sin RBAC") actualizados.
  **⚠️ MIGRACIÓN BD:** `ApiKey` ganó la columna `role` → en el próximo despliegue recrear la
  BD (`docker compose down -v`) o añadir la columna a mano; SQLModel no migra en caliente.
- **2026-09-29** (cloud, `feat/invite-tokens`) **Pivoting (entidades relacionadas):** nuevo
  `pivots.py` (función pura `extract_pivots`) que deriva IOCs relacionados de los resultados:
  dominio→IP (geolocation `resolved_ip`), IP→hostnames (shodan `hostnames`, ipinfo
  `hostname`, securitytrails `nearby_hostnames`), dominio→nameservers (rdap). Deduplica,
  valida tipo con `detect_ioc_type`, excluye el propio IOC, tope 6/fuente y 12 global.
  Campo `pivots: list[PivotEntity]` en `ScanResponse`, poblado en `_build_scan_response`.
  Frontend: componente `Pivots.tsx` (chips clicables agrupados por relación) en el
  Dashboard, cableado a `mutation.mutate({ioc})` → **escaneo encadenado**. Tipos
  `PivotEntity` + `ScanResponse.pivots` en el cliente. +7 tests (`test_pivots.py`) →
  **suite backend 315 verdes**; build FE OK + 6 tests. README (manual) actualizado.
  Nota: el detalle de historial (`ScanDetail.tsx`) aún no muestra pivotes (posible mejora
  menor); el flujo de escaneo encadenado vive en el Dashboard, que es donde se demuestra.
- **2026-09-29** (cloud, `design-soc-dashboard`) **MERGE: features + diseño en una rama.** El
  usuario quiere probar TODO junto (funcionalidades + rediseño SOC). Fusionado
  `feat/invite-tokens` dentro de `design-soc-dashboard`: el merge fue casi limpio (git
  auto-fusionó `App/Dashboard/Invite`; único conflicto real = este `CLAUDE.md`, resuelto
  conservando ambos historiales). Resultado: `design-soc-dashboard` = roadmap (I2/I3/R2/R3)
  + seguridad (RBAC + rate limit) + pivoting + **rediseño teal SOC**. `feat/invite-tokens`
  sigue con el diseño clásico (sin tocar). **⚠️ verificar en Kali** (`docker compose` con los
  5 servicios, `pytest`=315, `npm test`=6) — la migración de BD (`down -v`) aplica por las
  columnas nuevas de `ApiKey` y por el cambio a Postgres.
- **2026-09-29** (Kali → cloud, `design-soc-dashboard`) **¡ARRANQUE EN LIMPIO VERIFICADO!** El
  usuario levantó la rama fusionada en Kali con `docker compose ... down -v && up --build`:
  los **5 servicios arrancan** (db/redis *healthy*, backend *healthy*, worker *up*, frontend)
  y `curl /api/health` → `{"status":"ok","version":"1.0.0"}`. Escaneo real de `185.220.101.45`
  verificado de principio a fin con el look SOC: ThreatScore 70 MALICIOSO, tabla por fuente,
  análisis IA, **pivotes clicables**, geolocalización y botones STIX/MISP/PDF. **El criterio
  del 30% (instala y arranca desde cero por README) queda demostrado.** Nota Obsidian creada:
  `Fase P3-04 - Cierre de roadmap, seguridad avanzada, pivoting y diseño SOC.md`.
  **Ajuste de UI pedido por el usuario:** el botón de mostrar/ocultar historial no era
  intuitivo (estaba suelto junto a "ONLINE"). Reorganizado: el botón **"Ocultar"** ahora vive
  dentro del panel de historial (pegado a "Recientes"), y en la cabecera solo aparece un botón
  **"Historial"** cuando está oculto (para reabrirlo). El indicador "ONLINE" se mantiene.
  **Pendiente (tú):** solo cargar el plugin de navegador en Firefox/Chrome y probarlo.
- **2026-09-29** (cloud, `design-soc-dashboard`) **Fix UX del fallback de IA en PCAP.** El
  usuario vio que el "Análisis IA — tráfico de red" ponía *"Sin análisis de IA disponible"*.
  Diagnóstico: NO es un bug de código — es el **análisis local** (fallback heurístico), que
  salta cuando no hay `GROQ_API_KEY`/`ANTHROPIC_API_KEY` funcionando (mismas keys que el
  escaneo normal; el heurístico del IOC está mejor redactado y por eso no cantaba). Arreglado
  el **texto del fallback** en `_local_pcap_analysis` (`ai_analyst.py`): ya no se disculpa;
  sustituida la sección "Vector de ataque probable" (que decía "sin IA…") por **"Valoración
  del tráfico"** con heurística real (conexión top, HTTP sin cifrar, DNS/DGA), y el caso sin
  indicadores da una frase con confianza. +3 tests (`test_ai_analyst.py`) → **318 verdes**.
  **ACCIÓN [tú] para tener IA real (Groq/Claude) también en PCAP:** poner `GROQ_API_KEY`
  (tier gratuito) o `ANTHROPIC_API_KEY` en el `.env` (ya están en `.env.example`). Comprobar
  con `docker compose logs backend | grep ai_analyst` (si no hay warning = no hay key).
- **2026-09-30** (cloud, `design-soc-dashboard`) **Cierre del ÚLTIMO ítem del roadmap: F7.**
  Cotejado el roadmap completo del Informe P1 §8 (17 ítems: S1-S4, F1-F7, R1-R3, I1-I3):
  **16/17 estaban ya en código**; el único abierto era **F7**, cuyo entregable prometido no
  era código sino un **estudio comparativo + decisión** (Anthropic vs Ollama). Escrita la nota
  `10 - Estudio del Motor de IA (F7).md`: Ollama inviable en el CX23 (4 GB) sin degradar la
  calidad; se adoptó una **tercera opción**, Groq (Llama 3.3 70B) primario + Claude fallback +
  análisis heurístico local, en **cascada con degradación elegante**. Incluye tabla comparativa
  (calidad/coste/RAM/latencia/privacidad) y la justificación del cambio para la memoria P3
  (apts. 4 y 5). Tabla de roadmap del CLAUDE.md: F7 ⚠️→✅. **CON ESTO EL ROADMAP DEL INFORME P1
  §8 QUEDA 100% COMPLETO** (17/17). Solo documentación; sin cambios de código ni tests (siguen
  318 verdes). **Pendiente (tú):** (opcional) medir latencia real Groq vs Claude para el vídeo.
- **2026-09-30** (cloud, **rama nueva `feat/soc-watchlist-analytics`**, parte de
  `design-soc-dashboard`) **Funcionalidades SOC "gordas": B (watchlist + monitorización
  continua) + D (dashboard analítico).** El usuario pidió features reales de SOC/SIEM en rama
  aparte para no mezclar con lo ya validado. **B ✅:** modelos `WatchedIoc` + `WatchAlert`
  (aislamiento por token); tarea Celery periódica `check_watchlist` (Beat cada
  `WATCHLIST_BEAT_SECONDS`, worker con `--beat`) que re-escanea (enrich+score, **sin IA**) los
  IOCs vencidos (`WATCHLIST_CHECK_INTERVAL_MINUTES`) y **crea alerta al cambiar el veredicto**
  (+ webhook best-effort); endpoints `/api/watchlist` (add/list/delete), `/watchlist/{id}/check`
  (manual), `/watchlist/alerts` (+`/{id}/ack`). Página `Watchlist.tsx` (añadir, tabla, panel de
  alertas, comprobar-ahora). **D ✅:** `get_stats()` (total, distribución veredicto/tipo, serie
  14d, top amenazas, resumen watchlist) + `GET /api/stats`; página `Analytics.tsx` con Recharts
  (área temporal, donut de veredictos con **colores de estado reservados**, barras de tipo con
  **un solo tono teal** para magnitud, top amenazas como tabla) — seguí la skill `dataviz`
  (estado=color reservado+leyenda; magnitud=tono único, sin paleta categórica que validar).
  Navegación: enlaces Watchlist/Analítica en `App`. +10 tests (`test_watchlist.py`) → **suite
  backend 328 verdes**; build FE OK + 6 tests. README (endpoints watchlist+stats) y `.env.example`
  (`WATCHLIST_*`) actualizados. **⚠️ MIGRACIÓN BD:** 2 tablas nuevas → recrear BD (`down -v`) al
  desplegar. **⚠️ compose:** el worker ahora lleva `--beat`. **Pendiente (tú):** verificar en Kali
  (`docker compose` con el beat corriendo; para demo, bajar `WATCHLIST_CHECK_INTERVAL_MINUTES`).

---

## Práctica 3 — "Del prototipo al producto" · ENTREGA 16/10/2026

> **Esta es la práctica activa.** Sustituye como objetivo inmediato a cualquier fecha anterior
> mencionada arriba (la del 25/05/2026 era de otra entrega). Enunciado leído el 2026-09-24.

### Idea central

Práctica 3 **no pide funcionalidades nuevas**: pide coger lo prometido en la Práctica 1 y
**demostrar que funciona de verdad**, instalable, probado y documentado. Regla de oro del
enunciado: *"un producto con menos funciones que funcionen bien puntúa más que uno con muchas
funciones a medias"*. Primero cerrar y probar lo existente; las mejoras (P2, rediseño UI) solo
suman si lo original ya está cumplido y demostrado. Nada de maquetas ni datos inventados: si una
integración externa no está disponible y se simula, **hay que declararlo** en memoria y vídeo.

### Qué significa "funcional" (criterio con más peso)

- Se instala **desde cero** siguiendo solo el README, en máquina limpia o en contenedores, sin ayuda del grupo.
- Los flujos principales van **de principio a fin** (entra input → se procesa → se muestra resultado real).
- Se comporta bien ante errores: input inválido, servicio caído o usuario sin permisos no tumban el sistema ni filtran info interna.
- Cada requisito de la P1 está **implementado y demostrado**, o justificado si se cambió/descartó.

### Los 3 entregables

1. **Memoria técnica** (PDF, 20-40 págs sin portada/índice/anexos, 11-12pt, paginada, con índice y capturas legibles con pie que indique qué requisito muestran). El material de Obsidian `Bluecho/` alimenta esto.
2. **Vídeo de demostración** (MP4, ≥10 min — mínimo estricto; recomendado ≤20 —, 1080p rec./720p mín., audio claro). Sobre el **producto real desplegado desde el repo**, no diapositivas. Cortes solo para esperas largas y **señalados en pantalla**; un corte que oculte un fallo = falta grave. Se valora que intervengan todos los integrantes. Alojar en YouTube "no listado"/Drive y **comprobar el enlace en incógnito**.
3. **Repositorio GitHub** (público o privado; si privado, dar lectura al equipo docente).

### Estructura obligatoria de la memoria (no suprimir apartados)

1. Portada (producto, grupo, integrantes, fecha, enlace repo, enlace vídeo)
2. Resumen ejecutivo (máx. 1 pág)
3. Punto de partida (resumen P1, feedback recibido, tabla de clasificación inicial de requisitos)
4. Requisitos (lista completa **numerada**; si se modificó/descartó: versión original, nueva y justificación)
5. Arquitectura y decisiones técnicas (diagrama de componentes, tecnologías y por qué, cambios vs P1)
6. Funcionalidades implementadas (cada una con capturas, cómo se usa, qué requisitos cubre)
7. **Seguridad del producto** (ver abajo)
8. Pruebas y evidencias (plan, casos, resultados, y **pruebas que fallaron con explicación**)
9. **Matriz de trazabilidad** (ver abajo)
10. Limitaciones y trabajo futuro
11. Reparto del trabajo (quién hizo qué + estimación de horas/persona)
12. Uso de herramientas de IA (declarar qué herramientas y para qué — **este proyecto usa Claude Code, hay que declararlo**)
13. Anexos (manual instalación ampliado, credenciales de prueba, glosario, referencias)

### Apartado de seguridad (es un máster de ciberseguridad — pesa)

Debe responder, como mínimo:
- **Modelo de amenazas** (STRIDE sencillo vale): qué activos protege y quién atacaría.
- **Gestión de secretos**: dónde están claves/tokens y cómo se evita que acaben en el repo (ni en el historial).
- **Autenticación y control de acceso**: cómo se autentica y qué puede hacer cada rol. → *ya tenemos X-API-Key + rate limiting (slowapi); documentarlo.*
- **Validación de entradas**: qué entra y cómo se valida. → *validators.py, extractor, tipos de IOC.*
- **Dependencias**: revisar vulnerabilidades conocidas con Dependabot / `pip-audit` / `npm audit` / Trivy y documentarlo.
- **Datos personales**: si se tratan, cuáles, finalidad, retención y protección. (Ojo: IPs pueden ser dato personal.)

### Matriz de trazabilidad (pieza clave de la corrección)

Una fila por requisito P1: `Requisito | Descripción | Estado final | Implementación (ruta) | Prueba (ID) | Evidencia (apartado memoria + minuto exacto del vídeo)`. La corrección va requisito por requisito siguiendo esta matriz.

### Clasificación inicial de cada requisito P1 (primera tarea)

Numerar como `RF-01…` / `RNF-01…` y etiquetar cada uno: **Cumplido** (verificar con pruebas) · **Parcial** (terminar y probar) · **Pendiente** (implementar) · **A revisar** (reformular con justificación) · **Descartado** (justificar por escrito, debe ser la excepción).

### Reglas del repositorio para la entrega

- **Ningún secreto real** en el código ni en el historial (contraseñas, API keys, tokens, certs). Si se subió alguno por error: **revocar y limpiar historial**, no basta con borrarlo en un commit nuevo.
- Marcar la versión entregada con el tag **`v1.0-practica3`** sobre el commit final. Se evalúa ese commit; lo posterior a la fecha límite no cuenta.
- Historial que refleje el trabajo del grupo (no un único commit final ni todo de un solo autor).
- README que permita instalar y ejecutar desde cero; `.env.example` con todas las variables y valores ficticios; Dockerfiles/compose; tests y cómo ejecutarlos; `.gitignore` que excluya secretos; licencia si es público.

### Criterios de evaluación (sobre 10)

| Criterio | Peso |
|---|---|
| Producto funcional (se instala por README, flujos de principio a fin, casos de error) | **30 %** |
| Cumplimiento de requisitos de la P1 (+ calidad de la justificación de cambios) | **20 %** |
| Seguridad y calidad técnica (seguridad del producto, calidad del código, pruebas, dependencias) | **15 %** |
| Memoria técnica | **15 %** |
| Vídeo de demostración | **10 %** |
| Repositorio y trabajo en equipo | **10 %** |

**No superan la práctica:** falta un entregable · vídeo < 10 min · el producto no llega a ejecutarse · plagio o demo manipulada.

### Implicaciones para el trabajo a partir de ahora

- **Prioridad #1 = que arranque desde cero por README** (docker compose) y que los flujos reales funcionen. Verificarlo en limpio.
- **Prioridad #2 = tests verdes.** El enunciado valora pruebas explícitamente; hoy hay 6 tests rojos en el backend → arreglarlos.
- **GreyNoise** figura en la doc/scoring pero **no existe en el código** → implementarlo o justificarlo como "A revisar/Descartado" (coherencia requisito↔implementación).
- Cada cosa que se toque debe quedar reflejada en la **matriz de trazabilidad** y en Obsidian (memoria).
- Antes del 16/10: código congelado 2-3 días antes, grabar vídeo y cerrar memoria sobre esa versión, y crear el tag `v1.0-practica3`.
- Declarar el uso de Claude Code en la memoria (apartado 12).

### Contexto de entregas (IMPORTANTE — leer)

La "Práctica 2" que aparece más abajo en este documento **no es** la Práctica 2 del máster (esa iba de otro tema, no de esta herramienta). Lo último que el profesor evaluó de Blue-Echo es lo que hay en `Bluecho/IOC-Correlator/Informe-BlueEcho.md` (la entrega de la Práctica 1). **Todo lo implementado por encima de ese informe son mejoras que el profesor aún no ha visto** y que se presentan por primera vez en esta Práctica 3. El roadmap de mejoras futuras está en la sección 8 de ese informe ("Road map de mejora"), y la P3 consiste en demostrar que ese roadmap se ha cumplido (+ requisitos originales de P1).

### Estado del roadmap prometido (Informe P1 §8) vs. implementado

Cotejado con el código el 2026-09-24:

| ID | Mejora prometida | Prioridad | Estado real |
|---|---|---|---|
| S1 | Auth X-API-Key | Alta | ✅ Hecho |
| S2 | Rate limiting por IP (slowapi) | Alta | ✅ Hecho |
| S3 | HTTPS Let's Encrypt | Alta | ✅ Hecho (blueecho.es) |
| S4 | Validación tamaño de fichero | Media | ✅ Hecho (`MAX_UPLOAD_SIZE_MB` → 413) |
| F1 | Bulk scan | Alta | ✅ Hecho |
| F2 | ThreatFox + más conectores | Alta | ✅ Hecho (superado: 11 conectores nuevos) |
| F3 | WHOIS/RDAP dominios | Media | ✅ Hecho (`rdap.py`) |
| F6 | Mapping MITRE ATT&CK | Media-Alta | ✅ Hecho |
| F7 | Estudio motor IA (Anthropic vs Ollama) | Alta | ✅ **Hecho** (2026-09-30): estudio comparativo + decisión justificada en `Bluecho/IOC-Correlator/10 - Estudio del Motor de IA (F7).md`. Ollama inviable en CX23 (4 GB) sin degradar calidad; adoptado **Groq (Llama 3.3 70B) primario + Claude fallback + análisis local** (cascada con degradación elegante). Cambio justificado para la memoria (apts. 4 y 5) |
| R1 | Paginación real en historial | Baja | ✅ Hecho (`items`/`total`) |
| I1 | API pública OpenAPI + auth | Media | ✅ Mayormente (`/docs` + auth) |
| **F4** | **Exportación a PDF del escaneo** | Media | ✅ **Hecho** (2026-09-24): `GET /api/history/{id}/pdf` con fpdf2 (Python puro, sin libs de sistema) + botón "Descargar PDF" en el dashboard |
| **F5** | **Alertas por webhook (Slack/Discord/Teams)** | Media | ✅ **Hecho** (2026-09-24): `alerting.py`, dispara webhook si `score >= ALERT_SCORE_THRESHOLD`; formatos slack/discord/teams/generic; best-effort (nunca rompe el escaneo). Config en `.env` |
| **R2** | **PostgreSQL** | Baja | ✅ **Hecho** (2026-09-29): servicio `db` (postgres:16-alpine) en `docker-compose.yml` con healthcheck + `depends_on: service_healthy`; backend apunta a `postgresql+psycopg://…`. Driver `psycopg[binary]` en requirements. El código mantiene SQLite por defecto (dev/tests). `.env.example` con `POSTGRES_*`. **⚠️ verificar `docker compose up --build` en Kali (yo no levanto Docker aquí).** Rama `feat/invite-tokens` |
| **R3** | **Celery + Redis** | Baja | ✅ **Hecho** (2026-09-29): `celery_app.py` + `tasks.py` (tarea `scan_ioc` = enrich→score→IA→guardar en su propia sesión de BD). Endpoints `POST /api/scan/async` (encola, → task_id) y `GET /api/tasks/{id}` (estado/resultado). Servicios `redis` + `worker` en compose. Deps `celery`/`redis`. Tests en modo eager/mockeado (6, `test_tasks.py`). **⚠️ verificar en Kali con Docker.** Rama `feat/invite-tokens` |
| **I2** | **Export a SIEM** | Baja | ✅ **Hecho** (2026-09-29): `siem_export.py` (STIX 2.1 + MISP, Python puro, IDs deterministas, attack-patterns MITRE). `GET /api/history/{id}/export?format=stix\|misp` con aislamiento por token + botones STIX/MISP en el dashboard. 13 tests (`test_siem_export.py`). Rama `feat/invite-tokens` |
| **I3** | **Plugin de navegador** | Baja | ✅ **Hecho** (2026-09-29): `browser-extension/` (Manifest V3): popup de escaneo, menú contextual sobre IOCs, página de opciones (URL + API key), README de instalación. Habla con `POST /api/scan/json`. Rama `feat/invite-tokens` |

**Extras construidos fuera del roadmap** (mejoras adicionales, el profesor no las ha visto): análisis PCAP (scapy), geolocalización con mapa, login UI, rediseño completo de la UI, **pivoting / entidades relacionadas** (escaneo encadenado), **watchlist + monitorización continua** (Celery Beat, alerta al cambiar el veredicto) y **dashboard analítico SOC** (Recharts) — rama `feat/soc-watchlist-analytics`.

### Plan de trabajo P3 (orden)

1. **Arreglar los 6 tests rojos del backend** (formato historial `{items,total}`, `get_history` tupla, análisis local en Markdown, MalwareBazaar malformado). — *primero de todo.*
2. ~~**Resolver GreyNoise**~~ ✅ **Hecho** (2026-09-24): implementado `greynoise.py` (Community API, manejo de 404 = no observada), regla de scoring (+30 malicious / −10 benign), registrado en enricher, añadido a `.env.example` (`GREYNOISE_API_KEY`) y al análisis local. 16 tests nuevos (`test_greynoise.py`). 18 conectores en total.
3. ~~**Cerrar el roadmap prometido**: F4 (export PDF) y F5 (webhooks)~~ ✅ **Hecho** (2026-09-24). Roadmap de prioridad Alta/Media completo salvo lo marcado como backlog.
4. **Documentar F7** (decisión de motor IA) y el resto para la matriz de trazabilidad; R2/R3/I2/I3 → "trabajo futuro" justificado.
5. Verificar instalación desde cero por README (`docker compose`), tests verdes, y preparar tag `v1.0-practica3`.

### Checklist previa a la entrega (del enunciado)

Memoria: apartados completos y en orden · portada con integrantes + enlaces · matriz cubre todos los requisitos · uso de IA declarado · fichero `P3_GrupoXX_Memoria.pdf`. Vídeo: ≥10 min · producto real, cada requisito con su minuto en la matriz · enlace funciona en incógnito. Repo: README instala desde cero · tag `v1.0-practica3` · sin secretos reales (ni en historial) · acceso docente si es privado. Producto: alguien ajeno lo ha instalado siguiendo el README.

---

## Estado actual del proyecto

> **Actualizar esta sección al final de cada sesión.**

### Rama activa
`feat/invite-tokens` — sistema multiusuario en pruebas. Se mergeará a `main` cuando
pasen los tests y el build en Kali. El resto del desarrollo está en `main`.

### Qué hay implementado

**Práctica 1** (base de `main`):
- 7 conectores: VirusTotal, AbuseIPDB, Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise
- Scoring 0-100, 4 veredictos (LIMPIO / SOSPECHOSO / MALICIOSO / CRÍTICO)
- Análisis IA con Claude (AsyncAnthropic)
- Caché TTL, Docker multi-stage, Nginx, deploy.sh

**Práctica 2** (mergeado en `main`):
- Auth X-API-Key + rate limiting (slowapi)
- HTTPS con Let's Encrypt en blueecho.es
- 10+ conectores nuevos: ThreatFox, URLScan, IPInfo, RDAP, SecurityTrails, Hybrid Analysis, Netlas, Criminal IP, MalShare, Pulsedive, Censys
- Bulk scan (múltiples IOCs a la vez)
- MITRE ATT&CK mapping con reason + description
- Análisis PCAP: upload .pcap, reconstrucción TCP con scapy, extracción de objetos HTTP maliciosos
- Geolocalización con mapa react-leaflet (ipwho.is)
- Historial de escaneos PCAP con veredicto "CAPTURA DE RED"
- Login con X-API-Key

**Rediseño UI** (mergeado en `main`):
- Fuentes: Space Grotesk (UI) + JetBrains Mono (datos)
- Fondo `#08080f`, header minimalista h-12 con línea de acento azul
- ThreatScore: número enorme con glow del color del veredicto, sin gauge SVG
- ResultsTable: filas compactas monospace agrupadas por tipo de IOC
- EmptyState: radar animado, SkeletonResults: shimmer loader

**Sistema multiusuario** (rama `feat/invite-tokens`, sin mergear aún):
- Invitaciones autoservicio: `/invite` + `POST /api/auth/invite` (nombre obligatorio,
  gated by `ADMIN_SECRET`), tokens en tabla `ApiKey`
- Aislamiento de sesiones: `ScanResult.api_key` por usuario; historial y detalle
  filtrados por token (escaneo ajeno → 404)
- Sesión con nombre: `GET /api/auth/me` + nombre e iniciales en el menú de usuario
- Barra lateral de historial plegable (estado en localStorage)

### Pendiente

- **`feat/invite-tokens`**: ejecutar `pytest` y build de frontend en Kali; si verde,
  mergear a `main`. Recrear BD con `docker compose down -v` (columna `api_key` nueva).
- Ajustes finales de `Dashboard.tsx` (baja prioridad).

### Infraestructura

- VPS: Hetzner CX23 — IP `138.199.205.221`
- Dominio: blueecho.es (HTTPS, auto-renovación Let's Encrypt)
- SSH: `ssh root@138.199.205.221`
- Directorio producción: `/opt/blue-echo`
- Dev local (Kali): `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`

### Última sesión

**Fecha**: 2026-09-28 (rama `feat/invite-tokens`) — Sistema multiusuario: invitaciones
autoservicio con nombre obligatorio (`/invite`, `POST /api/auth/invite`), aislamiento de
historial por token (`ScanResult.api_key`, filtros en `/history`, ajeno → 404), sesión
con nombre en la UI (`GET /api/auth/me`), y barra lateral de historial plegable. Se
verificó por inspección de BD que el aislamiento funciona. Nota Obsidian `Fase P3-02`.
**Sin verificar (Windows sin npm): `pytest` y build de frontend → hacerlo en Kali antes
de mergear a `main`. Recrear BD con `docker compose down -v` por la columna nueva.**
