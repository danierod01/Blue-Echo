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

Estado a fecha 2026-09-24 (rama `claude/awesome-franklin-79do5a`):

- [ ] **Verificar arranque en limpio** `docker compose up --build` (criterio nº1
      de P3, 30% de la nota). NO verificado tras añadir `fpdf2`. **Prioritario.**
- [x] ~~**Numerar requisitos** RF-/RNF- de la P1 y montar la **matriz de trazabilidad**~~ ✅ (2026-09-24): `Bluecho/IOC-Correlator/08 - Requisitos y Matriz de Trazabilidad.md` (12 RF + 7 RNF derivados del Informe P1 + mejoras, mapeados a código y tests). Falta rellenar minuto del vídeo y medir latencia (RNF-07).
- [ ] **Documentar en Obsidian** (Claude puede hacerlo): F4 (PDF), F5 (webhooks),
      GreyNoise, decisión F7 (Groq vs Ollama), y la limpieza de tests. Crear nota
      "Fase P3" en `03 - Diario de Desarrollo/`.
- [ ] Redactar apartado de **seguridad** (STRIDE) y correr `pip-audit`/`npm audit`.
- [ ] Rediseño UI pendiente (baja prioridad): `AiSummary`, `SearchBar`,
      `SourcesStatus`, `Login`, ajustes `Dashboard`.
- [ ] Antes de entregar: tag `v1.0-practica3`, README instala-desde-cero.

### Trabajo pendiente (manual / otra máquina)

- [ ] Capturas de pantalla de cada funcionalidad para la memoria y Obsidian.
- [ ] Grabar el vídeo de demostración (≥10 min) sobre el producto real.
- [ ] Probar el despliegue real en el VPS Hetzner (SSH) si se actualiza producción.

### Registro de sesiones

- **2026-09-24** (cloud, rama `claude/awesome-franklin-79do5a`): leído enunciado
  P3 y anotado en CLAUDE.md. Arreglados 6 tests rojos + bug MalwareBazaar.
  Implementado GreyNoise (conector+scoring+tests). Implementado F4 (export PDF,
  fpdf2) y F5 (alertas webhook). De 6 tests rojos → **262 verdes**. Frontend
  compila. Todo commiteado y pusheado. Creada la matriz de trazabilidad
  (`08 - Requisitos y Matriz de Trazabilidad.md`) con requisitos RF/RNF
  numerados. **Pendiente inmediato (otra máquina): verificar `docker compose`.
  Siguiente aquí: documentar fase P3 en Obsidian y apartado de seguridad.**

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
| F7 | Estudio motor IA (Anthropic vs Ollama) | Alta | ⚠️ Modificado → Groq (Llama 3.3 70B) primario + Claude fallback + análisis local. **Justificar en memoria** |
| R1 | Paginación real en historial | Baja | ✅ Hecho (`items`/`total`) |
| I1 | API pública OpenAPI + auth | Media | ✅ Mayormente (`/docs` + auth) |
| **F4** | **Exportación a PDF del escaneo** | Media | ✅ **Hecho** (2026-09-24): `GET /api/history/{id}/pdf` con fpdf2 (Python puro, sin libs de sistema) + botón "Descargar PDF" en el dashboard |
| **F5** | **Alertas por webhook (Slack/Discord/Teams)** | Media | ✅ **Hecho** (2026-09-24): `alerting.py`, dispara webhook si `score >= ALERT_SCORE_THRESHOLD`; formatos slack/discord/teams/generic; best-effort (nunca rompe el escaneo). Config en `.env` |
| R2 | PostgreSQL | Baja | ❌ Backlog (justificar como trabajo futuro) |
| R3 | Celery + Redis | Baja | ❌ Backlog (justificar como trabajo futuro) |
| I2 | Export a SIEM | Baja | ❌ Backlog |
| I3 | Plugin de navegador | Baja | ❌ Backlog |

**Extras construidos fuera del roadmap** (mejoras adicionales, el profesor no las ha visto): análisis PCAP (scapy), geolocalización con mapa, login UI, rediseño completo de la UI.

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
`main` — todo el desarrollo va aquí desde ahora.

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

### Pendiente

- Rediseño de: `AiSummary.tsx`, `SearchBar.tsx`, `SourcesStatus.tsx`, `Login.tsx`, `tailwind.config.js` (keyframes), `Dashboard.tsx` (ajustes finales)

### Infraestructura

- VPS: Hetzner CX23 — IP `138.199.205.221`
- Dominio: blueecho.es (HTTPS, auto-renovación Let's Encrypt)
- SSH: `ssh root@138.199.205.221`
- Directorio producción: `/opt/blue-echo`
- Dev local (Kali): `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`

### Última sesión

**Fecha**: 2026-09-23 — Rediseño UI (ThreatScore, ResultsTable, App, index.css). Merge de todas las ramas a `main`. Creado sistema de contexto en CLAUDE.md.
