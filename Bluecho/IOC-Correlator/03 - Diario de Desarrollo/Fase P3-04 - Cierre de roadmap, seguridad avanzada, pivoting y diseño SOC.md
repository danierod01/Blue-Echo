# Fase P3-04 — Cierre de roadmap, seguridad avanzada, pivoting y rediseño SOC

> Sesión del 2026-09-29 (cloud). Rama de desarrollo `feat/invite-tokens`; el
> rediseño visual y la fusión final en `design-soc-dashboard`.

## Qué se ha construido

Bloque grande de trabajo con cinco piezas, todas verificadas con tests:

### 1. Cierre del roadmap prometido (Informe P1 §8)

- **I2 · Exportación a SIEM/TIP** (`backend/ioc_correlator/siem_export.py`):
  serializa un escaneo a **STIX 2.1** (indicador + `attack-pattern` MITRE +
  relaciones `indicates`, con IDs deterministas `uuid5`) y a **evento MISP**
  (atributo tipado + tags + `threat_level_id`). Python puro, sin dependencias
  nuevas. Endpoint `GET /api/history/{id}/export?format=stix|misp` con
  aislamiento por token (escaneo ajeno → 404) y validación de formato (→ 422).
  Frontend: botones **STIX** y **MISP** en el dashboard.
- **I3 · Plugin de navegador** (`browser-extension/`, Manifest V3): popup de
  escaneo rápido, menú contextual (clic derecho sobre un IOC → escanear),
  página de opciones (URL del servidor + API key), icono radar. Habla con
  `POST /api/scan/json`; usa `host_permissions` para no depender del CORS.
- **R2 · PostgreSQL**: servicio `db` (postgres:16-alpine) en `docker-compose.yml`
  con healthcheck (`pg_isready`) y `depends_on: service_healthy`; el backend
  apunta a `postgresql+psycopg://`. Driver `psycopg[binary]`. **El código
  mantiene SQLite por defecto** para desarrollo local y tests.
- **R3 · Celery + Redis**: cola de tareas en segundo plano. `celery_app.py` +
  `tasks.py` (tarea `scan_ioc` = pipeline completo con su propia sesión de BD).
  Endpoints `POST /api/scan/async` (encola → `task_id`) y `GET /api/tasks/{id}`
  (estado/resultado). Servicios `redis` + `worker` en compose.

Con esto, **todo el roadmap del Informe P1 queda cerrado** (R2/R3/I2/I3); antes
figuraban como *backlog*.

### 2. Seguridad avanzada (RBAC + rate limiting por token)

- **Roles admin/analyst** (columna `ApiKey.role`): el `analyst` solo escanea y
  ve/exporta lo suyo; el `admin` (o la master key) además gestiona tokens. Las
  operaciones de administración se autorizan por un **token admin en la
  cabecera** `X-API-Key` o por el `ADMIN_SECRET` (bootstrap). `GET /auth/me`
  devuelve nombre **+ rol**.
- **Rate limiting por token**: la clave del limitador es el token (hash SHA-256
  corto) cuando la petición está autenticada, y la IP en caso contrario. El
  login (`/auth/verify`) sigue por IP contra fuerza bruta.

### 3. Pivoting (entidades relacionadas)

- `backend/ioc_correlator/pivots.py` (`extract_pivots`, función pura): deriva
  IOCs relacionados de los resultados —dominio→IP (resuelto), IP→hostnames
  (Shodan/IPinfo/SecurityTrails), dominio→nameservers (RDAP)—, deduplicados y
  acotados. Campo `pivots` en `ScanResponse`. Frontend: componente `Pivots.tsx`
  con chips clicables que lanzan un **escaneo encadenado** (flujo real de una
  investigación de Threat Intelligence).

### 4. Rediseño visual "SOC" (rama `design-soc-dashboard`)

Identidad de **consola SOC**: paleta teal/cian sobre negro azulado
(`--soc-bg #05080e`, `--soc-accent #2dd4bf`), textura de rejilla de consola en
CSS (sin imágenes de stock), tira **"OPERATIVO"** en la cabecera, marcas de
esquina HUD en el ThreatScore, píldoras y paneles teal. Se conservan los
**colores de veredicto** (rojo/naranja/amarillo/verde) por semántica.

### 5. Fusión final

`feat/invite-tokens` fusionado dentro de `design-soc-dashboard`, de modo que esa
rama tiene **todo junto**: features + seguridad + pivoting + diseño SOC.

## Decisiones técnicas tomadas

| Decisión | Motivo |
|---|---|
| SQLite por defecto en el código, Postgres solo en Docker | La app arranca en cualquier sitio sin Postgres; los tests no cambian de backend; cierra R2 sin romper nada |
| R2 (Postgres) antes que R3 (Celery) | El worker Celery abre su propia sesión de BD; con SQLite por contenedor, worker y API no compartirían datos — Postgres lo resuelve |
| STIX con IDs deterministas (`uuid5`) | Reexportar el mismo IOC da el mismo `id`: el receptor lo trata como actualización, no como duplicado |
| Admin por cabecera **o** por `ADMIN_SECRET` | El secreto sirve de *bootstrap* para crear el primer token admin; luego un token admin basta |
| Rate limit por token con hash | No se expone el token en claves/logs del limitador |
| Escaneo síncrono intacto | El modo async (cola) es aditivo; el flujo clásico no depende de Celery/Redis |

## Comandos clave utilizados

```bash
# Backend: suite completa (SQLite en memoria)
cd backend && python -m pytest -q            # 315 verdes

# Frontend: build de producción + tests
cd frontend && npm run build && npm test     # build OK + 6 tests

# Arranque en limpio en Kali (recrea la BD por columnas nuevas + Postgres)
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose ps            # db, redis, worker, backend, frontend
curl http://localhost/api/health   # {"status":"ok","version":"1.0.0"}
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| Un test de export fallaba solo en la suite completa | La ruta `/scan/json` está rate-limited y agotaba su cupo global; el test se reescribió para **insertar el escaneo directo en BD** (`save_scan`) en vez de pasar por la ruta |
| El merge del diseño podía chocar con el trabajo posterior | Git auto-fusionó `App/Dashboard/Invite`; único conflicto real = `CLAUDE.md` (resuelto conservando ambos historiales). Los elementos nuevos (STIX/MISP, pivotes, selector de rol) se retematizaron a teal para coherencia |
| Migración de esquema (`ApiKey` ganó columnas) | SQLModel no migra en caliente → recrear BD con `docker compose down -v` en el despliegue |

## Evidencias

- Terminal: los 5 servicios `Up`/`healthy` y `/api/health` → `ok`.
- Dashboard SOC: cabecera teal, badge de rol **Administrador**, 15/18 fuentes.
- Escaneo de `185.220.101.45`: ThreatScore 70 MALICIOSO, tabla por fuente,
  análisis IA, **entidades relacionadas** (pivote a `tor-exit-45.for-privacy.net`),
  geolocalización y botones STIX/MISP/PDF.

![[captura_P3-04_servicios.png]]
![[captura_P3-04_dashboard.png]]
![[captura_P3-04_escaneo.png]]

## Estado al terminar esta fase

- [x] Tests pasando — backend **315** verdes, frontend **6** verdes, build OK
- [x] Variables de entorno documentadas en `.env.example` (`POSTGRES_*`, `CELERY_*`)
- [x] Commit realizado con mensaje convencional (I2/I3, R2, R3, seguridad, pivoting, merge)
- [x] **Arranque en limpio `docker compose` verificado en Kali** (5 servicios sanos)
- [ ] Cargar el plugin de navegador en Firefox/Chrome y probarlo (pendiente)
