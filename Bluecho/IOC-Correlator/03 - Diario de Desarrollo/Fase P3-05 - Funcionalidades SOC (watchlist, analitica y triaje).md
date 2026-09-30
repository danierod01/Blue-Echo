# Fase P3-05 — Funcionalidades SOC: watchlist, analítica y triaje del analista

> Sesión del 2026-09-30 (cloud). Rama de desarrollo `feat/soc-watchlist-analytics`
> (partida de `design-soc-dashboard`, que ya arranca en limpio y está verificada).
> Se trabaja en rama aparte para **no mezclar con lo que ya sabemos que funciona**.

## Qué se ha construido

Tres funcionalidades reales de SOC/SIEM que dan valor operativo a la herramienta,
seleccionadas por aportar seguimiento y contexto sin desviar la naturaleza del
producto (sigue siendo un **correlador de IOCs**, no un gestor de casos):

### B · Watchlist + monitorización continua

Un IOC no es un hecho puntual: su reputación cambia con el tiempo. La watchlist
convierte el escaneo puntual en **vigilancia automática**.

- **Modelos nuevos** (`database.py`): `WatchedIoc` (IOC vigilado, con
  `last_score`/`last_verdict`/`last_checked_at`, `active`, y `api_key` para
  aislamiento por usuario) y `WatchAlert` (alerta generada al cambiar el
  veredicto: guarda veredicto/score antiguos y nuevos, `acknowledged`, `api_key`).
- **Tarea Celery periódica** (`tasks.py` → `check_watchlist_task`): un **worker con
  scheduler (Celery Beat)** se despierta cada `WATCHLIST_BEAT_SECONDS` (por defecto
  300 s), busca los IOCs cuyo último chequeo excede `WATCHLIST_CHECK_INTERVAL_MINUTES`,
  los **re-escanea (enrich + score, SIN IA** para no gastar cuota de LLM en trabajo
  de fondo), y **si el veredicto cambia** (p. ej. `clean` → `malicious`) crea una
  `WatchAlert` y dispara el webhook de alertas si el score supera el umbral
  (best-effort, nunca rompe el ciclo).
- **Endpoints** (`routes.py`): `POST /api/watchlist` (añadir, idempotente),
  `GET /api/watchlist` (listar), `DELETE /api/watchlist/{id}` (quitar),
  `POST /api/watchlist/{id}/check` (comprobar ahora, sin esperar al beat),
  `GET /api/watchlist/alerts` y `POST /api/watchlist/alerts/{id}/ack` (reconocer).
- **Frontend** (`pages/Watchlist.tsx`): formulario de alta, tabla de IOCs vigilados
  con último veredicto y botón "comprobar ya", y panel de alertas de cambio de
  veredicto con acuse de recibo.

### D · Dashboard analítico

Una vista agregada del trabajo del analista, no un escaneo individual.

- **`get_stats()`** (`database.py`): total de escaneos, distribución por **veredicto**
  y por **tipo de IOC**, **serie temporal de 14 días**, **top amenazas** y un resumen
  de la watchlist. Todo filtrado por token (cada usuario ve sus métricas).
- **Endpoint** `GET /api/stats`.
- **Frontend** (`pages/Analytics.tsx`) con **Recharts**: tiles de cifras clave,
  `AreaChart` temporal, donut (`PieChart`) de veredictos, barras (`BarChart`) por
  tipo, y tabla de top amenazas.
  - Se siguió la skill **dataviz**: los **veredictos** usan colores de estado
    reservados (rojo/naranja/amarillo/verde) + leyenda; la magnitud por **tipo** usa
    **un solo tono teal** (sin paleta categórica que haya que justificar).

### A-lite · Triaje del analista

Se valoró "A" (gestión de casos completa, tipo TheHive) y se **descartó
conscientemente**: convertiría el correlador en un gestor de incidentes, desplazando
el centro de gravedad del producto. En su lugar, **A-lite**: triaje ligero *sobre el
propio escaneo*.

- **`ScanResult` gana 3 campos** (`database.py`): `triage` (estado del ciclo de
  investigación: `new` / `investigating` / `confirmed` / `false_positive` /
  `resolved`), `note` (nota libre del analista) y `tags` (lista de etiquetas,
  serializada JSON con dedupe y tope 10).
- **Helpers**: `update_scan_triage` (valida el estado → `ValueError`; respeta al
  propietario → `None` si el escaneo es de otro token) y `parse_tags`
  (deserialización defensiva: cualquier JSON corrupto → lista vacía).
- **Endpoint** `PATCH /api/history/{id}/triage`: `422` si el estado no es válido,
  `404` si el escaneo no existe o es ajeno; devuelve el `ScanResponse` actualizado.
- **Frontend**: `TriagePanel.tsx` (botones de estado, chips de etiquetas con
  add/remove, textarea de nota, guardar → toast) bajo el bloque de análisis IA en el
  Dashboard; además, badge de estado + etiquetas en la lista de historial
  (`HistoryList.tsx`).

## Decisiones técnicas tomadas

| Decisión | Motivo |
|---|---|
| Watchlist re-escanea **sin IA** | El chequeo de fondo corre cada pocos minutos sobre N IOCs; llamar al LLM en cada uno agotaría cuota y coste. La IA se reserva para el escaneo interactivo |
| Alerta **solo al cambiar el veredicto** | Reduce ruido: al analista le importa la *transición* (una IP que se vuelve maliciosa), no un chequeo idéntico repetido |
| Métricas de analítica **filtradas por token** | Coherencia con el aislamiento de sesiones: cada usuario ve solo su actividad |
| dataviz: estado = color reservado, magnitud = tono único | Evita paletas categóricas arbitrarias; el color comunica significado (veredicto) y no adorno |
| **A-lite** en vez de A completa | Un gestor de casos cambiaría la naturaleza del producto; el triaje sobre el escaneo añade seguimiento sin ese salto de alcance |
| Triaje respeta propietario y valida estado en la capa de BD | La regla de negocio (quién puede tocar qué, qué estados existen) vive junto al modelo, no solo en la ruta |
| `parse_tags` defensivo | Los `tags` son texto JSON en BD; un valor corrupto nunca debe romper el listado de historial |

## Comandos clave utilizados

```bash
# Backend: suite completa (SQLite en memoria)
cd backend && python -m pytest -q                 # 336 verdes
cd backend && python -m pytest tests/test_watchlist.py tests/test_triage.py -q

# Frontend: build de producción + tests
cd frontend && npm run build && npm test          # build OK + 6 tests

# Demo de la watchlist en Kali: bajar el intervalo para ver alertas rápido
#   WATCHLIST_CHECK_INTERVAL_MINUTES=1  en el .env, y el worker con --beat
docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
docker compose logs -f worker    # ver el beat re-escaneando la watchlist
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| `maybe_send_alert(...)` recibía un kwarg `extra=` que su firma no acepta | La firma solo toma 4 argumentos posicionales; se quitó el kwarg en `tasks.py` |
| El worker de fondo comparte datos con la API | Ya resuelto en P3-04: Postgres como BD compartida (con SQLite por contenedor no se verían); el beat corre en el mismo `worker` con `--beat` |
| Migración de esquema (3 columnas en `ScanResult` + 2 tablas nuevas) | SQLModel no migra en caliente → recrear BD con `docker compose down -v` en el despliegue |

## Evidencias

- Watchlist: alta de un IOC, tabla de vigilados y una alerta de cambio de veredicto.
- Analítica: donut de veredictos + serie temporal de 14 días + top amenazas.
- Triaje: panel bajo el análisis IA (estado "Confirmado", etiquetas `tor`/`c2`,
  nota), y el badge + etiquetas reflejados en el historial lateral.

![[captura_P3-05_watchlist.png]]
![[captura_P3-05_analitica.png]]
![[captura_P3-05_triaje.png]]

## Mapeo a la memoria P3

- **Apartado 6 (Funcionalidades implementadas)**: watchlist/monitorización,
  dashboard analítico y triaje del analista — cada una con capturas y "cómo se usa".
  Declarar que son **extras fuera del roadmap P1** (el profesor no las ha visto).
- **Apartado 8 (Pruebas y evidencias)**: `test_watchlist.py` (10) y `test_triage.py`
  (8) → suite backend **336** verdes.
- **Apartado 9 (Matriz de trazabilidad)**: estas features son mejoras (`MJ-*`), no
  requisitos P1; se listan como valor añadido con su prueba y evidencia.
- **Apartado 10 (Limitaciones y trabajo futuro)**: A-lite es triaje, no gestión de
  casos; el detalle de historial aún no muestra el panel de triaje (solo el badge).

## Estado al terminar esta fase

- [x] Tests pasando — backend **336** verdes, frontend **6** verdes, build OK
- [x] Variables de entorno documentadas en `.env.example` (`WATCHLIST_*`)
- [x] Commits realizados con mensaje convencional (B+D watchlist/analítica; A-lite triaje)
- [x] README actualizado (endpoints watchlist, `/stats`, triaje)
- [ ] Verificar en Kali con el **beat** corriendo (bajar `WATCHLIST_CHECK_INTERVAL_MINUTES` para la demo) — pendiente [tú]
- [ ] Recrear BD (`docker compose down -v`) por las 2 tablas + 3 columnas nuevas — al desplegar
- [ ] Capturas para la memoria (watchlist, analítica, triaje) — pendiente [tú]
