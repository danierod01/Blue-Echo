# Fase P3-02 — Sistema de invitaciones, sesiones aisladas y mejoras de UI

> Sesión del **2026-09-28** (rama `feat/invite-tokens`). Se construye sobre el sistema
> de auth X-API-Key existente para convertirlo en un sistema multiusuario real:
> generación de tokens autoservicio, historial privado por usuario y nombre de sesión
> en la interfaz. Alimenta los apartados **6 (Funcionalidades)**, **7 (Seguridad)** y
> **9 (Matriz de trazabilidad)** de la memoria de la P3.

## Qué se ha construido

1. **Sistema de invitaciones autoservicio (`POST /api/auth/invite`).**
   Una página `/invite` donde, introduciendo el `ADMIN_SECRET` del servidor, cualquiera
   puede generar su propio token de acceso personal. El token se genera con
   `secrets.token_urlsafe(32)` y se guarda en la tabla `ApiKey` de la BD. Evita tener
   que repartir la clave maestra a mano.

2. **Aislamiento de sesiones (historial privado por token).**
   Cada escaneo se guarda con el token que lo creó (`ScanResult.api_key`). El historial
   (`GET /api/history`) y el detalle (`GET /api/history/{id}`, `.../pcap`) se filtran por
   el token de la petición: cada usuario solo ve **sus** escaneos. Un escaneo de otro
   usuario devuelve `404` (no se revela ni que existe).

3. **Nombre obligatorio y sesión identificada.**
   Al generar un token ahora es obligatorio poner un nombre/identificador. Nuevo
   endpoint `GET /api/auth/me` que devuelve el nombre de la sesión actual. El frontend
   lo muestra en el menú de usuario (nombre + iniciales en el avatar).

4. **Barra lateral de historial plegable.**
   Botón en el dashboard para mostrar/ocultar la columna de "Recientes". El estado se
   recuerda en `localStorage`.

## Decisiones técnicas tomadas

- **Tokens con etiqueta en vez de login usuario/contraseña + email.** Se descartó el
  sistema clásico de cuentas (tabla de usuarios, hash de contraseñas, envío SMTP,
  verificación por correo, reset, sesiones JWT) por dos razones: (1) mucha más
  superficie que asegurar antes del 16/10 y más puntos de fallo en la demo del vídeo
  (deliverability, spam); (2) el token-con-etiqueta **es** un patrón de producto real
  — los *Personal Access Token* de GitHub o las API keys de Stripe/AWS funcionan igual:
  el token es la credencial y lleva un nombre identificativo. Menos código, menos
  riesgo, y sigue siendo defendible en un máster de ciberseguridad.

- **El filtro de historial es "por token si hay token".** `get_history(...,
  api_key=current_key or None)` solo filtra cuando hay un token. En modo dev (sin
  `BLUE_ECHO_API_KEY`) el token puede ir vacío y entonces se ve todo — comportamiento
  útil para desarrollo local, sin romper el aislamiento en producción.

- **404, no 403, para escaneos ajenos.** Al pedir el detalle de un escaneo que
  pertenece a otro token se responde `404`, no `403`. Así no se filtra la existencia de
  recursos de otros usuarios (evita enumeración de IDs).

- **`require_api_key` ahora devuelve la clave (antes `None`).** Era una dependencia de
  FastAPI que solo validaba; ahora además retorna el token para que los endpoints
  puedan filtrar por usuario. Los endpoints que no necesitan el token (`/sources`,
  `/history/{id}/pdf`) siguen usándolo como `dependencies=[...]`.

- **Limpieza de caché de React Query en login/logout.** Al cambiar de sesión en el
  mismo navegador, `queryClient.clear()` evita que se muestre el nombre o el historial
  cacheado del usuario anterior durante unos segundos.

## Comandos clave utilizados

```bash
# Migración de esquema: la tabla ScanResult no tenía la columna api_key.
# SQLModel NO migra en caliente, hay que recrear la BD (borra historial en dev):
docker compose down -v
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build

# Inspección directa de la BD para verificar el aislamiento:
sudo docker compose exec backend python -c "
import sqlite3
c = sqlite3.connect('/app/data/ioc_correlator.db')
for row in c.execute('SELECT id, ioc_value, api_key FROM scanresult'): print(row)
for row in c.execute('SELECT id, substr(key,1,16), label FROM apikey'): print(row)
"
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| HTTP 500 / NetworkError al escanear tras añadir sesiones | La BD antigua no tenía la columna `api_key`; SQLModel no migra en caliente. Recrear volumen con `docker compose down -v`. |
| Nginx crasheaba en local (`cannot load certificate blueecho.es`) | El compose de producción exige el cert de Let's Encrypt. En local hay que usar el override: `-f docker-compose.dev.yml`. |
| "Un token nuevo ve el historial de otro" (falsa alarma) | No era un bug: el escaneo estaba bajo otra clave/token. Cada clave ve solo lo suyo; verificado inspeccionando la BD. |
| El nombre de sesión no cambiaba al re-loguear en el mismo navegador | `queryClient.clear()` en login y logout. |

## Evidencias
<!-- Capturas pendientes (tú, mañana):
     - captura_invite.png    → página /invite generando un token con nombre
     - captura_sesion.png    → menú de usuario mostrando el nombre arriba
     - captura_sidebar.png   → dashboard con la barra lateral plegada y desplegada
     - captura_aislamiento.png → dos sesiones distintas con historiales distintos -->
![[captura_invite.png]]

## Estado al terminar esta fase
- [x] Tests pasando — **270 verdes** (262 previos + 8 nuevos en `tests/test_auth_invite.py`
      que cubren invitación, `/auth/me`, verify y **aislamiento de historial por token**;
      verificado en el entorno cloud el 2026-09-29)
- [x] Variables de entorno documentadas en `.env.example` (`ADMIN_SECRET`)
- [ ] Commit realizado (lo hace el desarrollador al terminar)
- [ ] Build de frontend verificado (no hay npm en la máquina Windows; verificar vía Docker en Kali)

## Ficheros tocados

**Backend**
- `backend/ioc_correlator/database.py` — modelo `ApiKey`, `ScanResult.api_key`,
  `create_api_key`, `is_valid_api_key`, `get_api_key_label`, filtro en `get_history`
- `backend/ioc_correlator/api/auth.py` — `/auth/invite`, `/auth/me`, nombre obligatorio,
  `require_api_key` devuelve la clave, `_check_key` (maestra o token de BD)
- `backend/ioc_correlator/api/routes.py` — endpoints pasan `current_key` a `save_scan` /
  `get_history`; detalle devuelve 404 si el escaneo es de otro token

**Frontend**
- `frontend/src/api/client.ts` — `getMe()`
- `frontend/src/App.tsx` — nombre + iniciales en el menú, limpieza de caché en logout
- `frontend/src/pages/Login.tsx` — limpieza de caché en login
- `frontend/src/pages/Invite.tsx` — página de generación de token (nombre obligatorio)
- `frontend/src/pages/Dashboard.tsx` — barra lateral plegable

## Pendiente / siguiente sesión
- Ejecutar `pytest` en Kali y verificar que sigue todo verde (los cambios en
  `require_api_key` y las firmas de `save_scan`/`get_history` pueden afectar a tests).
- Verificar el build de frontend vía Docker.
- Decidir si mergear `feat/invite-tokens` a `main` una vez validado.
- Los dos tokens generados antes de esta fase tienen nombre vacío → aparecen como
  "Administrador". Regenerarlos con nombre si se quiere una demo limpia.
