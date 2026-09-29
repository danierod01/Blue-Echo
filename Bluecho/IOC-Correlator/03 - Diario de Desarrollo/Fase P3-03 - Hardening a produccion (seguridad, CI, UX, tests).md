# Fase P3-03 — Hardening a producción (seguridad, CI/CD, UX y tests)

> Sesión del **2026-09-29** (rama `feat/invite-tokens`). Decisión de dejar la aplicación
> "a nivel de producto real" al ser la última entrega. Trabajo organizado en **5 tandas**.
> Alimenta los apartados **6 (Funcionalidades)**, **7 (Seguridad)** y **8 (Pruebas)** de la
> memoria de la P3.

## Qué se ha construido (por tandas)

### Tanda 1 — Gestión del ciclo de vida de tokens
- `ApiKey` gana `active` y `expires_at`; `is_valid_api_key` rechaza tokens revocados o
  caducados.
- Endpoints (con `ADMIN_SECRET`): `POST /auth/tokens` (listar con la clave **enmascarada**),
  `POST /auth/revoke` (revocar por id); `POST /auth/invite` acepta `expires_in_days`.
- Frontend: panel "Gestionar tokens" en `/invite` (listar/revocar + campo de caducidad).

### Tanda 2 — Cabeceras de seguridad + auditoría
- Cabeceras de seguridad en `nginx.dev.conf` (las de producción ya existían): X-Frame-Options
  DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy y **CSP** (sin HSTS por
  ser HTTP en local).
- **Log de auditoría** (`ioc_correlator/audit.py`, logger `blueecho.audit`): registra
  escaneos, invitaciones, revocaciones e intentos de acceso fallidos, con el token
  **enmascarado**. Enganchado en `routes._run_scan` y en `auth.py`.

### Tanda 3 — CI/CD + producción
- **GitHub Actions** (`.github/workflows/ci.yml`): job backend (pytest + pip-audit) y job
  frontend (npm ci + Vitest + build + npm audit) en cada push/PR. Auditorías con
  `continue-on-error` (avisan, no bloquean por un CVE nuevo aguas arriba).
- **LICENSE** (MIT) + badges de CI y licencia en el README.
- (Los healthchecks del `docker-compose.yml` ya existían.)

### Tanda 4 — UX
- **Bug corregido:** `index.html` referenciaba `/favicon.svg` inexistente (404) → creado
  `frontend/public/favicon.svg`.
- Meta **Open Graph / Twitter** + `theme-color`.
- Página **404** (`pages/NotFound.tsx` + ruta comodín `*`) — antes una ruta desconocida
  dejaba la pantalla en blanco.
- **Error boundary** global (`components/ErrorBoundary.tsx`): ante un error de render muestra
  pantalla de recuperación con botón "Recargar" en vez de pantalla en blanco.

### Tanda 5 — Tests de frontend
- **Vitest + Testing Library + jsdom** (`vitest.config.ts`, `src/test/setup.ts`, `npm test`).
- 6 tests: `lib/utils`, `AiSummary` (render de Markdown), `NotFound`.
- Tests excluidos del `tsc -b` de producción; añadidos al CI.

## Decisiones técnicas tomadas

- **Tokens tipo PAT con revocación/caducidad** en vez de RBAC completo: cubre el ciclo de
  vida real de una credencial con poca superficie. RBAC con roles queda como trabajo futuro.
- **404 en recursos ajenos** (ya en P3-02) + **auditoría con token enmascarado**: nunca se
  escribe el secreto completo en logs.
- **fpdf2 / mini-parser / Vitest excluido del build**: decisiones para no romper la imagen
  slim ni el `tsc -b` de producción.
- **Auditorías de dependencias no bloqueantes en CI** (`continue-on-error`,
  `--audit-level=high`): un CVE nuevo de terceros informa pero no impide integrar.

## Comandos clave utilizados

```bash
# Backend
cd backend && python -m pytest -q            # 281 tests

# Frontend
cd frontend && npm test                       # 6 tests (Vitest)
npm run build                                 # tsc -b + vite build
npm audit --audit-level=high                  # auditoría
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| `index.html` apuntaba a un favicon inexistente (404) | Creado `frontend/public/favicon.svg` |
| Tests de frontend romperían `tsc -b` (noUnusedLocals, tipos vitest) | Excluir `*.test.*` en `tsconfig.app.json`; Vitest los ejecuta aparte |
| Instalar Vitest introdujo CVEs (esbuild high/critical) | Subir a Vitest 3 (esbuild parcheado); quedan 2 moderate **dev-only** en `@vitest/mocker` (no afectan al producto) |
| El error boundary requiere componente de clase | `components/ErrorBoundary.tsx` con `getDerivedStateFromError` |

## Estado al terminar esta fase

- [x] Backend **281 tests** verdes · Frontend **6 tests** verdes · build OK
- [x] Cabeceras de seguridad también en dev; auditoría de eventos
- [x] CI de GitHub Actions + LICENSE
- [x] 404 + error boundary + favicon + meta OG
- [ ] Toasts (micro-paso, siguiente)
- [ ] Verificar en Kali (`docker compose`, pytest, npm test) y mergear a `main`

## Deuda técnica anotada (para la memoria — apartado 10, limitaciones)

- `react-markdown` está en `dependencies` pero `AiSummary` usa un mini-parser propio →
  revisar si otro componente lo usa; si no, se puede eliminar para adelgazar el bundle.
- 2 vulnerabilidades **moderate dev-only** en `@vitest/mocker` (solo se corrigen en Vitest 5,
  que arrastraría Vite 7). No afectan al artefacto de producción.
- Bundle del frontend > 500 kB (aviso de Vite): posible *code-splitting* futuro.

## Evidencias (pendientes de captura)

- `curl -I http://localhost` mostrando las cabeceras de seguridad.
- Panel "Gestionar tokens" en `/invite` (listar + revocar).
- Página 404 y pantalla del error boundary.
- Salidas de `pytest` (281) y `npm test` (6) en verde; CI en verde en GitHub.
