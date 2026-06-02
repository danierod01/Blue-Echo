# Fase P2-01 — Seguridad y Hardening

## Qué se ha construido

Auditoría completa de seguridad sobre todos los módulos del proyecto (backend, frontend, Nginx, Docker) y corrección de los problemas encontrados. Las mejoras se agrupan en cinco áreas: autenticación, rate limiting, CORS, cabeceras HTTP y corrección de bugs funcionales.

---

## Autenticación con API key propia

### Qué se ha implementado

Fichero `backend/ioc_correlator/api/auth.py` con:

- Dependencia `require_api_key` que lee la cabecera `X-API-Key` en cada petición protegida y la compara con la variable de entorno `BLUE_ECHO_API_KEY`.
- Endpoint `POST /api/auth/verify` para que el frontend valide la clave antes de mostrar la interfaz.
- Comparación con `hmac.compare_digest()` en lugar del operador `==` para prevenir ataques de timing.
- Modo desarrollo: si `BLUE_ECHO_API_KEY` no está configurada, la autenticación se desactiva automáticamente con un warning al arrancar.

### Decisión técnica: HMAC compare_digest

`==` en Python puede cortocircuitar la comparación en cuanto encuentra un carácter diferente. Un atacante que mida el tiempo de respuesta con suficiente precisión puede deducir cuántos caracteres de su intento son correctos (ataque de timing). `hmac.compare_digest()` siempre compara todos los caracteres en tiempo constante, independientemente de dónde esté la diferencia.

```python
return VerifyResponse(
    valid=hmac.compare_digest(body.api_key.encode(), expected.encode())
)
```

### Flujo de autenticación en el frontend

Al abrir la aplicación, si no hay API key en `localStorage`, se redirige a `/login`. Al introducir la clave, se llama a `/api/auth/verify`. Si es válida, se guarda en `localStorage` y se redirige al dashboard. Todas las llamadas posteriores incluyen la cabecera `X-API-Key`.

---

## Rate limiting por IP

### Qué se ha implementado

Fichero `backend/ioc_correlator/api/limiter.py` con `slowapi` (wrapper de `limits` para FastAPI):

- Endpoints de escaneo: 10 peticiones por minuto (configurable con `RATE_LIMIT_SCAN`).
- Endpoints de historial y fuentes: 30 peticiones por minuto.
- Endpoint de verificación: 5 peticiones por minuto (protección contra fuerza bruta de API keys).

### Problema encontrado: IP del contenedor Nginx

La implementación naive usaba `request.client.host` como clave de rate limiting. Detrás de Nginx, todos los clientes aparecen con la IP interna del contenedor (`172.x.x.x`), no con su IP real. Resultado: todos los usuarios compartían el mismo bucket, y un solo usuario podía agotar el rate limit de todos los demás.

**Solución:** función `_get_real_ip()` que lee la cabecera `X-Real-IP` cuando está presente (Nginx la inyecta) y cae a `request.client.host` como fallback:

```python
def _get_real_ip(request: Request) -> str:
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "127.0.0.1"
```

### Problema encontrado: incompatibilidad slowapi + limits 3.x

`SlowAPIMiddleware` (la forma recomendada de integrar slowapi en FastAPI) es incompatible con `limits==3.14.0`. Lanza `AttributeError` al arrancar el servidor. La solución fue registrar el limiter directamente en el objeto `app` de FastAPI:

```python
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

Y usar el decorador `@limiter.limit()` en cada endpoint individual en lugar del middleware global.

---

## Validación de inputs

- `ScanRequest.ioc`: campo Pydantic con `min_length=1, max_length=2048`.
- Endpoint de upload multipart: comprobación explícita `len(ioc) > 2048` antes de procesar.
- Parámetros de paginación en `/api/history`: `Query(ge=1, le=100)` para `limit` y `Query(ge=0)` para `offset`.

---

## CORS restrictivo

La configuración inicial tenía `allow_origins=["*"]` con `allow_credentials=True`. Esta combinación es inválida según la especificación CORS: los navegadores la ignoran silenciosamente. Se corrigió:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("CORS_ORIGIN", "http://localhost")],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)
```

---

## Cabeceras de seguridad en Nginx

Se añadieron al `nginx.conf`:

```nginx
server_tokens off;
add_header X-Frame-Options           "DENY"            always;
add_header X-Content-Type-Options    "nosniff"         always;
add_header Referrer-Policy           "no-referrer"     always;
add_header X-XSS-Protection          "1; mode=block"   always;
add_header Permissions-Policy        "geolocation=(), microphone=(), camera=()" always;
add_header Content-Security-Policy   "default-src 'self'; ..." always;
```

---

## Corrección de bugs funcionales

### Bug: breakdown siempre 0 en historial

`GET /api/history/{id}` devolvía siempre `breakdown: {}`. El motivo: al reconstruir el resultado desde la base de datos, se llamaba a `data.get("score", 0)` sobre un diccionario sin esa clave, devolviendo cero para todos los conectores.

**Solución:** reconstruir objetos `ConnectorResult` desde el JSON almacenado y ejecutar `compute_score()` de nuevo:

```python
raw = json.loads(db_scan.connector_results)
connector_objs = {name: ConnectorResult(**d) for name, d in raw.items()}
scoring = compute_score(connector_objs)
return _build_scan_response(db_scan, scoring.breakdown)
```

### Bug: URLhaus no contribuía al score

El conector URLhaus podía devolver `found=True` con `urls_count=0` (URL conocida pero no activa). La regla de scoring solo comprobaba `urls_count > 0` y asignaba cero puntos, ignorando el veredicto del conector. Corregido:

```python
def _score_urlhaus(result: ConnectorResult) -> int:
    if not result.success:
        return 0
    return 30 if result.data.get("urls_count", 0) > 0 or result.verdict == "malicious" else 0
```

---

## Estado al terminar esta fase

- [x] Autenticación con API key en todos los endpoints protegidos
- [x] Comparación de claves con HMAC constant-time
- [x] Rate limiting funcional detrás de proxy Nginx
- [x] CORS corregido
- [x] Cabeceras de seguridad en Nginx
- [x] Bug breakdown=0 en historial corregido
- [x] Bug scoring URLhaus corregido
- [x] Validación de longitud en inputs de usuario
