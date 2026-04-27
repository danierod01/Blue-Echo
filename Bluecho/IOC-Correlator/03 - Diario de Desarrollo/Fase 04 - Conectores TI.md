# Fase 04 — Conectores de Threat Intelligence

> **Estado:** En construcción. Se actualiza con cada conector implementado.

---

## Módulo 6 — BaseConnector (completado)

### Qué se ha construido

Clase abstracta `BaseConnector` que es la plantilla común para todos los conectores. Incluye:

- `ConnectorResult`: dataclass estándar con `source`, `success`, `data`, `verdict`, `summary`, `error`.
- `query(ioc_value, ioc_type)`: método público con manejo centralizado de errores.
- `_fetch(ioc_value, ioc_type)`: método abstracto que cada conector implementa.
- `is_available()`: comprueba si la API key está configurada en el entorno.
- `supports(ioc_type)`: comprueba si el conector puede procesar ese tipo de IOC.
- `_make_client()`: crea un `httpx.AsyncClient` con timeout desde variable de entorno.
- `_handle_http_error()`: traduce 429, 403, 404 y otros errores HTTP a `ConnectorResult`.

### Decisión técnica clave: Template Method Pattern

`query()` implementa el patrón Template Method. Gestiona toda la lógica defensiva (API key faltante, tipo no soportado, timeout, 429, 403, excepciones inesperadas) y delega solo la lógica específica de cada API a `_fetch()`. Esto garantiza que **ningún conector puede olvidarse de manejar un error**: el manejo está en la clase base y es obligatorio.

```
query()  →  comprueba disponibilidad y soporte
         →  llama a _fetch() dentro de try/except
         →  captura TimeoutException → error "timeout"
         →  captura HTTPStatusError  → error "http_4xx"
         →  captura Exception        → error genérico
```

### Decisión técnica: tests con monkeypatch en lugar de respx

Para testear `query()` se mockea `_fetch()` directamente con `monkeypatch.setattr()`. Esto es correcto porque lo que se quiere verificar es el comportamiento de `query()` ante distintas excepciones, no el comportamiento HTTP. Los tests con respx (interceptando el wire real) se hacen en los conectores concretos.

Nota técnica: `respx_mock` fixture y `@respx.mock` decorator no interceptan correctamente `httpx.AsyncClient` creados dentro de métodos cuando se combinan con fixtures de `monkeypatch` en pytest-asyncio 0.24. Usar el fixture directamente sobre el método `_fetch()` es más robusto y no depende de detalles de implementación de respx.

### Comandos clave

```bash
.venv/Scripts/python -m pytest tests/test_base_connector.py -v
# → 11 passed
```

### Estado al terminar este submódulo

- [x] 11 tests pasando (7 síncronos + 4 async)
- [x] `pytest.ini` con `asyncio_mode = auto` configurado
- [x] Manejo de timeout, 429, 403, missing key y unsupported type

---

---

## Módulo 7 — VirusTotal (completado)

### Qué se ha construido

Conector completo contra la API v3 de VirusTotal. Soporta todos los tipos de IOC:

| Tipo | Endpoint |
|---|---|
| IPv4 / IPv6 | `GET /api/v3/ip_addresses/{ip}` |
| MD5 / SHA1 / SHA256 | `GET /api/v3/files/{hash}` |
| Dominio | `GET /api/v3/domains/{domain}` |
| URL | `GET /api/v3/urls/{base64url_sin_padding}` |

### Decisiones técnicas tomadas

**Identificador de URL: base64url sin padding.**
VirusTotal identifica URLs por su representación en base64url (RFC 4648) sin los caracteres `=` de relleno. Implementado con `base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")`.

**Separación entre `_fetch()` y `_parse()`.**
`_fetch()` solo hace la petición HTTP. `_parse()` transforma el JSON en `ConnectorResult`. Esta separación permite testear el parseo sin ningún mock HTTP, con datos de ejemplo directamente.

**Umbral de veredicto: >5 motores = malicious.**
Con 1-5 motores = suspicious. Con 0 = clean. Este umbral reduce falsos positivos en IPs con baja reputación pero que no son activamente maliciosas.

### Reglas de scoring que aplica este conector

| Condición | Puntos |
|---|---|
| `malicious > 5` | +30 |
| `malicious >= 1` (o suspicious > 0) | +15 |

### Comandos clave

```bash
.venv/Scripts/python -m pytest tests/test_virustotal.py -v
# → 16 passed
```

### Estado al terminar este submódulo

- [x] 16 tests pasando (6 de endpoints + 6 de parseo + 4 de errores)
- [x] Manejo de 429 (rate limit), timeout, missing API key, tipo no soportado
- [x] `_parse()` nunca lanza excepciones: respuestas malformadas → `parse_error`

---

---

## Módulo 8 — AbuseIPDB (completado)

### Qué se ha construido

Conector contra la API v2 de AbuseIPDB. Solo soporta IPv4 e IPv6 (es una API exclusiva de IPs).

- Endpoint: `GET https://api.abuseipdb.com/api/v2/check`
- Parámetros: `ipAddress`, `maxAgeInDays=90`
- Cabecera de autenticación: `Key: {api_key}`

### Campos extraídos de la respuesta

| Campo | Uso |
|---|---|
| `abuseConfidenceScore` | Porcentaje de confianza de que la IP es abusiva (0-100) |
| `totalReports` | Número total de reportes en los últimos 90 días |
| `countryCode` | País de origen |
| `isp` | Proveedor de internet |
| `lastReportedAt` | Última vez reportada (null → "nunca") |
| `isWhitelisted` | Si está en whitelist de AbuseIPDB → fuerza veredicto "clean" |

### Reglas de scoring que aplica este conector

| Condición | Puntos |
|---|---|
| `confidence > 80` | +40 |
| `confidence 50-80` | +25 |
| `confidence > 0` (cualquier reporte) | +25 (suspicious) |

### Decisiones técnicas tomadas

**`isWhitelisted` tiene prioridad sobre el score.** IPs como `8.8.8.8` (Google DNS) pueden tener algún reporte espurio. Si AbuseIPDB la considera en whitelist, el veredicto es siempre `clean` independientemente del score.

**`lastReportedAt: null` → "nunca".** La API devuelve `null` si la IP nunca ha sido reportada. Se normaliza a "nunca" para que el frontend siempre tenga un string válido.

### Comandos clave

```bash
.venv/Scripts/python -m pytest tests/test_abuseipdb.py -v
# → 15 passed
```

### Estado al terminar este submódulo

- [x] 15 tests pasando (4 de soporte + 7 de parseo + 4 de errores)
- [x] Whitelist override implementado
- [x] Suite acumulada: 100 tests pasando

---

## Módulos 14 — Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise (pendiente)
