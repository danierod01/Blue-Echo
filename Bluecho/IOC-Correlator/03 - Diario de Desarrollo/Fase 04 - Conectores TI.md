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

## Módulo 14 — Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise (completado)

### Qué se ha construido

Cinco conectores adicionales que completan las 7 fuentes de Threat Intelligence del sistema:

| Conector | Archivo | Tipos soportados | API Key |
|---|---|---|---|
| Shodan | `connectors/shodan.py` | IPv4, IPv6 | `SHODAN_API_KEY` |
| AlienVault OTX | `connectors/otx.py` | IPv4, IPv6, MD5, SHA1, SHA256, Domain | `OTX_API_KEY` |
| MalwareBazaar | `connectors/malwarebazaar.py` | MD5, SHA1, SHA256 | — (API pública) |
| URLhaus | `connectors/urlhaus.py` | URL, Domain | — (API pública) |
| GreyNoise | `connectors/greynoise.py` | IPv4 | `GREYNOISE_API_KEY` |

### Decisiones técnicas tomadas

**Shodan: veredicto por puertos sensibles.**
Los puertos 22, 3389, 445, 1433 y 4444 se consideran "sensibles". Si la IP los tiene abiertos, el veredicto es `suspicious`. El scoring añade +10 por cada puerto sensible con un máximo de +30.

**OTX: veredicto por pulsos activos.**
OTX organiza la inteligencia en "pulsos" (campañas de amenaza). Si la IP/hash/dominio aparece en al menos un pulso, se considera malicioso. Se extraen los tags de los 3 primeros pulsos y se dedupen con `set()`.

**MalwareBazaar: API pública sin clave.**
`api_key_env = None`. La clase base `BaseConnector` detecta esto y no bloquea la consulta si no hay clave. Endpoint POST con form data `query=get_info`.

**URLhaus: dos endpoints según tipo de IOC.**
- URLs: `POST /v1/url/` → statuses: `is_online` (malicious), `was_online` (suspicious), `no_results` (clean)
- Dominios/hosts: `POST /v1/host/` → `ok` + `urls_count > 0` = malicious

**GreyNoise: 404 = "no vista", no error.**
La API Community devuelve 404 para IPs que no han sido observadas en internet ruidoso. Se intercepta antes del `raise_for_status()` y se retorna un `ConnectorResult` limpio directamente. Es el único conector con este comportamiento.

**GreyNoise: clasificación `benign` descuenta puntos.**
Según las reglas de scoring del CLAUDE.md, una IP clasificada como benigna por GreyNoise resta -10 puntos (es una señal activa de que es legítima).

### Reglas de scoring de los conectores nuevos

| Conector | Condición | Puntos |
|---|---|---|
| Shodan | Puerto sensible abierto (22/3389/445/1433/4444) | +10 c/u, máx +30 |
| OTX | Presente en pulsos activos | +20 |
| MalwareBazaar | Hash conocido | +40 |
| GreyNoise | Clasificado malicious | +30 |
| GreyNoise | Clasificado benign | -10 |

### Actualización de enricher.py

`_CONNECTORS` pasa de 2 a 7 conectores activos. Ahora se ejecutan todos en paralelo para cada consulta, filtrados automáticamente por tipo de IOC. Por ejemplo, una consulta de IP ejecutará: VT + AbuseIPDB + Shodan + OTX + GreyNoise (5 en paralelo). Un hash ejecutará: VT + OTX + MalwareBazaar (3 en paralelo).

### Tests escritos

5 ficheros de tests nuevos, 20 tests cada uno aproximadamente:
- `tests/test_shodan.py` — parseo de puertos sensibles, CVEs, errores
- `tests/test_otx.py` — parseo de pulsos, tags deduplicados, errores
- `tests/test_malwarebazaar.py` — found/not_found, fallback sin nombre, errores
- `tests/test_urlhaus.py` — URLs online/was_online/clean, host malicious/clean, errores
- `tests/test_greynoise.py` — malicious/benign/unknown/not_seen, 404 → clean, errores

### Comandos clave

```bash
# Ejecutar solo los tests de los nuevos conectores
.venv/Scripts/python -m pytest tests/test_shodan.py tests/test_otx.py tests/test_malwarebazaar.py tests/test_urlhaus.py tests/test_greynoise.py -v

# Ejecutar la suite completa
.venv/Scripts/python -m pytest -v
```

### Estado al terminar este módulo

- [x] 5 conectores nuevos implementados siguiendo el patrón BaseConnector
- [x] `enricher.py` actualizado con los 7 conectores
- [x] `scorer.py` ya tenía las reglas de los 7 conectores (implementadas previamente)
- [x] Tests para cada conector con casos de éxito, borde y error
- [x] MalwareBazaar y URLhaus sin API key (públicas), el sistema las ejecuta siempre
- [x] GreyNoise: comportamiento especial 404 documentado y testeado

---

## Módulo 15 — Caché TTL (completado)

### Qué se ha construido

Módulo `utils/cache.py` con una clase `TTLCache` de caché en memoria con expiración por tiempo, integrada en el `enricher.py`.

### Por qué hace falta

Sin caché, cada escaneo de un IOC llama a las 7 APIs externas aunque ese mismo IOC ya se haya consultado hace 5 minutos. Con un TTL de 1 hora (3600 s por defecto), el segundo escaneo del mismo IOC es instantáneo y no consume quota de API.

### Arquitectura de la caché

```
utils/cache.py
├── _Entry(value, expires_at)    — entrada con timestamp de expiración
├── TTLCache(ttl)                — dict[str, _Entry] con get/set/delete/clear/__len__
├── get_cache()                  — devuelve el singleton de proceso
└── reset_cache()                — borra el singleton (usado en tests)
```

**Clave de caché:** `"{ioc_type}:{ioc_value}"` — incluye el tipo para evitar colisiones entre un dominio y una URL con el mismo texto.

**Eliminación lazy:** las entradas expiradas se eliminan en el momento de la lectura (`get()`), no en background. Esto evita la necesidad de un hilo auxiliar.

**Thread-safety:** Python garantiza atomicidad de las operaciones dict en CPython (GIL). Asyncio ejecuta en un solo hilo, por lo que no hay condiciones de carrera.

### Decisión técnica: caché al nivel del enricher, no del conector

La caché se aplica a la salida completa de `enrich()` (todos los conectores), no a cada conector individualmente. Razón: si cualquier conector falla (API down, timeout), el resultado cacheado reflejaría ese fallo. Almacenando el resultado completo, se cachea el "estado del mundo" en ese momento, que es lo que el usuario ve.

### Integración en enricher.py

```python
key = f"{ioc_type.value}:{ioc_value}"
cached = get_cache().get(key)
if cached is not None:
    return cached           # ← respuesta inmediata sin llamadas HTTP

# ... ejecutar conectores ...
get_cache().set(key, result_map)
return result_map
```

### Variables de entorno

| Variable | Default | Descripción |
|---|---|---|
| `CACHE_TTL_SECONDS` | `3600` | Segundos que un resultado permanece válido en caché |

### Tests escritos

- `tests/test_cache.py` — 13 tests unitarios de TTLCache: get/set/miss/expiración/delete/clear/len/tipos complejos
- `tests/test_enricher_cache.py` — 3 tests de integración: cache hit no llama conectores, cache miss guarda resultado, IOCs distintos tienen entradas independientes

### Comandos clave

```bash
.venv/Scripts/python -m pytest tests/test_cache.py tests/test_enricher_cache.py -v
```

### Estado al terminar este módulo

- [x] `TTLCache` con expiración lazy, sin hilos auxiliares
- [x] Singleton `get_cache()` compartido por todo el proceso
- [x] `reset_cache()` para aislamiento de tests
- [x] Integración en `enricher.py`: cache-first, escribe en caché tras primera consulta
- [x] TTL configurable via `CACHE_TTL_SECONDS`
- [x] 16 tests nuevos (13 unitarios + 3 integración)
