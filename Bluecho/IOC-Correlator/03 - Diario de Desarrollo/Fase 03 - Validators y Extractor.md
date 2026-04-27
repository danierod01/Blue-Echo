# Fase 03 — Validators, Extractor, Database y Scorer

## Qué se ha construido

Cuatro módulos de lógica central sin dependencias HTTP:

### `utils/validators.py` (Módulo 3)
- Enum `IOCType`: `ipv4`, `ipv6`, `md5`, `sha1`, `sha256`, `domain`, `url`.
- `detect_ioc_type(value)` — clasifica cualquier string.
- `is_valid_ioc(value)` — atajo booleano.

### `extractor.py` (Módulo 4)
- `extract_iocs(text)` — extrae IOCs únicos de texto libre por fases.
- `extract_iocs_from_bytes(content)` — wrapper para ficheros subidos (con fallback latin-1).
- Soporta: texto genérico, Apache/Nginx access log, syslog, JSON lines, CSV.

### `database.py` (Módulo 5)
- Modelo `ScanResult` con SQLModel: `ioc_value`, `ioc_type`, `score`, `verdict`, `connector_results` (JSON), `ai_summary`, `created_at`.
- Engine SQLite configurado desde `DATABASE_URL`.
- Helpers: `save_scan()`, `get_history()`, `get_scan_by_id()`.

### `scorer.py` (Módulo 9)
- `compute_score(results)` — recibe `dict[str, ConnectorResult]` y devuelve `ScoringResult`.
- `ScoringResult`: `score` (0-100), `verdict`, `breakdown` (puntos por conector).
- Reglas implementadas para los 6 conectores. Score acotado entre 0 y 100.

## Decisiones técnicas tomadas

**Orden de detección en validators: URL → IP → SHA256 → SHA1 → MD5 → DOMAIN.**
El orden importa para evitar que los primeros 32 chars de un SHA256 se detecten como MD5.

**Extracción por fases con borrado progresivo del texto.**
Las URLs se extraen y eliminan del texto antes de buscar dominios. Sin esto, `https://malware.com` generaría dos IOCs: la URL y el dominio.

**`connector_results` como JSON string en SQLite.**
SQLite no tiene tipo JSON nativo. Serializar/deserializar explícitamente con `json.dumps/loads` hace el comportamiento transparente y portable a PostgreSQL sin cambios de modelo.

**`ORDER BY created_at DESC, id DESC` en `get_history()`.**
El criterio secundario `id DESC` garantiza orden determinista cuando varios registros tienen el mismo timestamp (frecuente en tests que insertan filas en el mismo microsegundo).

**Scorer: reglas como funciones privadas, tabla de despacho `_RULES`.**
Cada conector tiene su función `_score_X()` aislada, registrada en el dict `_RULES`. Añadir un nuevo conector en el futuro es añadir una función y una entrada en el dict, sin tocar `compute_score()`.

**Score acotado con `max(0, min(100, total))`.**
GreyNoise puede restar 10 puntos (clasificado `benign`). Si el total fuera negativo, el score quedaría en 0, nunca negativo.

## Comandos clave utilizados

```bash
# Validators
.venv/Scripts/python -m pytest tests/test_validators.py -v  # 34 passed

# Extractor
.venv/Scripts/python -m pytest tests/test_extractor.py -v  # 17 passed

# Database
.venv/Scripts/python -m pytest tests/test_database.py -v  # 7 passed

# Scorer
.venv/Scripts/python -m pytest tests/test_scorer.py -v  # 35 passed

# Suite completa hasta este punto
.venv/Scripts/python -m pytest tests/ -q  # 135 passed
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| SHA256 fragmentado en MD5+SHA1 por orden de extracción incorrecto | Extraer SHA256 primero, borrar del texto, luego SHA1, luego MD5 |
| Dominios dentro de URLs aparecían como IOC separado | Borrar la URL del texto antes de buscar dominios |
| `test_get_history_order` fallaba intermitentemente en la suite completa | SQLite con timestamps iguales → orden no determinista. Solucionado añadiendo `id DESC` como criterio secundario |

## Estado al terminar esta fase

- [x] 135 tests pasando en la suite completa
- [x] Todos los tipos de IOC detectados y clasificados correctamente
- [x] Extractor funciona con texto libre, logs Apache, syslog, JSON lines y bytes
- [x] Base de datos con historial ordenado de forma determinista
- [x] Scorer con reglas para los 6 conectores, acotado 0-100
