# Fase 05 — IA Generativa (ai_analyst.py)

## Qué se ha construido

Módulo `ai_analyst.py` que genera un resumen ejecutivo del IOC en español. Implementa dos modos de funcionamiento:

**Modo producción** — cuando `ANTHROPIC_API_KEY` está configurada:
- Llama a la API de Claude (`claude-sonnet-4-20250514`) con un system prompt de analista de Threat Intelligence.
- Construye un user prompt estructurado con todos los datos de los conectores.

**Modo desarrollo** — cuando no hay API key (o la llamada falla):
- Genera el mismo tipo de análisis directamente en Python, sin coste.
- Examina los datos de cada conector y construye frases en español con los hallazgos relevantes.
- Termina siempre con una recomendación accionable según el nivel de amenaza.

En ambos casos la función nunca lanza excepción: garantía de que el endpoint no se rompe si la IA falla.

## Ejemplo de salida (modo local, IP crítica)

> "La IP 185.220.101.45 ha sido clasificado como CRÍTICO con un score de amenaza de 87/100. VirusTotal registra detecciones activas en 23 de 87 motores antivirus. AbuseIPDB acumula 142 reportes con un índice de confianza del 95%, asociados principalmente al proveedor Tor Exit Node ISP. Recomendación: bloquear inmediatamente en firewall perimetral y revisar los logs internos en busca de conexiones hacia este indicador en las últimas 72 horas."

## Decisiones técnicas tomadas

**Modo local en lugar de fallback con datos crudos.**
La alternativa habitual es devolver un string con los datos en bruto cuando la API no está disponible. Aquí se genera texto legible directamente, de modo que el panel web es útil incluso sin API key. Esto es especialmente relevante en desarrollo y evaluación del proyecto.

**Prioridad: API key → análisis real. Sin key → análisis local. API falla → fallback al local.**
El triple nivel de degradación graceful garantiza que `ai_summary` siempre contiene texto útil en la respuesta del endpoint, nunca un string vacío o un error.

**Import tardío de `anthropic`.**
`from anthropic import Anthropic` está dentro de `_claude_api_analysis()`, no en el módulo. Así el backend arranca aunque el paquete no esté instalado o la clave sea incorrecta, sin ImportError.

**System prompt fijo en español.**
El system prompt define el rol (analista blue team), el idioma (español), la longitud (3-5 frases) y el formato (sin introducciones, directo y técnico). Esto garantiza consistencia entre llamadas.

## Estructura del prompt enviado a Claude

```
[System] Eres un analista experto en Threat Intelligence...

[User]
IOC: 185.220.101.45 (tipo: ipv4)
Score de amenaza: 87/100 — Veredicto: CRITICAL
Contribución por fuente: {"virustotal": 30, "abuseipdb": 40, ...}

Resultados por conector:
  [virustotal] OK — VirusTotal: 23/87 motores lo detectan como malicioso.
    Datos: {"malicious": 23, "total": 87}
  [abuseipdb] OK — AbuseIPDB: score de confianza 95%, 142 reportes.
    Datos: {"confidence": 95, "total_reports": 142}
```

## Comandos clave

```bash
.venv/Scripts/python -m pytest tests/test_ai_analyst.py -v
# → 15 passed

.venv/Scripts/python -m pytest tests/ -q
# → 165 passed
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| Test con `.lower()` comparando "hash MD5" (case-sensitive) | Corregido a `"hash md5" in r.lower()` |

## Estado al terminar esta fase

- [x] `generate_summary()` siempre devuelve un string, nunca lanza excepción
- [x] Modo local genera análisis coherente para todos los tipos de IOC y niveles de amenaza
- [x] Modo API configurable con `ANTHROPIC_API_KEY` en `.env`
- [x] Fallback automático si la llamada a la API falla
- [x] Integrado en el endpoint `/api/scan` → `ai_summary` siempre relleno
- [x] 15 tests pasando · Suite acumulada: 165 tests
