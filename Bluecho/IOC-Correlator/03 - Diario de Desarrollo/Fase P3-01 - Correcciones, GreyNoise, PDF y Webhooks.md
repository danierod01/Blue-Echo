# Fase P3-01 — Correcciones, GreyNoise, exportación PDF y alertas por webhook

> Sesión del **2026-09-24** (rama `claude/awesome-franklin-79do5a`). Primera fase de la
> Práctica 3: cerrar la calidad de lo existente y completar el roadmap prometido en el
> Informe de la P1. Alimenta los apartados **6 (Funcionalidades)**, **8 (Pruebas)** y
> **9 (Matriz de trazabilidad)** de la memoria de la P3.

## Qué se ha construido

1. **Reparación de la batería de tests + bug real en un conector.**
   El backend tenía 6 tests en rojo tras los cambios de fases anteriores. Se
   arreglaron y, al hacerlo, se detectó y corrigió un **bug de seguridad funcional**
   en el conector de MalwareBazaar.

2. **Conector GreyNoise (`greynoise.py`).**
   GreyNoise figuraba en la documentación y en las reglas de scoring desde la P1
   pero **no existía en el código**. Se implementó de verdad para restaurar la
   coherencia entre lo prometido y lo entregado (requisito RF-03).

3. **Exportación a PDF del informe de escaneo (roadmap F4).**
   Botón "Descargar PDF" en el dashboard + endpoint que genera el informe.

4. **Alertas por webhook (roadmap F5).**
   Notificación a Slack/Discord/Teams/genérico cuando un IOC supera un umbral de score.

## Decisiones técnicas tomadas

- **MalwareBazaar — de "tolerante" a "fail-safe".** El parser trataba una respuesta
  malformada (`query_status` ausente o no-cadena) como *"limpio / no encontrado"*.
  En un contexto blue team eso es peligroso: reportarías un IOC como limpio cuando en
  realidad la fuente falló (falso negativo). Se cambió para que una respuesta
  inesperada se marque como `parse_error` (`success=False`) en lugar de como limpio.

- **Tests: el código es la fuente de verdad, no al revés.** 5 de los 6 fallos eran
  tests desfasados respecto al comportamiento correcto y actual del producto
  (historial paginado `{items, total}`, `get_history` devolviendo tupla, análisis
  local en Markdown). Se actualizaron los tests, no el código. El 6º (MalwareBazaar)
  sí era un bug de código y se arregló ahí.

- **GreyNoise — 404 no es un error.** En la Community API de GreyNoise, un 404
  significa "IP no observada por los sensores", no un fallo. Se trata como resultado
  válido con veredicto limpio (`seen: false`), en vez de propagarlo como error HTTP.
  Scoring según la tabla de la P1: `+30` si `classification == malicious`, `-10` si
  `benign` (el total se acota a ≥ 0).

- **F4 — fpdf2 en lugar de WeasyPrint.** El roadmap sugería WeasyPrint, pero necesita
  librerías de sistema (Pango, Cairo) por `apt`, lo que rompería la imagen
  `python:3.11-slim` y complicaría el criterio nº1 de la P3 ("instala desde cero").
  Se eligió **fpdf2** (Python puro, sin dependencias de sistema). El texto se sanea a
  latin-1 (sustituyendo em-dash, comillas tipográficas, etc.) para las fuentes core.

- **F5 — best-effort y no bloqueante.** La alerta se dispara tras guardar el escaneo,
  pero si el webhook falla (timeout, 5xx) se registra y se devuelve `False`;
  **nunca** rompe ni retrasa la respuesta del escaneo. El formato del payload se
  adapta al destino (`text` para Slack/Teams, `content` para Discord, MessageCard
  para Teams, JSON estructurado para `generic`).

- **F7 (motor de IA) — decisión registrada.** El estudio del roadmap ("Anthropic vs
  Ollama local") se cerró con una tercera opción: **Groq (Llama 3.3 70B) como motor
  primario, Claude (Anthropic) como fallback y un análisis local determinista** como
  último recurso. Motivo: coste cero en el tier gratuito de Groq y menor latencia,
  conservando la calidad de Claude cuando hay `ANTHROPIC_API_KEY`. Se documenta como
  requisito **RF-06 "a revisar"** en la matriz de trazabilidad.

## Comandos clave utilizados

```bash
# Backend — ejecutar toda la batería de tests
cd backend && python -m pytest -q

# Solo los tests nuevos de esta fase
python -m pytest tests/test_greynoise.py tests/test_alerting.py -q

# Frontend — compilar (verifica TypeScript + build de Vite)
cd frontend && npm install && npm run build

# Generar un PDF de prueba del informe (sanity check de report_pdf.py)
python -c "from ioc_correlator.report_pdf import build_scan_pdf; ..."
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| MalwareBazaar marcaba una respuesta malformada como "limpio" (falso negativo) | Validar `query_status` como cadena no vacía; si no, `parse_error` |
| `respx` no interceptaba las peticiones (versión incompatible en el entorno) | Usar `httpx.MockTransport` para los tests de `query()` de GreyNoise y alerting |
| WeasyPrint exige libs de sistema (Pango/Cairo) que rompen la imagen slim | Cambiar a `fpdf2` (Python puro, sin dependencias de sistema) |
| El endpoint PDF requiere `X-API-Key`, no vale `<a href>` | `fetch` con cabecera de auth → `blob` → descarga con enlace temporal |
| `const VERDICT_SCORE` sin usar rompía `npm run build` (bloquea el Docker del frontend) | Eliminada la constante muerta en `ResultsTable.tsx` |
| Los requisitos de la P1 no estaban numerados | Derivados del Informe P1 a 12 RF + 7 RNF en la nota `08 - Requisitos y Matriz de Trazabilidad` |

## Ficheros tocados (para la matriz de trazabilidad)

**Backend**
- `ioc_correlator/connectors/greynoise.py` (nuevo) · `ioc_correlator/scorer.py` (regla) · `ioc_correlator/enricher.py` (registro) · `ioc_correlator/ai_analyst.py` (hallazgo GreyNoise)
- `ioc_correlator/connectors/malwarebazaar.py` (fix parser)
- `ioc_correlator/report_pdf.py` (nuevo) · `ioc_correlator/api/routes.py` (endpoint PDF + hook alerta)
- `ioc_correlator/alerting.py` (nuevo)
- `requirements.txt` (+`fpdf2==2.8.1`) · `.env.example` (GreyNoise + ALERT_*)
- Tests: `tests/test_greynoise.py` (nuevo, 16), `tests/test_alerting.py` (nuevo, 12), ajustes en `test_database.py`, `test_scan_endpoint.py`, `test_ai_analyst.py`

**Frontend**
- `src/api/client.ts` (`downloadScanPdf`) · `src/pages/Dashboard.tsx` (botón) · `src/components/ResultsTable.tsx` (limpieza)

## Estado al terminar esta fase

- [x] Tests pasando — **262 verdes** (0 rojos; eran 6 rojos al empezar)
- [x] Frontend compila (`npm run build` OK)
- [x] Variables de entorno documentadas en `.env.example` (`GREYNOISE_API_KEY`, `ALERT_WEBHOOK_URL`, `ALERT_SCORE_THRESHOLD`, `ALERT_WEBHOOK_TYPE`)
- [x] Commits realizados con mensajes convencionales y pusheados
- [ ] Verificación `docker compose up --build` en limpio (pendiente, otra máquina)
- [ ] Capturas de pantalla del botón PDF y de una alerta recibida (pendiente, manual)

## Evidencias (pendientes de captura)

- Captura del dashboard con el botón "Descargar PDF" y del PDF generado.
- Captura de una alerta recibida en Slack/Discord (con webhook de prueba).
- Salida de `pytest` mostrando los 262 tests en verde.
