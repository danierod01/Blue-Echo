# 10 — Estudio y decisión del motor de IA generativa (F7)

> Cierre del ítem **F7** del roadmap del Informe P1 §8. El compromiso de F7 no
> era solo implementar IA, sino **evaluar alternativas y justificar la decisión**
> sobre calidad de respuesta, coste operativo y viabilidad en el servidor. Este
> documento es esa evaluación. Alimenta la memoria P3 (apartado 4 "Requisitos
> modificados" y apartado 5 "Arquitectura y decisiones técnicas").

## 1. Qué se prometió en la P1

F7 planteaba decidir entre **dos** opciones para el motor de IA:

- **Opción A — API de Anthropic (Claude):** mayor calidad en contextos de
  ciberseguridad; coste ~0,001-0,003 €/escaneo.
- **Opción B — Ollama con modelo local:** LLM en el propio VPS, sin coste por
  token; limitado por la RAM del servidor (CX23 = 4 GB).

La decisión debía tomarse tras comparar **calidad**, **coste a largo plazo** y
**viabilidad de recursos** en el servidor actual.

## 2. Restricción determinante: la RAM del VPS

El servidor de producción es un **Hetzner CX23 (≈4 GB RAM)**, compartido entre
Nginx, el backend FastAPI, la base de datos y (tras la P3) también Redis y el
worker Celery. Ollama con un modelo de calidad razonable para análisis de
seguridad (p. ej. Llama 3.1/3.3 8B cuantizado) necesita del orden de 5-8 GB solo
para el modelo; modelos pequeños (3B) caben pero **degradan sensiblemente** la
calidad del análisis, que es justo el factor diferenciador del producto.

**Conclusión parcial:** la Opción B (Ollama local) **no es viable** en el CX23
sin sacrificar la calidad o ampliar el plan (más RAM = más coste mensual), lo que
contradice su única ventaja (coste cero).

## 3. La tercera opción adoptada: Groq

Durante el desarrollo apareció una alternativa que no existía en el planteamiento
original de la P1: **Groq** (inferencia en la nube con aceleradores propios),
que ofrece **Llama 3.3 70B** con un **tier gratuito** y una API compatible.

Esto combina lo mejor de A y B:

- **Calidad** de un modelo grande (70B), superior a lo que cabría en el VPS.
- **Coste cero** en el tier gratuito (como Ollama), sin consumir RAM del servidor
  (como una API en la nube).
- **Sin infraestructura** que mantener en el VPS.

## 4. Comparativa

| Criterio | A · Claude (Anthropic) | B · Ollama local (CX23) | **Adoptado · Groq (Llama 3.3 70B)** |
|---|---|---|---|
| Calidad del análisis | Muy alta | Baja-media (modelo pequeño por RAM) | Alta (modelo 70B) |
| Coste por escaneo | ~0,001-0,003 € | 0 € (pero +RAM/€ VPS) | **0 € (tier gratuito)** |
| Consumo de RAM en el VPS | Nulo | Alto (5-8 GB) — inviable en 4 GB | **Nulo** |
| Latencia | Media | Alta (CPU del VPS) | **Baja (aceleradores)** |
| Privacidad del dato | Sale a un tercero | Local (no sale) | Sale a un tercero |
| Mantenimiento | Ninguno | Alto (actualizar modelos) | Ninguno |
| Límite de uso | Presupuesto | Hardware | Cuota del tier gratuito |

## 5. Decisión final (arquitectura en cascada)

En lugar de elegir **un** proveedor, se implementó una **cascada con degradación
elegante** (`backend/ioc_correlator/ai_analyst.py`), que prioriza calidad y
disponibilidad sin romper nunca la respuesta:

1. **Groq — Llama 3.3 70B** (primario, `GROQ_API_KEY`): calidad alta, coste cero.
2. **Anthropic — Claude Sonnet** (fallback, `ANTHROPIC_API_KEY`): si Groq falla o
   no está configurado y hay presupuesto/clave, se usa Claude por su calidad.
3. **Análisis heurístico local** (último recurso, sin IA): plantillas construidas
   a partir de los datos crudos de los conectores. Garantiza que el análisis
   **siempre** se muestre, aunque no haya ninguna API de IA configurada o todas
   fallen (timeout, cuota agotada, 5xx).

Esto cumple el mandato del `CLAUDE.md` ("si la llamada falla, devolver fallback
con datos crudos, nunca romper la respuesta") y convierte una limitación (cuota
gratuita, red) en una garantía de robustez.

## 6. Justificación del cambio respecto a la P1 (para la memoria)

- **Versión original (P1):** elegir entre Anthropic (A) y Ollama local (B).
- **Versión nueva (P3):** **Groq (Llama 3.3 70B) primario + Claude fallback +
  análisis local**, en cascada.
- **Motivo del cambio:** la Opción B era inviable en el CX23 (4 GB) sin degradar
  la calidad, y la Opción A sola introduce coste variable. Groq —inexistente en
  el planteamiento inicial— resuelve el trilema calidad/coste/recursos, y la
  cascada añade tolerancia a fallos que ninguna de las dos opciones originales
  contemplaba. Es una **mejora sobre lo prometido**, no un recorte.

## 7. Cómo se demuestra / reproduce

- Configurar `GROQ_API_KEY` (tier gratuito) en `.env` → el análisis lo genera
  Llama 3.3 70B. Sin clave, se ve el análisis heurístico local (declararlo así
  en la demo, sin simular que es IA).
- Comprobar qué proveedor actuó: `docker compose logs backend | grep ai_analyst`
  (un warning `fallo en Groq/Anthropic` indica que se pasó al siguiente escalón).
- Modelo configurable con `GROQ_MODEL` (default `llama-3.3-70b-versatile`).

## Estado

- [x] Estudio comparativo redactado (calidad / coste / recursos).
- [x] Decisión justificada + tabla comparativa.
- [x] Cascada implementada y verificada en código (`ai_analyst.py`).
- [x] Justificación del cambio lista para la memoria (apartados 4 y 5).
- [ ] (Opcional) Medir latencia real Groq vs Claude para adjuntar cifras al vídeo.
