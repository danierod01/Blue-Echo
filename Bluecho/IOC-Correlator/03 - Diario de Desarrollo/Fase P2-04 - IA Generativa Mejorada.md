# Fase P2-04 — IA Generativa Mejorada

## Qué se ha construido

Tres mejoras sobre el módulo de IA original: soporte para múltiples proveedores (con fallback automático), reestructuración del output en secciones Markdown y renderizado de esas secciones en el frontend con `react-markdown`.

---

## Multi-proveedor con fallback en cadena

### Proveedores configurados

**Groq (proveedor principal)**
- Modelo: `llama-3.3-70b-versatile`
- API key: `GROQ_API_KEY`
- Tier gratuito: disponible sin coste
- Latencia media: ~2 segundos para 1.000 tokens

**Anthropic Claude (fallback)**
- Modelo: `claude-sonnet-4-20250514`
- API key: `ANTHROPIC_API_KEY`
- Solo se usa si Groq falla o no tiene key configurada

**Análisis local (fallback final)**
- Sin coste, sin dependencias externas
- Genera el mismo formato de 4 secciones directamente en Python
- Cubre todos los conectores activos en el proyecto

### Lógica de fallback

```python
async def generate_summary(...) -> str:
    if groq_key:
        try:
            return await _groq_analysis(...)
        except Exception as exc:
            logger.warning("fallo en Groq — %s", exc)
    if anthropic_key:
        try:
            return await _claude_api_analysis(...)
        except Exception as exc:
            logger.warning("fallo en Anthropic — %s", exc)
    return _local_analysis(...)
```

La función nunca lanza excepción. Si todos los proveedores fallan, el análisis local garantiza que `ai_summary` siempre contiene texto útil.

---

## Informe estructurado en 4 secciones Markdown

### Problema con el output anterior

El output original era un párrafo de texto continuo. Útil, pero difícil de leer cuando contiene información de muchas fuentes. En la Práctica 2 se rediseñó el system prompt para forzar un informe con secciones fijas.

### Nuevo system prompt

```
## Resumen
Una o dos frases indicando el tipo de IOC, el nivel de amenaza y el score.

## Hallazgos por fuente
Para cada fuente con datos relevantes:
- **NombreFuente**: hallazgo clave con datos concretos.

## Contexto de amenaza
Dos o tres frases sobre qué tipo de actor o actividad sugieren los datos:
C2, nodo Tor, scanner masivo, malware conocido, phishing...

## Recomendaciones
Lista de 2-4 acciones concretas y priorizadas para el equipo de seguridad.
```

El prompt especifica explícitamente que no se añadan introducciones ni texto fuera de las secciones. Esto reduce el "relleno" típico de los LLMs y garantiza densidad informativa.

### Análisis local con el mismo formato

`_local_analysis()` fue reescrita para producir exactamente las mismas 4 secciones, cubriendo los 9 conectores activos del proyecto: VirusTotal, AbuseIPDB, Shodan, OTX, MalwareBazaar, ThreatFox, IPinfo, Hybrid Analysis y Pulsedive.

---

## Renderizado Markdown en el frontend

### Problema

El componente `AiSummary.tsx` original usaba `<p>{summary}</p>`. Con el nuevo formato estructurado, los `##` y los `-` aparecían como texto plano en lugar de renderizarse como cabeceras y listas.

### Solución

Se añadió `react-markdown` al proyecto y se actualizó el componente:

```tsx
import ReactMarkdown from "react-markdown";

<div className="prose prose-invert prose-sm ...
  [&_h2]:text-blue-300 [&_h2]:font-semibold [&_h2]:text-xs
  [&_h2]:uppercase [&_h2]:tracking-wider ...">
  <ReactMarkdown>{summary}</ReactMarkdown>
</div>
```

Los selectores de Tailwind `[&_h2]:...` aplican estilos específicos a los elementos generados por react-markdown sin necesidad de modificar el output del modelo.

### Activación

Los cambios requieren reconstruir la imagen Docker del frontend para que `react-markdown` se instale en el contenedor:

```bash
docker compose up -d --build
```

---

## Estado al terminar esta fase

- [x] Soporte para Groq como proveedor principal (gratuito)
- [x] Fallback automático: Groq → Anthropic → análisis local
- [x] System prompt rediseñado con 4 secciones Markdown fijas
- [x] Análisis local actualizado con mismo formato y todos los conectores
- [x] `react-markdown` integrado en `AiSummary.tsx`
- [x] Estilos Tailwind para cabeceras, listas y código en el bloque IA
