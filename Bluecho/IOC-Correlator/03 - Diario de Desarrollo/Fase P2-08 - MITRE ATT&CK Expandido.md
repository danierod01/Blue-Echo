# Fase P2-08 — MITRE ATT&CK Expandido

## Qué se ha construido

Mejora del módulo de mapping MITRE ATT&CK para que cada técnica identificada incluya dos explicaciones: por qué se ha detectado (evidencia concreta del conector que la activó) y en qué consiste la técnica (descripción breve del comportamiento adversario). Las cards en el frontend son ahora expandibles.

---

## Por qué no se usó IA

La IA añadiría variabilidad innecesaria cuando el motivo de detección es siempre determinista: si Shodan detecta el puerto 4444, la razón es siempre la misma. El mapper ya conoce exactamente qué condición activó cada técnica, así que basta con codificar el `reason` en el momento de la atribución. Esto es más rápido, gratuito y consistente.

---

## Cambios en el modelo de datos

Se añadieron dos campos opcionales a `MitreTechnique`:

```python
@dataclass
class MitreTechnique:
    id: str
    name: str
    tactic: str
    url: str
    source: str
    reason: str = ""       # evidencia concreta que activó esta técnica
    description: str = ""  # qué hace el adversario con esta técnica
```

El mismo cambio se propagó al schema Pydantic `MitreTechnique` en `schemas.py` y al interface TypeScript en `client.ts`.

---

## Descripciones en el catálogo _T

Cada entrada del catálogo de técnicas incluye ahora una descripción de 1-2 frases:

```python
"T1090.003": {
    "name": "Multi-hop Proxy (Tor)",
    "tactic": "Command and Control",
    "description": "El adversario enruta el tráfico C2 a través de la red Tor o cadenas de proxies para anonimizar su infraestructura y dificultar el bloqueo."
},
```

---

## Reasons contextuales por fuente

Cada regla de mapping genera un `reason` específico con datos del conector:

| Fuente | Ejemplo de reason |
|---|---|
| ThreatFox | "ThreatFox identifica el IOC como infraestructura de Cobalt Strike." |
| Hybrid Analysis | "El sandbox clasificó la muestra como LockBit." |
| IPinfo (Tor) | "IPinfo confirma que esta IP es un nodo de salida de la red Tor, usada para anonimizar el origen del tráfico C2." |
| Shodan (puerto 4444) | "Shodan detecta el puerto 4444 abierto, puerto por defecto de Metasploit y otros frameworks C2." |
| OTX | "AlienVault OTX referencia este IOC en 3 pulso(s) de amenaza activos..." |
| Criminal IP | "Criminal IP asigna un score critical a esta IP, perfil consistente con servidores C2." |

---

## Componente MitreAttack.tsx

Las técnicas pasaron de ser badges planos a cards expandibles con un componente `TechniqueCard`:

- **Cabecera siempre visible:** ID (monospace), nombre, icono de enlace externo a attack.mitre.org y chevron de expansión.
- **Detalle expandible (clic en chevron):** dos bloques — "Por qué se detectó" y "En qué consiste".
- Si la técnica no tiene reason ni description, el chevron no aparece.

```tsx
function TechniqueCard({ t }: { t: MitreTechnique }) {
  const [expanded, setExpanded] = useState(false);
  // ...
  return (
    <div className={`rounded-lg border text-xs ${color}`}>
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="font-mono font-bold">{t.id}</span>
        <span>{t.name}</span>
        <a href={t.url} target="_blank">...</a>
        {hasDetail && <button onClick={() => setExpanded(v => !v)}>...</button>}
      </div>
      {expanded && hasDetail && (
        <div className="border-t px-3 py-2">
          {t.reason && <p>Por qué se detectó: {t.reason}</p>}
          {t.description && <p>En qué consiste: {t.description}</p>}
        </div>
      )}
    </div>
  );
}
```

---

## Estado al terminar esta fase

- [x] Campo `reason` en `MitreTechnique` con evidencia concreta por fuente
- [x] Campo `description` con descripción de la técnica en todos los TIDs del catálogo
- [x] Reasons contextuales para ThreatFox, Hybrid Analysis, IPinfo, Shodan, OTX y Criminal IP
- [x] Cards expandibles en `MitreAttack.tsx`
- [x] Schema Pydantic y TypeScript actualizados
