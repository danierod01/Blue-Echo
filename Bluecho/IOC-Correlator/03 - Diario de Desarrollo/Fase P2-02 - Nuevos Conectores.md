# Fase P2-02 — Nuevos Conectores de Threat Intelligence

## Qué se ha construido

Ampliación de la capa de conectores con nueve fuentes nuevas, elevando el total de 7 a 16 conectores. Todos siguen el mismo patrón `BaseConnector` y son transparentes para el resto del sistema. Además, se eliminó GreyNoise por limitaciones del tier gratuito.

---

## Conectores añadidos

### ThreatFox (Abuse.ch)
- **Tipo de IOC:** IP, dominio, hash, URL
- **API key:** No requerida
- **Qué aporta:** Asocia el IOC a familias de malware concretas (Cobalt Strike, Emotet, Qakbot, etc.) y tipos de indicador (C2, payload, etc.).
- **Endpoint:** `POST https://threatfox-api.abuse.ch/api/v1/` con body `{"query": "search_ioc", "search_term": "<valor>"}`
- **Scoring:** +35 si el IOC aparece en la base de datos

### IPinfo
- **Tipo de IOC:** IPv4, IPv6
- **API key:** Sí (tier gratuito: 50.000 req/mes)
- **Qué aporta:** Geolocalización y flags de privacidad: `is_tor`, `is_vpn`, `is_proxy`, `is_hosting`. Especialmente útil para contextualizar IPs que aparecen limpias en otras fuentes pero son infraestructura de anonimización.
- **Scoring:** +25 por cualquier flag de privacidad activo

### Hybrid Analysis
- **Tipo de IOC:** Hash (MD5, SHA1, SHA256)
- **API key:** Sí (tier gratuito disponible)
- **Qué aporta:** Resultados de análisis dinámico (sandbox). Cuando un hash está en la base de datos, devuelve la familia de malware (`vx_family`), el veredicto del sandbox y el entorno de ejecución.
- **Endpoint:** `GET https://www.hybrid-analysis.com/api/v2/search/hash`

### Pulsedive
- **Tipo de IOC:** IP, dominio, URL
- **API key:** Sí (tier gratuito disponible)
- **Qué aporta:** Evaluación de riesgo propia (none, low, medium, high, critical) basada en feeds propios. Complementa las fuentes de reputación clásicas.

### Netlas
- **Tipo de IOC:** IPv4
- **API key:** Sí (tier gratuito disponible)
- **Qué aporta:** Similar a Shodan. Indexa IPs con sus puertos abiertos, servicios y certificados. Se usa para contrastar los puertos identificados por Shodan.
- **Scoring:** +10 por cada puerto sensible abierto (22, 3389, 445, 1433, 4444), máximo +30

### Criminal IP
- **Tipo de IOC:** IPv4
- **API key:** Sí (tier gratuito disponible)
- **Qué aporta:** Puntuación de riesgo propia (0-100) y clasificación (safe, low, moderate, high, critical). Fuente de inteligencia de IPs orientada a SOC.

### MalShare
- **Tipo de IOC:** Hash (MD5, SHA1, SHA256)
- **API key:** Sí (tier gratuito disponible)
- **Qué aporta:** Base de datos de muestras de malware compartidas por la comunidad. Complementa MalwareBazaar para cobertura de hashes.

### Censys
- **Tipo de IOC:** IPv4
- **API key:** Sí, par API ID + Secret (tier gratuito: 250 req/mes)
- **Qué aporta:** Escáner de internet similar a Shodan y Netlas. Aporta los puertos abiertos indexados por su infraestructura de escaneo independiente.

### RDAP (WHOIS moderno)
- **Tipo de IOC:** Dominio
- **API key:** No requerida (protocolo público)
- **Qué aporta:** Fecha de registro del dominio (`registration_date`). Un dominio registrado hace menos de 30 días es inherentemente sospechoso y recibe puntos adicionales en el scoring.
- **Endpoint:** `https://rdap.org/domain/<dominio>` (agregador público de RDAP)
- **Scoring:** +25 si el dominio tiene menos de 30 días; +10 si tiene menos de 90 días

---

## Eliminación de GreyNoise

GreyNoise fue eliminado de la Práctica 2 porque su API de Community tier dejó de ser viable para el tipo de uso del proyecto. Se eliminaron:

- `backend/ioc_correlator/connectors/greynoise.py`
- `backend/tests/test_greynoise.py`
- Regla `_score_greynoise` en `scorer.py`
- Importación y registro en `enricher.py`
- Referencias en `ai_analyst.py`, `mitre_mapper.py` y `ResultsTable.tsx`

---

## MITRE ATT&CK mapping

### Qué se ha construido

Módulo `backend/ioc_correlator/mitre_mapper.py` que cruza los resultados de los conectores con técnicas del framework MITRE ATT&CK y devuelve las técnicas más relevantes.

### Lógica de mapping

Cada conector tiene un conjunto de condiciones que activan técnicas específicas:

| Condición | Técnica MITRE | Táctica |
|---|---|---|
| AbuseIPDB: confianza alta | T1071 — Application Layer Protocol | Command and Control |
| IPinfo: is_tor = true | T1090.003 — Multi-hop Proxy | Defense Evasion |
| Shodan/Netlas: puerto 4444 abierto | T1219 — Remote Access Software | Command and Control |
| ThreatFox: malware conocido | T1059 — Command and Scripting Interpreter | Execution |
| MalwareBazaar/Hybrid Analysis: hash encontrado | T1204 — User Execution | Execution |
| OTX: pulsos activos | T1566 — Phishing | Initial Access |

### Visualización en el frontend

Componente `MitreAttack.tsx` con cards por técnica que muestran el ID, nombre, táctica y enlace directo al `attack.mitre.org`. Solo aparece si hay al menos una técnica identificada.

---

## Estado al terminar esta fase

- [x] 9 conectores nuevos implementados
- [x] GreyNoise eliminado completamente
- [x] MITRE ATT&CK mapping con visualización en dashboard
- [x] Tabla de fuentes en frontend actualizada con todos los conectores
- [x] Tests unitarios para los nuevos conectores
