# Resumen Ejecutivo

## Nombre del proyecto
**IOC-Correlator** — Plataforma web de correlación de Indicadores de Compromiso con Threat Intelligence e IA generativa.

## Problema que resuelve
Los analistas de seguridad blue team pierden tiempo consultando manualmente cada IOC (IP, hash, dominio, URL) en múltiples fuentes de Threat Intelligence. IOC-Correlator automatiza este proceso: en segundos obtiene datos de 7 fuentes, calcula un score de amenaza consolidado y genera un análisis en lenguaje natural usando IA generativa.

## Solución implementada
Plataforma full-stack accesible desde internet con:
- **Backend** FastAPI (Python) con conectores asíncronos a 7 fuentes de TI.
- **Motor de scoring** que calcula un riesgo 0-100 con reglas ponderadas por fuente.
- **IA generativa** (Claude de Anthropic) que produce un resumen ejecutivo del IOC en español.
- **Dashboard React** con código de colores por nivel de amenaza y historial de consultas.
- **Despliegue en producción** sobre Hetzner Cloud con Docker Compose y Nginx.

## Fuentes de Threat Intelligence integradas
VirusTotal · AbuseIPDB · Shodan · AlienVault OTX · MalwareBazaar · URLhaus · GreyNoise

## Stack tecnológico
| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 + FastAPI + httpx async + SQLModel + SQLite |
| IA | Anthropic Claude (claude-sonnet-4-20250514) |
| Frontend | React 18 + Vite + TypeScript + Tailwind CSS + shadcn/ui |
| Infraestructura | Docker Compose + Nginx + Hetzner Cloud VPS Ubuntu 24.04 |

## Resultado académico esperado
Herramienta funcional, desplegada y documentada. Entrega: **25 de mayo de 2026**.
