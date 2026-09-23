# CONTEXT.md — Estado del proyecto Blue-Echo

> **Leer esto al inicio de cada sesión antes de tocar nada.**
> Actualizar al final de cada sesión con los cambios realizados.

---

## Estructura de ramas

| Rama | Descripción | Estado |
|---|---|---|
| `main` | **Rama principal activa** — contiene todo (P1 + P2 + rediseño) | Desarrollo activo aquí |
| `feat/pcap-https` | Rama intermedia de P2 — ya mergeada en main | Obsoleta |
| `design` | Rama de rediseño — ya mergeada en main | Obsoleta |

**Trabajar siempre desde `main`.** Las ramas intermedias ya están incorporadas.

---

## Qué hay en cada práctica

### Práctica 1 (`main`)
- 7 conectores: VirusTotal, AbuseIPDB, Shodan, OTX, MalwareBazaar, URLhaus, GreyNoise
- Scoring 0-100, 4 veredictos (LIMPIO / SOSPECHOSO / MALICIOSO / CRÍTICO)
- Análisis IA con Claude (AsyncAnthropic)
- Caché TTL en memoria
- Frontend: Dashboard + Historial + Detalle
- Docker multi-stage + Nginx + deploy.sh
- Desplegado en HTTP en IP directa de Hetzner

### Práctica 2 (`feat/pcap-https`) — sobre lo anterior añade:
- **Autenticación** con X-API-Key + rate limiting (slowapi)
- **HTTPS** con Let's Encrypt en blueecho.es (dominio propio)
- **10+ conectores nuevos**: ThreatFox, URLScan, IPInfo, RDAP, SecurityTrails, Hybrid Analysis, Netlas, Criminal IP, MalShare, Pulsedive, Censys
- **Bulk scan**: escaneo de múltiples IOCs a la vez
- **MITRE ATT&CK**: mapping con reason + description por técnica
- **Análisis PCAP**: upload de fichero .pcap, reconstrucción TCP con scapy, extracción de objetos HTTP maliciosos con detección por magic bytes, modal de advertencia antes de descargar
- **Geolocalización**: mapa interactivo con react-leaflet usando ipwho.is (IPs, dominios y URLs), visible también en el historial
- **Historial de PCAP**: los escaneos de ficheros aparecen en historial con veredicto "CAPTURA DE RED"
- **Login**: página de autenticación con X-API-Key
- **Documentación Obsidian**: notas de fases P2-06 y P2-07 en `Bluecho/IOC-Correlator/`

### Rediseño UI (`design`) — sobre `feat/pcap-https` añade:
- Fuentes: Space Grotesk (UI) + JetBrains Mono (datos)
- Fondo oscuro `#08080f`, sin dot grid
- Header minimalista h-12 con línea de acento azul inferior
- ThreatScore: número enorme con glow del color del veredicto, sin gauge SVG
- ResultsTable: filas compactas monospace agrupadas por tipo de IOC
- EmptyState: radar animado
- SkeletonResults: shimmer loader
- App.tsx: header minimalista, UserMenu con avatar BE

**Componentes pendientes de rediseñar (en `main`):**
- `AiSummary.tsx`
- `SearchBar.tsx`
- `SourcesStatus.tsx`
- `Login.tsx`
- `tailwind.config.js` (keyframes)
- `Dashboard.tsx` (ajustes finales de layout)

---

## Infraestructura de producción

- **VPS**: Hetzner CX23 — IP `138.199.205.221`
- **Dominio**: blueecho.es (HTTPS con Let's Encrypt, auto-renovación)
- **Acceso**: `ssh root@138.199.205.221`
- **Directorio en producción**: `/opt/blue-echo`
- **Arranque**: `docker compose up -d --build` desde `/opt/blue-echo`
- **Dev local (Kali)**: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`

---

## Flujo de trabajo habitual

```bash
# Al empezar (en cualquier máquina)
git pull origin main

# Al terminar
git add <ficheros>
git commit -m "..."
git push origin main
```

**Rama activa actual: `main`**

---

## Ficheros clave a conocer

| Fichero | Qué hace |
|---|---|
| `backend/ioc_correlator/api/routes.py` | Todos los endpoints REST |
| `backend/ioc_correlator/api/schemas.py` | Modelos Pydantic (request/response) |
| `backend/ioc_correlator/pcap_analyzer.py` | Análisis PCAP con scapy |
| `backend/ioc_correlator/mitre_mapper.py` | Mapping MITRE ATT&CK |
| `backend/ioc_correlator/geolocator.py` | Geolocalización con ipwho.is |
| `backend/ioc_correlator/connectors/` | Todos los conectores TI |
| `frontend/src/pages/Dashboard.tsx` | Página principal |
| `frontend/src/pages/ScanDetail.tsx` | Detalle de escaneo del historial |
| `frontend/src/lib/utils.ts` | VERDICT_LABEL, VERDICT_COLOR, etc. |
| `CLAUDE.md` | Instrucciones de arquitectura para el agente |

---

## Última sesión trabajada

**Fecha**: 2026-09-23
**Rama**: `main` (antes `design`, mergeada a main al final de la sesión)
**Resumen**:
- Rediseño radical de la UI: nuevas fuentes (Space Grotesk + JetBrains Mono), ThreatScore sin gauge SVG, ResultsTable compacta monospace, header minimalista con línea de acento azul.
- Creado `CONTEXT.md` para continuidad entre máquinas y sesiones.
- Mergeadas todas las ramas (`design`, `feat/pcap-https`) en `main`. A partir de ahora todo el desarrollo va en `main`.
- Pendiente: completar rediseño de `AiSummary`, `SearchBar`, `SourcesStatus`, `Login`, `tailwind.config.js` y ajustes de `Dashboard`.
