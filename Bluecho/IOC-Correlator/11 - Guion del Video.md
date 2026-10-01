# 11 — Guion del vídeo de demostración (P3)

> Entregable 2. **MP4, ≥10 min (mínimo estricto), 1080p rec. / 720p mín., audio claro.**
> Sobre el **producto real desplegado desde el repo**, narrado, sin diapositivas.
> Cortes solo para esperas largas y **señalados en pantalla** (un corte que oculte un
> fallo = falta grave). Alojar en **YouTube "no listado"/Drive** y **probar el enlace en
> incógnito**. El enlace va en la portada de la memoria.

Este guion está pensado para **durar ~15 min** (margen cómodo sobre el mínimo de 10) y
para que grabar sea *leer y hacer*. La columna **Req.** indica qué requisitos demuestra
cada escena → al terminar, copiar el minuto real a la columna *Evidencia (vídeo)* de la
**matriz de trazabilidad** (`08 - Requisitos y Matriz…`).

## Antes de grabar (checklist)

- [ ] `.env` con `GROQ_API_KEY` o `ANTHROPIC_API_KEY` (para que el análisis IA sea real, no el heurístico local) y las API keys de fuentes que tengas.
- [ ] Para la demo de watchlist: bajar `WATCHLIST_CHECK_INTERVAL_MINUTES=1` y `WATCHLIST_BEAT_SECONDS=60` en el `.env`.
- [ ] BD limpia: `docker compose -f docker-compose.yml -f docker-compose.dev.yml down -v`.
- [ ] Tener a mano los IOCs de demo (abajo) y un `.log`/`.pcap` de ejemplo.
- [ ] Grabar a 1080p, audio probado, navegador a pantalla completa, zoom de fuente legible.
- [ ] Cerrar pestañas/credenciales personales que no quieras que salgan.

### IOCs de demostración (reales, verificados)

| Uso | Valor |
|---|---|
| IP maliciosa (Tor exit) | `185.220.101.45` |
| IP **defanged** (pegar tal cual) | `185[.]220[.]101[.]45` o `hxxp://185[.]220[.]101[.]45` |
| IP limpia (DNS Google) | `8.8.8.8` |
| Hash de ejemplo (YARA) | un SHA256 conocido de MalwareBazaar |
| Input inválido (caso de error) | `esto-no-es-un-ioc !!` |

---

## Guion minuto a minuto

| Tiempo | Escena | Qué haces / dices | Req. que demuestra |
|---|---|---|---|
| **00:00–00:40** | **Intro** | "Soy [nombre], Blue-Echo / IOC-Correlator, práctica 3. Grupo de una persona. Declaro que he usado **Claude Code** como asistente de desarrollo." Enseña el repo en GitHub un segundo. | Apt. 12 (uso de IA) |
| **00:40–02:10** | **Arranque desde cero** | En terminal limpia: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build`. Mientras construye (corte señalado si tarda), explica la arquitectura (frontend Nginx + backend FastAPI + Postgres + Redis + worker). Al acabar: `docker compose ps` (5 servicios *healthy/up*) y `curl http://localhost/api/health` → `{"status":"ok",...}`. | **RNF-03** (criterio 30%), RF-12 |
| **02:10–02:50** | **Login** | Abre el navegador en `localhost`, pantalla de login, introduce la **X-API-Key**. Explica que la auth es por API key y que cada usuario ve solo lo suyo. | MJ-S1, MJ-AUTH |
| **02:50–05:00** | **Escaneo de principio a fin** ⭐ | Pega `185.220.101.45` y escanea. Ve narrando lo que aparece: detección automática del tipo (IPv4), consulta **en paralelo** a las fuentes, **ThreatScore** con color y veredicto, **tabla por fuente** (VT/AbuseIPDB/Shodan/GreyNoise…), **análisis IA** en lenguaje natural, **MITRE ATT&CK**, **geolocalización** en el mapa. Recalca que es resultado **real**. | RF-01, RF-02, RF-03, RF-04, RF-05, RF-06, RF-08, RF-10, MJ-F6 |
| **05:00–06:00** | **Pivoting + grafo** | En "Entidades relacionadas", muestra el **grafo** (IOC central + pivotes). Haz **clic en un pivote** → escaneo encadenado. Explica que es el flujo real de una investigación. Alterna a vista **Lista**. | MJ-PIVOT, MJ-GRAPH |
| **06:00–07:10** | **Detección → respuesta** ⭐ | Botón **"Detección"**: enseña las pestañas **Sigma / Suricata / YARA**, copia una. Botón **"Bloqueo"**: **iptables / pf / Cisco / Windows Firewall / hosts**. "Convierto la inteligencia en detección y respuesta desplegables." | MJ-DETECT, MJ-BLOCK |
| **07:10–07:50** | **Exportación** | Botón **PDF** (abre el informe). Botones **STIX** y **MISP** (enseña el JSON descargado). "Interoperable con SIEM/TIP." | MJ-F4, MJ-I2 |
| **07:50–08:50** | **Triaje del analista** | En el escaneo, panel **Triaje**: cambia el estado a *Investigando/Confirmado*, añade etiquetas (`tor`, `c2`), escribe una nota, **Guardar** (toast). Enseña que el estado+etiquetas aparecen luego en el **historial**. | MJ-TRIAGE |
| **08:50–10:10** | **Watchlist + monitorización** ⭐ | Añade `185.220.101.45` a la **watchlist**. Explica que el **worker (Celery Beat)** la re-escanea sola. Pulsa **"comprobar ahora"**; enseña el panel de **alertas** (cambio de veredicto). (Tienes el intervalo bajado para que se vea en vivo.) | MJ-WATCH |
| **10:10–11:00** | **Dashboard analítico** | Página **Analítica**: donut de veredictos, serie temporal de 14 días, tipos de IOC, top amenazas. "Visión agregada del trabajo del analista." | MJ-STATS |
| **11:00–12:00** | **Entrada flexible** | (a) Pega el IOC **defanged** `185[.]220[.]101[.]45` → se normaliza y escanea igual. (b) **Bulk scan**: pega varios IOCs. (c) **Subir un `.log`** → el extractor saca los IOCs. | MJ-REFANG, MJ-F1, RF-07 |
| **12:00–12:50** | **PCAP + historial** | Sube un `.pcap` → análisis de tráfico (scapy). Luego abre el **Historial**: lista paginada, clic en un escaneo → **detalle completo**. | RF-09, MJ-R1, (PCAP extra) |
| **12:50–14:00** | **Seguridad y errores** ⭐ | (a) Escanea `esto-no-es-un-ioc !!` → **error controlado** (no rompe, no filtra). (b) Con **otra API key**, intenta abrir un escaneo ajeno → **404** (aislamiento). (c) Página `/invite`: crea un token (rol **analyst** vs **admin**), muestra **revocación/caducidad**. (d) Menciona **rate limiting** y cabeceras de seguridad. | RF (validación), MJ-AUTH, MJ-RBAC, MJ-S2 |
| **14:00–14:40** | **API + estado** | Abre `/docs` (OpenAPI). Enseña **estado de fuentes** (`/api/sources`). (Opcional) `POST /scan/async` → `task_id`. | MJ-I1, RF-12, MJ-R3 |
| **14:40–15:15** | **Cierre** | Recap de 30 s: "IOC real → análisis → detección → respuesta, instalado desde cero por README, 376 tests backend + 8 frontend". Repite que se ha usado **Claude Code**. Menciona el tag `v1.0-practica3` y el repo. | — |

---

## Notas de narración

- **Habla mientras haces** cada paso; no dejes silencios largos ni clips mudos.
- Cada vez que salga un resultado, **di qué requisito estás demostrando** ("esto cubre el score y el veredicto, RF-04 y RF-05").
- Si algo tarda (build, beat), **anúncialo y corta señalándolo en pantalla** ("corto la espera del build, 2 minutos"). Nunca cortes sobre un fallo.
- Si una fuente no tiene API key y devuelve "sin datos", **dilo** — el enunciado exige declarar lo simulado/no disponible; aquí no se simula nada, simplemente esa fuente queda inactiva.
- Deja para el final la frase de **declaración de IA** (apartado 12) bien clara.

## Nota sobre el plugin de navegador (I3)

El plugin es un **cliente opcional** de la API, no la aplicación. El profesor evalúa
el producto desde el **dashboard desplegado** (no necesita instalar nada). Si quieres
enseñarlo en el vídeo (opcional, ~40 s, p. ej. tras la escena de API/estado):

1. Cárgalo en tu navegador (modo desarrollador, carpeta `browser-extension/`).
2. En Opciones pon `URL = https://blueecho.es` + tu API key.
3. Selecciona un IOC en cualquier web → clic derecho → *Escanear en Blue-Echo*, o
   usa el popup. Enseña que funciona **contra el servidor desplegado**.

Deja dicho en voz que es un extra y que la herramienta se usa entera desde el dashboard.

## Tras grabar

- [ ] Rellenar la columna **Evidencia (vídeo)** de la matriz con el minuto real de cada requisito.
- [ ] Subir a YouTube **no listado** / Drive y **probar el enlace en incógnito**.
- [ ] Pegar el enlace en la **portada de la memoria**.
- [ ] Comprobar que el vídeo dura **≥10 min** y el audio se entiende.
