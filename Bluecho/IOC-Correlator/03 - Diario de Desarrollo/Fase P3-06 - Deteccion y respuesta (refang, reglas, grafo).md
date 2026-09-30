# Fase P3-06 — Detección y respuesta: refang, reglas y grafo de pivoting

> Sesión del 2026-09-30 (cloud). Rama `feat/detection-response` (partida de
> `feat/soc-watchlist-analytics`). Cuatro funcionalidades de valor real hechas en
> orden de riesgo ascendente, para **no mezclar con lo ya validado**.

## Qué se ha construido

Cuatro piezas que cuentan una historia redonda para el vídeo/memoria:
**entrada real → análisis → detección y respuesta accionables**.

### F1 · Higiene de entrada (refang)

Los analistas copian IOCs de informes de amenazas y correos de phishing donde el
indicador viene "neutralizado" para que no sea clicable. Hasta ahora la herramienta
no los reconocía; ahora sí.

- `utils/validators.refang()` revierte la notación defanged: `hxxp://`/`hxxps://` →
  `http(s)://`, `1[.]2[.]3[.]4` → `1.2.3.4`, `evil[dot]com`/`evil(dot)com` →
  `evil.com`, `user[at]host` → `user@host`, `\.` → `.`, `[:]`/`[://]` → `:`/`://`.
  Es **idempotente**: aplicado sobre un IOC ya normal no lo cambia.
- `detect_ioc_type()` aplica refang primero (reconoce un IOC neutralizado igual que
  su forma real) y los puntos de entrada de escaneo (`_run_scan`, `watchlist_add`,
  `_async_scan`) **guardan el IOC ya normalizado**, de modo que lo almacenado y
  consultado siempre es la forma real.

### F3 · Reglas de bloqueo / respuesta

El propio análisis de IA recomienda *"bloquear en firewall perimetral"*; esto lo
hace real. Cierra el ciclo **detección → respuesta**.

- `response_actions.generate_block_rules()` (texto puro, sin dependencias) produce,
  según el tipo de IOC, reglas listas para pegar:
  - **IP**: iptables, nftables, pf (pfSense/OpenBSD), Cisco ACL, Windows Firewall.
  - **Dominio**: fichero hosts (sinkhole), Unbound, BIND RPZ, Pi-hole.
  - **URL**: reglas del host (firewall o DNS) + ACL de proxy Squid.
  - **Hash**: nota indicando que va en EDR/AV (no se bloquea en red).
  Cada regla lleva una **cabecera de procedencia** (IOC, veredicto, score, aviso).
- `GET /api/history/{id}/blocklist` → `{ioc, ioc_type, formats}`, con aislamiento
  por token.

### F2 · Reglas de detección

Convierte la inteligencia en **detección desplegable**.

- `detection_rules.generate_detection_rules()` (texto puro y determinista):
  - **Sigma** (YAML, agnóstico de SIEM): IP, dominio, URL y hash.
  - **Suricata/Snort** (IDS de red): IP, dominio, URL.
  - **YARA** (ficheros/EDR): hashes, con el módulo `hash`.
  - IDs **deterministas** (uuid5 para Sigma, SID derivado en el rango local de
    Suricata ≥ 1000000): reimportar la misma regla no genera duplicados.
- `GET /api/history/{id}/detection-rules`, aislamiento por token.

### F5 · Grafo visual de pivoting

Visualiza las entidades relacionadas (que ya derivaba `pivots.py`) como un grafo.

- `PivotGraph.tsx`: **node-link en SVG puro** (sin librerías, para no engordar el
  bundle). El IOC escaneado en el centro y cada pivote radial; nodos **clicables →
  escaneo encadenado**.
- Paleta de relaciones **categórica validada para CVD** sobre la superficie oscura
  SOC con la skill `dataviz` (teal-600 `#0d9488` / amber-600 `#d97706` / violet
  `#8b5cf6` / rose `#f43f5e`, todas PASS en banda de luminosidad, separación CVD y
  contraste). La identidad **nunca es solo color**: leyenda por relación + valor
  escrito junto a cada nodo.
- `Pivots.tsx`: toggle **Grafo / Lista** (grafo por defecto).

### Frontend transversal

- `RulesModal.tsx`: modal con pestañas por formato, **copiar** (toast) y
  **descargar** (extensión correcta: `.yml`/`.rules`/`.yar`/…).
- Botones **"Detección"** y **"Bloqueo"** en la barra de acciones del dashboard,
  junto a STIX/MISP/PDF.

## Decisiones técnicas tomadas

| Decisión | Motivo |
|---|---|
| refang en `detect_ioc_type` **y** en los puntos de entrada | El tipo se reconoce siempre; y lo que se persiste/consulta es la forma real, no el IOC neutralizado |
| Reglas de detección/bloqueo **deterministas** (sin LLM) | Robustas y testeables; un fallo de red nunca rompe la función; los IDs estables evitan duplicados al reimportar |
| SID de Suricata en rango ≥ 1.000.000 | Es el rango reservado a reglas locales; no colisiona con los rulesets públicos |
| Endpoints devuelven **JSON `{formats}`** (no un fichero) | Una sola llamada trae todos los formatos; el modal los muestra en pestañas y el usuario copia/descarga el que quiera |
| Grafo en **SVG a mano**, no una librería de grafos | El grafo es pequeño (≤ 12 nodos); una librería (d3/cytoscape) engordaría el bundle sin aportar; la skill `dataviz` desaconseja librerías que no hagan trabajo sustancial |
| Paleta de relaciones **validada con el script** de dataviz | No eyeballear CVD: se corrió `validate_palette.js --mode dark` hasta PASS |

## Comandos clave utilizados

```bash
# Backend
cd backend && python -m pytest -q                         # 376 verdes
cd backend && python -m pytest tests/test_refang.py tests/test_response_actions.py tests/test_detection_rules.py -q

# Frontend
cd frontend && npm run build && npm test                  # build OK + 8 tests

# Validación de la paleta del grafo (skill dataviz)
node scripts/validate_palette.js "#0d9488,#d97706,#8b5cf6,#f43f5e" --mode dark --surface "#05080e"
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| Las reglas de bloqueo/detección contenían el IOC **sin refang** (venía neutralizado) | `generate_*` aplica `refang()` sobre el valor antes de construir la regla |
| La paleta inicial del grafo (teal/amber brillantes) **fallaba la banda de luminosidad** en dark | Se bajó a los tonos 600 (teal-600/amber-600) hasta que el validador de dataviz dio PASS en las 6 comprobaciones |

## Evidencias

- Pegar `hxxp://185[.]220[.]101[.]45` en la barra → escanea `http://185.220.101.45`.
- Botón **Detección** → modal con pestañas Sigma / Suricata (regla con su SID).
- Botón **Bloqueo** → modal con iptables / pf / Cisco / Windows Firewall.
- Panel de entidades relacionadas → **grafo** con el IOC central y pivotes clicables.

![[captura_P3-06_defang.png]]
![[captura_P3-06_reglas_deteccion.png]]
![[captura_P3-06_reglas_bloqueo.png]]
![[captura_P3-06_grafo_pivoting.png]]

## Mapeo a la memoria P3

- **Apartado 6 (Funcionalidades)**: refang (higiene de entrada), reglas de detección,
  reglas de bloqueo/respuesta y grafo de pivoting — cada una con capturas.
- **Apartado 7 (Seguridad)**: el ciclo detección→respuesta refuerza el valor
  defensivo; las reglas se generan pero **se avisa de revisarlas antes de aplicar**.
- **Apartado 8 (Pruebas)**: `test_refang.py` (20), `test_response_actions.py` (10),
  `test_detection_rules.py` (10), `PivotGraph.test.tsx` (2) → backend **376**, FE **8**.
- **Apartado 9 (Matriz)**: filas `MJ-REFANG / MJ-DETECT / MJ-BLOCK / MJ-GRAPH`.

## Estado al terminar esta fase

- [x] Tests pasando — backend **376** verdes, frontend **8** verdes, build OK
- [x] Paleta del grafo validada con el script de dataviz (dark, PASS)
- [x] Commits convencionales (refang+reglas; grafo)
- [x] README actualizado (endpoints detection-rules/blocklist + nota de defang)
- [ ] Verlo en el navegador: grafo, modales de reglas, IOC defanged — pendiente [tú]
- [x] **Sin migración de BD** (no cambian modelos)
