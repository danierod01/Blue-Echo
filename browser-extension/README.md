# Blue-Echo IOC Scanner — Extensión de navegador

Extensión **Manifest V3** que permite escanear IOCs (IP, hash, dominio, URL)
contra tu instancia de Blue-Echo sin salir del navegador — desde un popup o
seleccionando texto y usando el menú contextual (clic derecho → *"Escanear … en
Blue-Echo"*).

Implementa el ítem **I3** del roadmap de la Práctica 1.

## El plugin es un cliente opcional, no la aplicación

La **aplicación** es el dashboard web desplegado (p. ej. `https://blueecho.es`):
se abre en el navegador y se usa entera **sin instalar nada**. El plugin es solo
un **cliente ligero** de la API pública (`POST /api/scan/json`), una comodidad
para escanear un IOC desde cualquier página sin abrir el dashboard.

Por tanto, **para evaluar el producto no hace falta instalar el plugin**: basta
con abrir la URL desplegada. El plugin:

- se **demuestra en el vídeo** cargándolo en tu navegador y apuntándolo al
  servidor desplegado (`URL = https://blueecho.es` + API key en Opciones);
- si alguien quiere probarlo, se instala **"descomprimido"** desde este repo
  (ver *Instalación*) apuntando al mismo servidor. No está publicado en la
  Chrome Web Store / Firefox AMO (eso requiere revisión + cuota, innecesario aquí).

Como declara `host_permissions: <all_urls>`, funciona contra **cualquier**
instancia de Blue-Echo accesible (localhost o el servidor de Hetzner) con solo
cambiar la URL en sus Opciones — no depende de tener el backend en local.

## Qué hace

- **Popup** (icono de la barra): escribe o pega un IOC y pulsa *Escanear*; se
  muestra el score, el veredicto (con color) y el resumen de la IA.
- **Menú contextual**: selecciona una IP/hash/dominio/URL en cualquier página,
  clic derecho → *Escanear … en Blue-Echo*; el resultado llega como notificación.
- **Auto-relleno**: el popup precarga el texto que tengas seleccionado.

Todas las peticiones van a `POST /api/scan/json` de tu servidor. La extensión no
almacena datos fuera de tu navegador (solo la URL del servidor y, opcionalmente,
tu API key en `chrome.storage.sync`).

## Instalación

### Firefox
1. Abre `about:debugging#/runtime/this-firefox`.
2. *Cargar complemento temporal…* → selecciona `browser-extension/manifest.json`.

### Chrome / Edge / Brave
1. Abre `chrome://extensions`.
2. Activa el *Modo de desarrollador*.
3. *Cargar descomprimida* → selecciona la carpeta `browser-extension/`.

## Configuración

Tras instalarla, abre sus **Opciones** (icono ⚙ del popup) y define:

- **URL del servidor**: la base de tu instancia, p. ej. `https://blueecho.es`
  o `http://localhost` en desarrollo (sin barra final).
- **API key** (opcional): si tu servidor tiene la autenticación activada
  (`BLUE_ECHO_API_KEY`), pega aquí tu token.

## Notas

- La extensión usa `host_permissions`, por lo que sus peticiones **no dependen de
  la política CORS** del servidor (el navegador las autoriza por el permiso de host).
  Funciona igual con `CORS_ORIGINS` restringido en producción.
- El icono es un SVG; Firefox lo admite en MV3. En Chromium, si tu versión no
  renderiza el SVG, verás el icono genérico de extensión (no afecta a la función).
