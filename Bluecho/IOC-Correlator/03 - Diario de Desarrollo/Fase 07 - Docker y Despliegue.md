# Fase 07 — Docker y Despliegue en Hetzner

## Módulo 16 — Docker (completado)

### Qué se ha construido

| Fichero | Propósito |
|---|---|
| `backend/Dockerfile` | Imagen Python 3.11 multi-stage para el backend FastAPI |
| `frontend/Dockerfile` | Imagen Node 22 (build) + Nginx 1.27 (runtime) para el frontend |
| `frontend/nginx.conf` | Proxy `/api/` → backend, SPA fallback, gzip, caché de assets |
| `docker-compose.yml` | Orquestación de los dos servicios + volumen persistente para la BD |

### Arquitectura de contenedores

```
Internet
    │ :80
    ▼
┌─────────────────────────────────┐
│  frontend (Nginx)               │
│  - sirve /usr/share/nginx/html  │
│  - proxy /api/* → backend:8000  │
└──────────────┬──────────────────┘
               │ :8000 (interno, no expuesto)
               ▼
┌─────────────────────────────────┐
│  backend (FastAPI + uvicorn)    │
│  - monta volumen db_data        │
│  - lee .env para las API keys   │
└─────────────────────────────────┘
               │
               ▼
         db_data (volumen Docker)
         /app/data/ioc_correlator.db
```

### Decisiones técnicas tomadas

**Multi-stage build en ambas imágenes.**
El stage `builder` instala dependencias / compila. El stage `runtime` solo copia artefactos finales. Reduce el tamaño de la imagen ~300-400 MB y elimina compiladores de la superficie de ataque.

**Backend: usuario sin privilegios.**
El proceso `uvicorn` corre como `appuser`. Si el contenedor es comprometido, el atacante no tiene privilegios de root en el host.

**Puerto 8000 solo interno (`expose`, no `ports`).**
El backend no es accesible directamente desde internet. Solo Nginx lo alcanza por la red Docker interna. El único punto de entrada público es el puerto 80.

**Frontend: `VITE_API_BASE_URL` vacío en el build.**
Las peticiones del frontend van a `/api/*` (mismo origen). Nginx intercepta y hace proxy al backend. Evita CORS en producción.

**React Router: `try_files $uri $uri/ /index.html`.**
Sin esto, refrescar `/history` devuelve 404. El fallback a `index.html` deja que React Router maneje la ruta.

**Volumen `db_data` para la BD SQLite.**
La BD vive en `/app/data/ioc_correlator.db` fuera del sistema de ficheros del contenedor. Persiste tras `docker compose down` (pero no tras `down -v`).

**`healthcheck` en el backend.**
El frontend usa `depends_on: condition: service_healthy`. Docker espera a que el backend responda en `/api/health` antes de arrancar Nginx.

**`restart: unless-stopped`.**
Los contenedores se reinician automáticamente tras un fallo o reinicio del servidor.

### Comandos clave

```bash
# Primera vez: construir y arrancar
docker compose up -d --build

# Verificar que todo funciona
curl http://localhost/api/health

# Ver logs en tiempo real
docker compose logs -f backend

# Reconstruir solo el backend tras cambios de código
docker compose up -d --build backend

# Parar sin borrar datos
docker compose down

# Parar Y borrar la BD (cuidado)
docker compose down -v
```

### Prerrequisitos antes de `docker compose up`

1. Docker Engine instalado (`docker --version`)
2. Fichero `.env` creado a partir de `.env.example` con las API keys reales
3. No es necesario tener Python ni Node.js en el host

### Estado al terminar este módulo

- [x] `backend/Dockerfile` multi-stage (builder + runtime, usuario no root)
- [x] `frontend/Dockerfile` multi-stage (Node 22 build + Nginx 1.27 runtime)
- [x] `frontend/nginx.conf` con proxy, SPA fallback, gzip y caché de assets
- [x] `docker-compose.yml` con healthcheck, volumen persistente, dependencias entre servicios
- [x] Backend no expuesto directamente a internet

---

## Módulo 17 — deploy.sh (completado)

### Qué se ha construido

Script `deploy.sh` de despliegue automatizado para un VPS Ubuntu 24.04 limpio. Ejecuta en orden:

1. Verifica que corre como root
2. Actualiza paquetes del sistema (`apt-get upgrade`)
3. Instala Docker Engine si no está presente (via `get.docker.com`)
4. Instala git si no está presente
5. Clona el repositorio en `/opt/blue-echo` (o hace `git pull` si ya existe)
6. Si no existe `.env`, lo crea desde `.env.example` y **para la ejecución** pidiendo al usuario que rellene las API keys
7. Ejecuta `docker compose up -d --build`
8. Espera hasta 45 segundos a que `/api/health` responda (15 reintentos × 3 s)
9. Muestra la IP pública del servidor y comandos útiles

### Decisiones técnicas tomadas

**`set -euo pipefail`.**
El script falla inmediatamente ante cualquier error, variable no definida o pipe roto. Evita que un fallo silencioso en un paso deje el sistema a medias.

**Parada explícita si `.env` no existe.**
En lugar de arrancar la aplicación sin API keys, el script para con un mensaje claro indicando que hay que editar `.env`. Esto evita confusión al ver que los conectores están todos inactivos.

**Health check con reintentos.**
`docker compose up` retorna inmediatamente sin esperar a que el backend esté listo. El bucle de espera garantiza que el mensaje final de "desplegado correctamente" es real.

**Muestra la IP pública en el resumen final.**
Usa `curl ipinfo.io/ip` con fallback a `hostname -I` para mostrar la URL accesible desde internet, sin que el usuario tenga que buscarla.

### Flujo de uso en el servidor

```bash
# Primera vez en un VPS limpio
ssh root@<IP>
curl -fsSL https://raw.githubusercontent.com/danierod01/blue-echo/main/deploy.sh -o deploy.sh
chmod +x deploy.sh && ./deploy.sh
# → El script para y pide editar .env
nano /opt/blue-echo/.env
cd /opt/blue-echo && docker compose up -d --build

# Actualización tras cambios en el repositorio
git -C /opt/blue-echo pull
docker compose -C /opt/blue-echo up -d --build
```

### Estado al terminar este módulo

- [x] `deploy.sh` con `set -euo pipefail` (falla limpiamente)
- [x] Instalación automática de Docker y git si no están presentes
- [x] Parada explícita si `.env` no está configurado
- [x] Health check con reintentos antes de declarar éxito
- [x] Resumen final con IP pública y comandos útiles
- [x] README actualizado con Opción C (pasos completos para Hetzner)
