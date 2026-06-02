# Fase P2-06 — HTTPS y Despliegue en Producción

## Qué se ha construido

Configuración completa de HTTPS con certificado Let's Encrypt para el dominio `blueecho.es`, incluyendo redirect automático HTTP→HTTPS, cabeceras de seguridad TLS y renovación automática sin downtime.

---

## Dominio e infraestructura

- **Dominio:** `blueecho.es` (registrado en IONOS)
- **VPS:** Hetzner Cloud, Ubuntu 24.04, IP `138.199.205.221`
- **DNS:** Registros A `@` y `www` apuntando a la IP del VPS con TTL 300s
- **Propagación:** El registro `.es` tarda horas en procesarse por Red.es (la NIC española)

---

## Obtención del certificado con Certbot

Certbot se instala en el host (no en Docker) y obtiene el certificado vía modo standalone:

```bash
apt install certbot
certbot certonly --standalone -d blueecho.es -d www.blueecho.es
```

El puerto 80 debe estar libre durante la obtención (se para el contenedor de Nginx si está corriendo). Los certificados quedan en:

```
/etc/letsencrypt/live/blueecho.es/fullchain.pem
/etc/letsencrypt/live/blueecho.es/privkey.pem
```

Expiración: 90 días (renovación automática configurada).

---

## nginx.conf actualizado

El fichero `frontend/nginx.conf` se rediseñó con dos server blocks:

### Block 1 — Redirect HTTP→HTTPS

```nginx
server {
    listen 80;
    server_name blueecho.es www.blueecho.es;
    server_tokens off;
    return 301 https://$host$request_uri;
}
```

### Block 2 — HTTPS

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name blueecho.es www.blueecho.es;

    root  /usr/share/nginx/html;
    index index.html;

    ssl_certificate     /etc/letsencrypt/live/blueecho.es/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/blueecho.es/privkey.pem;

    ssl_protocols             TLSv1.2 TLSv1.3;
    ssl_ciphers               HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache         shared:SSL:10m;
    ssl_session_timeout       10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    ...
}
```

**Error cometido durante el proceso:** el bloque HTTPS no incluía `root /usr/share/nginx/html` ni `index index.html`, lo que causaba un error 500 con "rewrite or internal redirection cycle while internally redirecting to /index.html". Corregido añadiendo las directivas.

---

## docker-compose.yml actualizado

Se añadieron el puerto 443 y el volumen de certificados al servicio `frontend`:

```yaml
frontend:
  ports:
    - "80:80"
    - "443:443"
  volumes:
    - /etc/letsencrypt:/etc/letsencrypt:ro
```

El volumen es de solo lectura (`:ro`) — Nginx solo necesita leer los certificados, nunca escribirlos.

**Nota:** Este cambio se hizo directamente en el VPS con `nano` (no con git), ya que los certificados solo existen en producción.

---

## Separación dev/prod del nginx.conf

El `nginx.conf` de producción requiere certificados SSL que no existen en local. Para poder levantar el proyecto localmente sin errores, se creó:

- `frontend/nginx.dev.conf` — servidor HTTP simple sin SSL, sin cabeceras de seguridad TLS
- `docker-compose.dev.yml` — override que monta el config de dev en el contenedor

```yaml
# docker-compose.dev.yml
services:
  frontend:
    ports:
      - "80:80"
    volumes:
      - ./frontend/nginx.dev.conf:/etc/nginx/conf.d/default.conf:ro
```

**En local (Kali):**
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

**En producción (VPS):**
```bash
docker compose up -d --build
```

Docker Compose carga `docker-compose.dev.yml` solo si se especifica con `-f`. En el VPS no se usa, por lo que el config HTTPS bakeado en la imagen es el que se aplica.

---

## Renovación automática del certificado

Certbot usa pre/post hooks para parar y arrancar el contenedor de Nginx durante la renovación, liberando el puerto 80 para el modo standalone:

```bash
# /etc/letsencrypt/renewal-hooks/pre/stop-nginx.sh
docker compose -f /opt/blue-echo/docker-compose.yml stop frontend

# /etc/letsencrypt/renewal-hooks/post/start-nginx.sh
docker compose -f /opt/blue-echo/docker-compose.yml start frontend
```

```bash
certbot renew --dry-run   # Verifica que la renovación funcionará
```

El downtime durante la renovación es de unos pocos segundos, cada 90 días.

---

## Apertura de puertos en el firewall de Hetzner

El firewall de Hetzner Cloud requiere reglas de entrada explícitas. Se añadieron:

| Protocolo | Puerto | Descripción |
|---|---|---|
| TCP | 22 | SSH |
| TCP | 80 | HTTP (redirect a HTTPS) |
| TCP | 443 | HTTPS |
| ICMP | — | Ping |

**Error cometido:** al añadir el puerto 443 se olvidó incluir el 22, lo que dejó el servidor sin acceso SSH hasta añadir la regla.

---

## Estado al terminar esta fase

- [x] Certificado Let's Encrypt obtenido para `blueecho.es` y `www.blueecho.es`
- [x] nginx.conf con redirect HTTP→HTTPS y TLS 1.2/1.3
- [x] HSTS, X-Frame-Options, CSP y demás cabeceras de seguridad
- [x] docker-compose.yml con puerto 443 y volumen de certificados
- [x] Renovación automática con pre/post hooks
- [x] `docker-compose.dev.yml` para desarrollo local sin SSL
- [x] Puertos 22, 80, 443 abiertos en firewall Hetzner
