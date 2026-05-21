#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Blue-Echo
# Despliegue automatizado sobre un VPS Ubuntu 24.04 limpio.
#
# Uso:
#   chmod +x deploy.sh && ./deploy.sh
#
# Requisito: ejecutar como root o con sudo.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------
REPO_URL="https://github.com/danierod01/blue-echo.git"
INSTALL_DIR="/opt/blue-echo"
COMPOSE_FILE="$INSTALL_DIR/docker-compose.yml"

GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Verificar que se ejecuta como root
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    err "Ejecuta este script como root: sudo ./deploy.sh"
fi

log "Iniciando despliegue de Blue-Echo..."

# ---------------------------------------------------------------------------
# 2. Actualizar el sistema
# ---------------------------------------------------------------------------
log "Actualizando paquetes del sistema..."
apt-get update -qq
apt-get upgrade -y -qq

# ---------------------------------------------------------------------------
# 3. Instalar Docker si no está presente
# ---------------------------------------------------------------------------
if ! command -v docker &>/dev/null; then
    log "Instalando Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
    log "Docker instalado: $(docker --version)"
else
    log "Docker ya instalado: $(docker --version)"
fi

# Verificar Docker Compose v2
if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 no disponible. Actualiza Docker a una versión reciente."
fi
log "Docker Compose: $(docker compose version --short)"

# ---------------------------------------------------------------------------
# 4. Instalar git si no está presente
# ---------------------------------------------------------------------------
if ! command -v git &>/dev/null; then
    log "Instalando git..."
    apt-get install -y -qq git
fi

# ---------------------------------------------------------------------------
# 5. Clonar o actualizar el repositorio
# ---------------------------------------------------------------------------
if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Repositorio ya existe, actualizando..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    log "Clonando repositorio en $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"

# ---------------------------------------------------------------------------
# 6. Crear .env si no existe
# ---------------------------------------------------------------------------
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    warn "Fichero .env creado desde .env.example."
    warn "Se abrirá nano para que añadas tus API keys. Guarda con Ctrl+O y cierra con Ctrl+X."
    warn "El despliegue continuará automáticamente al salir del editor."
    echo ""
    read -r -p "Pulsa ENTER para abrir el editor..."
    nano "$INSTALL_DIR/.env"
fi

# ---------------------------------------------------------------------------
# 7. Construir y arrancar los contenedores
# ---------------------------------------------------------------------------
log "Construyendo imágenes y arrancando contenedores..."
docker compose -f "$COMPOSE_FILE" up -d --build

# ---------------------------------------------------------------------------
# 8. Verificar que el servicio responde
# ---------------------------------------------------------------------------
log "Esperando a que el backend arranque..."
MAX_RETRIES=15
COUNT=0
until curl -sf http://localhost/api/health > /dev/null; do
    COUNT=$((COUNT + 1))
    if [[ $COUNT -ge $MAX_RETRIES ]]; then
        err "El backend no respondió tras $MAX_RETRIES intentos. Revisa los logs: docker compose logs backend"
    fi
    sleep 3
done

# ---------------------------------------------------------------------------
# 9. Mostrar resumen
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Blue-Echo desplegado correctamente${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "  Panel web:   http://$(curl -sf https://ipinfo.io/ip 2>/dev/null || hostname -I | awk '{print $1}')"
echo -e "  Health:      http://localhost/api/health"
echo -e "  Directorio:  $INSTALL_DIR"
echo ""
echo -e "  Logs:        docker compose -C $INSTALL_DIR logs -f"
echo -e "  Parar:       docker compose -C $INSTALL_DIR down"
echo -e "  Actualizar:  git -C $INSTALL_DIR pull && docker compose -C $INSTALL_DIR up -d --build"
echo ""
