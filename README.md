# IOC-Correlator

Plataforma web de correlación de Indicadores de Compromiso (IOCs) contra múltiples fuentes de Threat Intelligence, con análisis en lenguaje natural generado por IA.

## Qué hace

Dado un IOC (IP, hash MD5/SHA1/SHA256, dominio, URL) o un fichero de logs, la plataforma:

1. Extrae y normaliza los IOCs del input.
2. Los consulta en paralelo contra VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, MalwareBazaar, URLhaus y GreyNoise.
3. Calcula un **score de amenaza** (0-100) basado en los resultados consolidados.
4. Genera un **resumen ejecutivo** en español usando la API de Claude (Anthropic).
5. Muestra todo en un dashboard React con código de colores por nivel de amenaza.
6. Almacena el historial de escaneos en base de datos.

## Stack técnico

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 + FastAPI + httpx (async) + SQLModel |
| IA | Anthropic Claude (claude-sonnet-4-20250514) |
| Frontend | React 18 + Vite + TypeScript + Tailwind CSS + shadcn/ui |
| Infra | Docker Compose + Nginx + Hetzner Cloud VPS |

## Inicio rápido (desarrollo local)

```bash
# 1. Clona el repositorio
git clone https://github.com/danierod01/ioc-correlator.git
cd ioc-correlator

# 2. Configura las variables de entorno
cp .env.example .env
# Edita .env y añade tus API keys

# 3. Levanta los servicios
docker compose up -d --build

# 4. Verifica que el backend responde
curl http://localhost/api/health
```

El panel web estará disponible en `http://localhost`.

## API REST

| Método | Endpoint | Descripción |
|---|---|---|
| POST | `/api/scan` | Escanea un IOC o fichero de logs |
| GET | `/api/history` | Lista los últimos escaneos |
| GET | `/api/history/{id}` | Detalle de un escaneo |
| GET | `/api/health` | Estado del servicio |
| GET | `/api/sources` | Estado de los conectores |

## Fuentes de Threat Intelligence

| Fuente | Tipos de IOC soportados |
|---|---|
| VirusTotal | IP, Hash, Dominio, URL |
| AbuseIPDB | IP |
| Shodan | IP |
| AlienVault OTX | IP, Hash, Dominio |
| MalwareBazaar | Hash |
| URLhaus | URL, Dominio |
| GreyNoise | IP |

## Estructura del repositorio

```
ioc-correlator/
├── backend/          # FastAPI (Python)
├── frontend/         # React + Vite + TypeScript
├── docker-compose.yml
├── deploy.sh         # Script de despliegue para Hetzner Ubuntu 24.04
├── .env.example      # Plantilla de variables de entorno
└── .gitignore
```

## Despliegue en producción

Ver [deploy.sh](deploy.sh) para el script de despliegue automatizado sobre un VPS Ubuntu 24.04 limpio.

## Licencia

Proyecto académico — Máster en Ciberseguridad 2025-2026.
