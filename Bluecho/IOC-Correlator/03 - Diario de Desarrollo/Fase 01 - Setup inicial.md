# Fase 01 — Setup inicial

## Qué se ha construido

Estructura base del repositorio con las reglas de seguridad aplicadas desde el primer fichero:

- `.gitignore` creado **antes** que cualquier otro fichero.
- `.env.example` con todas las variables de entorno del proyecto (valores vacíos).
- `README.md` con descripción, stack, API reference y guía de inicio rápido.
- Árbol de carpetas completo: `backend/ioc_correlator/{api,connectors,utils}` y `frontend/src/{api,components,pages}`.

## Decisiones técnicas tomadas

**El `.gitignore` es siempre el primer fichero.** Si se crea después de subir código, git ya ha trackeado los ficheros y el `.gitignore` no los excluye retroactivamente. Para este proyecto, donde se manejan API keys reales, el riesgo de filtración es real.

**Solo `.env.example` en el repo, nunca `.env`.** El `.env.example` documenta qué variables existen y para qué sirven. El `.env` real lo rellena el desarrollador a mano y nunca sale del servidor.

## Comandos clave utilizados

```bash
# Crear estructura de carpetas
mkdir -p backend/ioc_correlator/api \
          backend/ioc_correlator/connectors \
          backend/ioc_correlator/utils \
          frontend/src/api \
          frontend/src/components \
          frontend/src/pages

# Crear __init__.py en cada paquete Python
touch backend/ioc_correlator/__init__.py \
      backend/ioc_correlator/api/__init__.py \
      backend/ioc_correlator/connectors/__init__.py \
      backend/ioc_correlator/utils/__init__.py

# Copiar plantilla de entorno (esto lo hace el usuario)
cp .env.example .env
```

## Problemas encontrados y soluciones

| Problema | Solución |
|---|---|
| `.venv/` no estaba en el `.gitignore` inicial | Se añadió `backend/.venv/` al crearlo en el módulo 2 |

## Estado al terminar esta fase

- [x] `.gitignore` cubre `.env`, `*.db`, `node_modules`, `__pycache__`, `.venv`
- [x] `.env.example` con las 10 variables del proyecto documentadas
- [x] `README.md` con tabla de endpoints y guía de inicio rápido
- [x] Estructura de carpetas completa y lista para los módulos siguientes
