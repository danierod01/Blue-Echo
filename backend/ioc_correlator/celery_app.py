"""Configuración de Celery (roadmap R3).

Define la aplicación Celery que usa **Redis** como broker de mensajes y como
backend de resultados. El worker se levanta en docker-compose con:

    celery -A ioc_correlator.celery_app worker --loglevel=info

El escaneo síncrono clásico (`POST /api/scan`) sigue funcionando sin Celery ni
Redis; la cola solo interviene en los endpoints async (`POST /api/scan/async`).

En los tests se activa `task_always_eager` (vía la variable de entorno
`CELERY_TASK_ALWAYS_EAGER`) para ejecutar las tareas en el mismo proceso, sin
necesidad de un Redis real.
"""

import os

from celery import Celery

_broker = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1")


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


celery_app = Celery(
    "blue_echo",
    broker=_broker,
    backend=_backend,
    include=["ioc_correlator.tasks"],  # registra las tareas al arrancar el worker
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    result_expires=3600,            # los resultados caducan a la hora
    task_always_eager=_truthy(os.getenv("CELERY_TASK_ALWAYS_EAGER", "")),
    task_eager_propagates=True,
)
