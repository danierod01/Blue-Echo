import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from starlette.requests import Request
from starlette.responses import JSONResponse

from ioc_correlator.api.auth import auth_router
from ioc_correlator.api.limiter import limiter
from ioc_correlator.api.routes import router
from ioc_correlator.database import create_db_and_tables

load_dotenv()

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    if not os.getenv("BLUE_ECHO_API_KEY", "").strip():
        logger.warning(
            "BLUE_ECHO_API_KEY no está configurada — "
            "todos los endpoints de la API están abiertos sin autenticación. "
            "Define la variable en .env antes de desplegar en producción."
        )
    yield


app = FastAPI(
    title="Blue-Echo",
    description="Plataforma de correlación de IOCs con Threat Intelligence e IA generativa.",
    version="1.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse({"error": "Too many requests. Try again later."}, status_code=429)

# CORS: en producción restringe allow_origins al dominio del frontend
_cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)

app.include_router(auth_router, prefix="/api")
app.include_router(router, prefix="/api")
