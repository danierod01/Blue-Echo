import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ioc_correlator.api.routes import router
from ioc_correlator.database import create_db_and_tables

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title="Blue-Echo",
    description="Plataforma de correlación de IOCs con Threat Intelligence e IA generativa.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS: en producción restringe allow_origins al dominio del frontend
_cors_origins = os.getenv("CORS_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")
