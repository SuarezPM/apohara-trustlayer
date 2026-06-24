"""FastAPI application entrypoint for the TrustLayer Control Plane."""

from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import disclosures, evidence, health, verify
from app.config import get_settings

settings = get_settings()
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks."""
    log.info(
        "control_plane.startup",
        service=settings.service_name,
        env=settings.environment,
        org_id=settings.org_id,
        tsa_provider=settings.tsa_provider,
    )
    yield
    log.info("control_plane.shutdown", service=settings.service_name)


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title="Apohara TrustLayer Control Plane",
        version="0.1.0",
        description="Evidence-grade AI compliance API per EU AI Act Art. 50 + DORA.",
        lifespan=lifespan,
        # OpenAPI 3.1 generated automatically by FastAPI / pydantic v2.
        openapi_version="3.1.0",
    )

    # CORS — permissive in dev, locked down via env in prod.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Routers
    app.include_router(health.router, tags=["health"])
    app.include_router(disclosures.router, prefix="/v1", tags=["disclosures"])
    app.include_router(verify.router, prefix="/v1", tags=["verify"])
    app.include_router(evidence.router, prefix="/v1", tags=["evidence"])

    return app


app = create_app()
