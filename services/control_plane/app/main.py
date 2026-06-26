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

    # v1.2-US-1: multi-tenant org resolution middleware. Resolves
    # `org_id` from either (1) `Authorization: Bearer <jwt>` (HS256
    # with `org_id` claim) or (2) `X-Org-Id: <id>` header (test context).
    # Missing both on non-public paths → 401 (per architect IC-3:
    # no silent default). Production MUST set `TL_JWT_SECRET` to a
    # 32+ byte HMAC secret via env var. Tests use `X-Org-Id` directly
    # (no secret required).
    #
    # v1.2 (post-EXA research + runtime debugging 2026-06-26): we use
    # a PURE ASGI middleware (`OrgResolverASGIMiddleware`) instead of
    # `@app.middleware("http")` (which is BaseHTTPMiddleware under
    # the hood and creates a NEW Request object between middleware
    # and dependencies — breaking `request.state.org_id` propagation).
    # Pure ASGI writes directly to `scope["state"]`, which IS the
    # same dict the FastAPI Request exposes as `request.state`. See
    # app/middleware/__init__.py for the full rationale.
    from app.middleware import OrgResolverASGIMiddleware
    app.add_middleware(OrgResolverASGIMiddleware)

    # v3.0 W1.4: EU AI Act Article 50(2) disclosure middleware.
    # Adds `X-Disclosure-AI` header to every response (except public paths).
    # Per EU AI Office Code of Practice on Transparency (10 June 2026).
    # Per Plan v3.0 W1.4 — closes the EU AI Act Art. 50 marking gap
    # before the 2 August 2026 deadline (37 days from this commit).
    from app.middleware.article50 import Article50DisclosureMiddleware
    app.add_middleware(Article50DisclosureMiddleware)

    # Routers
    app.include_router(health.router, tags=["health"])
    app.include_router(disclosures.router, prefix="/v1", tags=["disclosures"])
    app.include_router(verify.router, prefix="/v1", tags=["verify"])
    app.include_router(evidence.router, prefix="/v1", tags=["evidence"])

    return app


app = create_app()
