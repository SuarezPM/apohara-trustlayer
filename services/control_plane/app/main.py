"""FastAPI application entrypoint for the TrustLayer Control Plane."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import (
    adversarial,
    cross_jurisdiction,
    disclosures,
    dora,
    evidence,
    health,
    pld,
    risk_scoring,
    verify,
)
from app.config import get_settings


settings = get_settings()
log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hooks.

    W8.5: instantiate the production NotaryService and all its backends
    (NotaryDB, QTSPClient, SCITTClient, CertificateArtifactGenerator)
    once at startup and stash them on `app.state`. The notary router
    reads `app.state.notary_service` lazily per request (the Python
    equivalent of Rust's `OnceLock<NotaryService>` — one initialisation,
    many reads, no per-request reconfiguration). We also call
    `init_verification_routes(db)` so the public verify page can read
    from the same DB instance.
    """
    log.info(
        "control_plane.startup",
        service=settings.service_name,
        env=settings.environment,
        org_id=settings.org_id,
        tsa_provider=settings.tsa_provider,
        notary_db_path=settings.notary_db_path,
        notary_output_dir=settings.notary_output_dir,
    )

    # Lazy imports — keep lifespan cold-start path light, and let
    # tests override individual backends without triggering the full
    # wire-up.
    from app.notary_production import (
        CertificateArtifactGenerator,
        NotaryDB,
        NotaryServiceProduction,
        QTSPClient,
        SCITTClient,
    )
    from app.verification_page import init_verification_routes

    # Ensure the artifact output dir exists.
    Path(settings.notary_output_dir).mkdir(parents=True, exist_ok=True)

    db = NotaryDB(db_path=settings.notary_db_path)
    qtsp = QTSPClient(timeout=10.0)
    scitt = SCITTClient(timeout=10.0)
    artifact_gen = CertificateArtifactGenerator(
        output_dir=settings.notary_output_dir
    )
    app.state.notary_db = db
    # W8.3.1: HSM-backed signing. get_signer() returns
    # AWSKmsMLDSASigner (production) / ThalesLunaPqcSigner (on-prem HSM)
    # / EphemeralEd25519Signer (dev). main.py logs which one is in use.
    from app.hsm_adapter import get_signer
    signer = get_signer()
    app.state.signer = signer  # exposed for /v1/admin/signer endpoint
    app.state.notary_service = NotaryServiceProduction(
        db=db,
        qtsp=qtsp,
        scitt=scitt,
        artifact_gen=artifact_gen,
        signer=signer,
        issuer=f"did:web:{settings.org_id}",
        key_id="notary-key-1",
    )

    # Verification routes read from the same DB.
    init_verification_routes(db)

    log.info(
        "control_plane.notary_ready",
        db_path=settings.notary_db_path,
        output_dir=settings.notary_output_dir,
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
    # v3.0 W2: PLD 2024/2853 compliance shield (disclosure order response,
    # defect rebuttal pack, ISO 42001 SoA, NIST AI 600-1 profile, regulatory
    # deadline countdown). The killer feature is the rebuttal pack that
    # SHIFTS THE BURDEN back to the plaintiff under PLD Art. 10.
    app.include_router(pld.router, prefix="/v1", tags=["pld-shield"])

    # W8 production routers (W8.5 / W8.6 / W8.7):
    # - verification_page: L1 HTML verify page + L1 JSON verify API
    # - notary_production: POST /v1/notarize
    # - catalyst_production: POST /v1/catalyst/receipt + /v1/catalyst/manifest
    from app import (
        catalyst_production,
        notary_production,
        verification_page,
    )

    app.include_router(
        verification_page.router, tags=["verify-page"]
    )
    if getattr(notary_production, "router", None) is not None:
        app.include_router(
            notary_production.router, tags=["notary"]
        )
    if getattr(catalyst_production, "router", None) is not None:
        app.include_router(
            catalyst_production.router, tags=["catalyst"]
        )

    # W9.0: DORA (Regulation (EU) 2022/2554) evidence pack — replaces the
    # v1.0 "Partial" stub with a real 7-check evidence pack covering
    # DORA Art. 9-21 (ICT risk, incident reporting, DOR testing, third-
    # party risk, CTPPs, info register, regulator cooperation).
    app.include_router(dora.router, prefix="/v1", tags=["dora"])

    # W10.1: Cross-jurisdiction compliance profiles (EU AI Act, UK AI
    # Bill, US EO 14110, PRC GenAI Measures). Exposes the 4 profiles
    # the auditor flagged as "NotImplemented" in the v1.0 README.
    app.include_router(
        cross_jurisdiction.router, prefix="/v1", tags=["cross-jurisdiction"]
    )

    # W8.9.1: Adversarial scenarios harness (OASB v0.3.2 + AgentDojo
    # v0.1.35 + MITRE ATLAS 2026). Exposes the CordonEnforcer mapping
    # for the auditor-flagged "NotImplemented" adversarial testing.
    app.include_router(
        adversarial.router, prefix="/v1", tags=["adversarial"]
    )

    # W12: ISO 23894:2023 risk scoring dashboard (CISO Pro $199/mo
    # tier surface). 5 process stages + NIST AI RMF crosswalk.
    app.include_router(
        risk_scoring.router, prefix="/v1", tags=["risk-scoring"]
    )

    return app


app = create_app()