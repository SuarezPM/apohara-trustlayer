"""Backwards-compat shim — re-exports from `app.notary` split modules.

This module previously contained 5 classes + helpers + a FastAPI router
in a single 1044-line god file. W9.1 refactored it into 5 focused
submodules under `app.notary.*`:

    app.notary.db                   — NotaryDB
    app.notary.qtsp                  — QTSPClient + QTSPError
    app.notary.scitt                 — SCITTClient + SCITTError
    app.notary.certificate_generator  — CertificateArtifactGenerator
    app.notary.service               — NotaryServiceProduction + router

This shim preserves the legacy `from app.notary_production import X`
import path for 9.1-era callers (main.py, verification_page.py, tests).
New code should use `from app.notary import X` (the clean path).
"""
from app.notary import (
    CertificateArtifactGenerator,
    NotaryDB,
    NotaryServiceProduction,
    QTSPClient,
    QTSPError,
    SCITTClient,
    SCITTError,
)
# Re-export the FastAPI router instance so `main.py` can do
# `app.include_router(notary_production.router, tags=["notary"])`.
# Without this, the 404 fires (the /v1/notarize endpoint is never
# registered because the legacy module path no longer builds the
# router at import time).
from app.notary.service import router  # noqa: F401, E402

__all__ = [
    "NotaryDB",
    "QTSPClient",
    "QTSPError",
    "SCITTClient",
    "SCITTError",
    "CertificateArtifactGenerator",
    "NotaryServiceProduction",
    "router",
]
