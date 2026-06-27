"""Notary Layer (split from notary_production.py).

Single-responsibility modules:
- `app.notary.db`                   — NotaryDB (SQLite persistence)
- `app.notary.qtsp`                  — QTSPClient + QTSPError (RFC 3161)
- `app.notary.scitt`                 — SCITTClient + SCITTError (IETF RFC 9943)
- `app.notary.certificate_generator`  — CertificateArtifactGenerator (PDF/QR)
- `app.notary.models`                — ContentType, NotarizeRequest, NotarizeResponse
- `app.notary.service`               — NotaryServiceProduction + FastAPI router

Backwards-compatible re-exports: callers can do either

    from app.notary import NotaryDB, QTSPClient, NotarizeRequest
    from app.notary_production import NotaryDB, QTSPClient  # legacy path

The legacy `app.notary_production` module is a thin compat shim that
re-exports from `app.notary.*`.
"""
from app.notary.db import NotaryDB
from app.notary.qtsp import QTSPClient, QTSPError
from app.notary.scitt import SCITTClient, SCITTError
from app.notary.certificate_generator import CertificateArtifactGenerator
from app.notary.models import ContentType, NotarizeRequest, NotarizeResponse
from app.notary.service import NotaryServiceProduction

__all__ = [
    "NotaryDB",
    "QTSPClient",
    "QTSPError",
    "SCITTClient",
    "SCITTError",
    "CertificateArtifactGenerator",
    "NotaryServiceProduction",
    "ContentType",
    "NotarizeRequest",
    "NotarizeResponse",
]
