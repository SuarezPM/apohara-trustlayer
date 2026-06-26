"""Helper utilities for tests that need to pass the X-Org-Id header
to the org_resolver_middleware.

Per Plan v1.2 Block 4 v1.2-US-1: the middleware requires either
(a) `Authorization: Bearer <jwt>` with `org_id` claim, or
(b) `X-Org-Id: <id>` header (test context).

This module provides a `TestClient` wrapper that:
1. Auto-injects X-Org-Id into every request.
2. Auto-attaches the org_resolver_middleware (for test apps that
   don't include it via main.create_app()).
"""
from __future__ import annotations

# Make the control_plane app importable for `from app.middleware import ...`
# (used by OrgIdTestClient's auto-attach). The `conftest.py` also
# adds services/ to sys.path, but we set it here for robustness.
import sys
from pathlib import Path

services_dir = Path(__file__).resolve().parent.parent / "services"
sys.path.insert(0, str(services_dir))

from fastapi import FastAPI
from fastapi.testclient import TestClient

# v1.2 (post-EXA research): the middleware is FUNCTION-based, not
# class-based. We import the function and apply it via the
# `app.middleware("http")` decorator pattern — this avoids the
# contextvars propagation issues that BaseHTTPMiddleware has with
# SQLAlchemy 2.0. See app/middleware/__init__.py for the full
# explanation.
try:
    from app.middleware import org_resolver_middleware
    _HAS_MIDDLEWARE = True
except ImportError:
    _HAS_MIDDLEWARE = False
    org_resolver_middleware = None  # type: ignore


class OrgIdTestClient:
    """TestClient that auto-injects X-Org-Id into every request.

    Usage:
        client = OrgIdTestClient(app, org_id="acme")
        resp = client.get("/v1/evidence/test-bundle")  # X-Org-Id auto-set
    """

    def __init__(self, app: FastAPI, org_id: str = "test-org"):
        # Auto-attach the function-based middleware if available.
        # The function-based middleware is applied via the decorator
        # pattern: `app.middleware("http")(org_resolver_middleware)`.
        # FastAPI/Starlette keeps the most recent add, so this is
        # idempotent for our test purposes.
        if _HAS_MIDDLEWARE:
            app.middleware("http")(org_resolver_middleware)
        self._client = TestClient(app)
        self._org_id = org_id

    def get(self, path, **kwargs):
        return self._client.get(path, headers=self._inject(kwargs.pop("headers", None)), **kwargs)

    def post(self, path, **kwargs):
        return self._client.post(path, headers=self._inject(kwargs.pop("headers", None)), **kwargs)

    def _inject(self, existing):
        h = dict(existing) if existing else {}
        h.setdefault("X-Org-Id", self._org_id)
        return h
