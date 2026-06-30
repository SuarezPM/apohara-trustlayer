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
# adds services/ to sys.path, but we need services/control_plane/ so
# that `from app.middleware import ...` resolves to
# services/control_plane/app/middleware/__init__.py. Without this,
# the import fails silently, _HAS_ASGI_MIDDLEWARE is False, and the
# middleware is never attached — causing 401 on every test.
import sys
from pathlib import Path

control_plane_dir = (
    Path(__file__).resolve().parent.parent / "services" / "control_plane"
)
sys.path.insert(0, str(control_plane_dir))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# v1.2 (post-EXA research + runtime debugging 2026-06-26): the
# middleware is PURE ASGI, not function-based. Pure ASGI writes
# to `scope["state"]` which IS the same dict the FastAPI Request
# exposes as `request.state`. This fixes the 4 failing test files
# (test_scitt, test_stix, test_content_negotiation) that were
# getting 401 because `@app.middleware("http")` (BaseHTTPMiddleware
# under the hood) creates a NEW Request object between middleware
# and dependencies, so request.state writes weren't visible to
# Depends(get_org_id). See app/middleware/__init__.py for the full
# rationale.
try:
    from app.middleware import OrgResolverASGIMiddleware

    _HAS_ASGI_MIDDLEWARE = True
except ImportError:
    _HAS_ASGI_MIDDLEWARE = False
    OrgResolverASGIMiddleware = None  # type: ignore


class OrgIdTestClient:
    """TestClient that auto-injects X-Org-Id into every request.

    Usage:
        client = OrgIdTestClient(app, org_id="acme")
        resp = client.get("/v1/evidence/test-bundle")  # X-Org-Id auto-set
    """

    def __init__(self, app: FastAPI, org_id: str = "test-org"):
        # Auto-attach the pure ASGI middleware if available.
        # Pure ASGI middleware (not @app.middleware("http")) writes
        # to scope["state"], which IS the same dict the FastAPI
        # Request exposes as `request.state`. This is the fix for
        # the 4 failing test files (test_scitt, test_stix,
        # test_content_negotiation, test_async_wiring) that were
        # getting 401 because the function-based middleware's
        # request.state write wasn't visible to Depends(get_org_id).
        if _HAS_ASGI_MIDDLEWARE:
            app.add_middleware(OrgResolverASGIMiddleware)
        self._client = TestClient(app)
        self._org_id = org_id

    def get(self, path, **kwargs):
        return self._client.get(
            path, headers=self._inject(kwargs.pop("headers", None)), **kwargs
        )

    def post(self, path, **kwargs):
        return self._client.post(
            path, headers=self._inject(kwargs.pop("headers", None)), **kwargs
        )

    def _inject(self, existing):
        h = dict(existing) if existing else {}
        h.setdefault("X-Org-Id", self._org_id)
        return h
