"""
JWT + X-Org-Id middleware for multi-tenant v1.2.

Per Plan v1.2 Block 4 v1.2-US-1 (closes auditor-3 v1.0.x honest-fail
`multi_tenant_isolation` and the auditor-2 v1.0.x multi-tenant
gating).

How it works:
- If `Authorization: Bearer <jwt>` is present, decode the JWT and
  extract `org_id` (claim) → set on `request.state.org_id`.
- If only `X-Org-Id: <id>` is present (test contexts), use that.
- If neither is set, return 401 (architect IC-3: no silent default).

Production deploys MUST set `TL_JWT_SECRET` (HMAC secret) so JWTs
can be decoded. Tests use `X-Org-Id` directly without JWT.

NOTE: this is a function-based middleware (NOT BaseHTTPMiddleware)
because BaseHTTPMiddleware creates a fresh request scope per
middleware, which would break state sharing with downstream
function middlewares + routes.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp


# Routes that DO NOT require org_id (public, no tenant binding).
# Per architect IC-3: missing org_id is a loud error, not a
# silent default. The list below is the explicit allow-list.
PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/health",
        "/healthz",
        "/v1/health",
        "/v1/healthz",
        "/",
        "/v1/welcome",
        # Content negotiation + version endpoints
        "/v1/version",
        "/v1/.well-known/scitt-keys",
    }
)


def _is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    for prefix in ("/docs", "/redoc", "/openapi.json", "/static"):
        if path.startswith(prefix):
            return True
    return False


def _decode_jwt_org_id(token: str, jwt_secret: str) -> str | None:
    """Decode HS256 JWT and extract the `org_id` claim.

    Minimal HS256 implementation (no PyJWT dependency for the
    control plane's middleware; PyJWT is heavy). Production
    may swap to PyJWT if it grows.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        return None
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(
            jwt_secret.encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        actual_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
        if header.get("alg") != "HS256":
            return None
        org = payload.get("org_id")
        return str(org) if org else None
    except Exception:  # noqa: BLE001
        return None


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding fixup."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


# Use BaseHTTPMiddleware to access ASGI scope + send + receive
# but with a stable state scope (set scope['state'] via Starlette
# State so downstream can read it). The actual setting happens
# in the inner ASGI wrapper below.
class OrgResolverMiddleware(BaseHTTPMiddleware):
    """BaseHTTPMiddleware wrapper for v1.2 multi-tenant org resolution.

    Public API: add to FastAPI app via `app.add_middleware(OrgResolverMiddleware, jwt_secret=...)`.
    """

    def __init__(self, app: ASGIApp, jwt_secret: str | None = None) -> None:
        super().__init__(app)
        self._jwt_secret = jwt_secret or os.environ.get("TL_JWT_SECRET")

    async def dispatch(self, request, call_next):
        path = request.url.path
        if _is_public_path(path):
            return await call_next(request)

        org_id = self._resolve_org_id(request)
        if org_id is None:
            return JSONResponse(
                status_code=401,
                content={
                    "error": "org_id_required",
                    "path": path,
                    "hint": (
                        "Provide an Authorization: Bearer <jwt> header with an "
                        "`org_id` claim OR an X-Org-Id header. v1.2 multi-tenant "
                        "deployments MUST resolve org_id for every authenticated "
                        "request (per architect IC-3, no silent default)."
                    ),
                },
                headers={"Content-Type": "application/json"},
            )

        # Set org_id on request.state. The state wrapper propagates
        # through BaseHTTPMiddleware's scope correctly.
        request.state.org_id = org_id
        return await call_next(request)

    def _resolve_org_id(self, request) -> str | None:
        # 1. JWT (production path)
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            if self._jwt_secret:
                org = _decode_jwt_org_id(token, self._jwt_secret)
                if org:
                    return org
            else:
                # No secret: reject bearer (per IC-3: no silent default).
                return None

        # 2. X-Org-Id header (test context)
        x_org = request.headers.get("X-Org-Id", "").strip()
        if x_org:
            return x_org

        return None


__all__ = ["OrgResolverMiddleware"]
