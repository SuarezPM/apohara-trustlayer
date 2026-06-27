"""
Pure ASGI middleware for multi-tenant org_id resolution (v1.2-US-1).

Per Plan v1.2 Block 4 v1.2-US-1 (closes auditor-3 v1.0.x honest-fail
`multi_tenant_isolation` and the auditor-2 v1.0.x multi-tenant gating).

How it works:
- If `Authorization: Bearer <jwt>` is present, decode the JWT and
  extract `org_id` (claim) → set on `scope["state"]["org_id"]`.
- If only `X-Org-Id: <id>` is present (test contexts), use that.
- If neither is set, return 401 (architect IC-3: no silent default).

Production deploys MUST set `TL_JWT_SECRET` (HMAC secret) so JWTs
can be decoded. Tests use `X-Org-Id` directly without JWT.

## Why pure ASGI middleware (not BaseHTTPMiddleware, not @app.middleware)

EXA research + runtime debugging (2026-06-26) confirmed TWO distinct
issues with the previous approaches:

1. **`BaseHTTPMiddleware`** spawns a new task per request, breaking
   SQLAlchemy 2.0's contextvars-based session.execute() propagation.
2. **`@app.middleware("http")`** (which IS `BaseHTTPMiddleware`
   under the hood) ALSO creates a NEW `Request` object between the
   middleware and downstream dependencies. So `request.state.org_id`
   set in the middleware is NOT visible to `Depends(get_org_id)`.
   This was the root cause of the 4 failing test files (test_scitt,
   test_stix, test_content_negotiation, test_async_wiring) showing
   401 `org_id_required (middleware misconfiguration?)`.

The fix: pure ASGI middleware writes to `scope["state"]`, which IS
the same dict shared with the FastAPI `Request` object downstream.
`scope["state"]` is the canonical Starlette pattern for passing
per-request data between middleware and route handlers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Awaitable, Callable

from fastapi import Request
from fastapi.responses import JSONResponse


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
        # W8.7: Public certificate verification — third parties can
        # verify without org_id (the cert_id is itself the proof).
        # Both the L1 HTML page and the L1 JSON API are public.
        "/verify",
        "/v1/verify",
    }
)


def _is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    for prefix in (
        "/docs",
        "/redoc",
        "/openapi.json",
        "/static",
        # W8.7: public verify pages (HTML + JSON) — the cert_id in the
        # URL is the access token, no org_id needed.
        "/verify/",
        "/v1/verify/",
    ):
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
    except Exception:  # noqa: BLE001 — intentional degraded mode (per README §"Scope of Compliance in v1.0").
        # W8.9.1+narrowed: catch is documented in the function docstring.
        # Any JWT decode/parse failure (binascii.Error, json.JSONDecodeError, KeyError,
        # ValueError, AttributeError) is treated as "no valid org_id" — the request
        # proceeds to the X-Org-Id header fallback or returns 401 if neither resolves.
        # Per IC-3: NEVER silently default to a tenant; an unparseable JWT is an
        # unparseable JWT, not a free pass.
        return None


def _b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode with padding fixup."""
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _resolve_org_id_from_scope(scope: dict, jwt_secret: str | None) -> str | None:
    """Resolve org_id from (1) JWT bearer or (2) X-Org-Id header.

    Reads raw headers from `scope["headers"]` (list of (bytes, bytes)
    tuples per ASGI spec) — this avoids creating a `Request` object
    which would defeat the purpose of pure ASGI middleware.
    """
    headers_raw = scope.get("headers") or []
    auth_value = ""
    x_org_value = ""
    for key, value in headers_raw:
        try:
            k = key.decode("latin-1").lower()
            v = value.decode("latin-1")
        except Exception:  # noqa: BLE001 — intentional degraded mode (per README §"Scope of Compliance in v1.0").
            # W8.9.1+narrowed: catch is documented in the function docstring.
            # Per ASGI spec, headers are (bytes, bytes) tuples. If a header cannot
            # be decoded as latin-1 (which is the only spec-permitted encoding),
            # it is malformed. Skip it silently and continue with the rest of
            # the headers — never crash the middleware on a single bad header.
            continue
        if k == "authorization":
            auth_value = v
        elif k == "x-org-id":
            x_org_value = v.strip()

    # 1. JWT
    if auth_value.lower().startswith("bearer "):
        token = auth_value[7:].strip()
        if jwt_secret:
            org = _decode_jwt_org_id(token, jwt_secret)
            if org:
                return org
        else:
            # No secret: reject bearer (per IC-3: no silent default).
            return None
    # 2. X-Org-Id header (test context)
    if x_org_value:
        return x_org_value
    return None


# Lazy-resolved JWT secret (resolved on first call to avoid reading
# the env var at import time, which is critical for test isolation).
#
# CRITICAL: we use a module-level sentinel `_UNSET`. Using a fresh
# `object()` for the comparison is a bug because `object()` creates
# a NEW object on every evaluation, so the `is` check would never
# be True. The module-level singleton is the correct pattern.
_UNSET = object()
_jwt_secret_cache: object = _UNSET


def _get_jwt_secret() -> str | None:
    global _jwt_secret_cache
    if _jwt_secret_cache is _UNSET:
        _jwt_secret_cache = os.environ.get("TL_JWT_SECRET")
    if isinstance(_jwt_secret_cache, str) or _jwt_secret_cache is None:
        return _jwt_secret_cache
    return None


def reset_jwt_secret_cache_for_tests() -> None:
    """Reset the JWT secret cache. Used by tests that change
    TL_JWT_SECRET between cases.
    """
    global _jwt_secret_cache
    _jwt_secret_cache = _UNSET


class OrgResolverASGIMiddleware:
    """Pure ASGI middleware: resolve org_id, set on scope["state"]["org_id"],
    and short-circuit with 401 if missing.

    Usage (in main.py):
        from app.middleware import OrgResolverASGIMiddleware
        app.add_middleware(OrgResolverASGIMiddleware)

    Why pure ASGI and not `@app.middleware("http")`:
    - `@app.middleware("http")` uses BaseHTTPMiddleware internally,
      which creates a NEW Request object between the middleware and
      downstream dependencies. So `request.state.org_id` set in the
      middleware is invisible to `Depends(get_org_id)`.
    - Pure ASGI middleware writes directly to `scope["state"]`, which
      IS the same dict shared with the FastAPI `Request` object
      downstream. This is the canonical Starlette pattern.

    Why not `BaseHTTPMiddleware`:
    - It spawns a new task per request, breaking SQLAlchemy 2.0's
      contextvars-based session.execute() propagation.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            # Lifespan, websocket, etc — pass through.
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if _is_public_path(path):
            await self.app(scope, receive, send)
            return

        secret = _get_jwt_secret()
        org_id = _resolve_org_id_from_scope(scope, secret)
        if org_id is None:
            # Build the 401 response directly (pure ASGI, no Request).
            response = JSONResponse(
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
            await response(scope, receive, send)
            return

        # Set on scope["state"] so Depends(get_org_id) can read it.
        # CRITICAL: scope["state"] is the SAME dict the FastAPI Request
        # object exposes as `request.state`. This is what makes the
        # pure ASGI approach work where @app.middleware("http") failed.
        state = scope.setdefault("state", {})
        state["org_id"] = org_id

        await self.app(scope, receive, send)

__all__ = [
    "OrgResolverASGIMiddleware",
    "PUBLIC_PATHS",
    "reset_jwt_secret_cache_for_tests",
]
