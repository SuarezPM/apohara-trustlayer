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

## Why function-based middleware, not BaseHTTPMiddleware

EXA research (2025-11) confirmed that `BaseHTTPMiddleware` has
known contextvars propagation issues: it spawns a new task, which
breaks SQLAlchemy 2.0's session.execute() propagation. The fix per
Starlette's own docs is to use either a function-based middleware
(`@app.middleware("http")`) or a pure ASGI middleware. We use the
function-based approach because it's the minimal-change path that
preserves the same public surface.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os

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


def _resolve_org_id(request: Request, jwt_secret: str | None) -> str | None:
    """Resolve org_id from (1) JWT bearer or (2) X-Org-Id header.

    Production paths:
    1. JWT (Authorization: Bearer): org_id is the verified claim.
    2. X-Org-Id header: org_id is the literal header value.
    3. Missing both on non-public paths: 401 (loud, per IC-3).
    """
    # 1. JWT
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if jwt_secret:
            org = _decode_jwt_org_id(token, jwt_secret)
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


async def org_resolver_middleware(request: Request, call_next):
    """Function-based FastAPI middleware: resolve org_id, set on
    `request.state.org_id`, and short-circuit with 401 if missing.

    Usage (in main.py):
        from app.middleware import org_resolver_middleware
        app.middleware(\"http\")(org_resolver_middleware)

    This is a function-based middleware (vs BaseHTTPMiddleware) to
    avoid the documented contextvars propagation issues that come
    with BaseHTTPMiddleware's new-task model. SQLAlchemy 2.0's
    session.execute() depends on contextvars, so a BaseHTTPMiddleware
    in the stack can break the session.execute() path.

    See tests/test_multi_tenant_middleware.py for the contract
    and tests/test_real_evidence_lookup.py for the integration.
    """
    path = request.url.path
    if _is_public_path(path):
        return await call_next(request)

    secret = _get_jwt_secret()
    org_id = _resolve_org_id(request, secret)
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

    # Set on request.state for the route handler (and downstream deps).
    request.state.org_id = org_id
    return await call_next(request)


__all__ = [
    "org_resolver_middleware",
    "PUBLIC_PATHS",
    "reset_jwt_secret_cache_for_tests",
]
