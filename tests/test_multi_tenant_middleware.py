"""
Test the v1.2 multi-tenant JWT + X-Org-Id middleware.

Per Plan v1.2 Block 4 v1.2-US-1 (closes auditor-3 honest-fail
`multi_tenant_isolation` + auditor-2 multi-tenant gating).

The middleware rejects requests with no org_id (loud 401 per
architect IC-3: no silent default) and accepts requests with either:
  - `Authorization: Bearer <jwt>` (HS256) with `org_id` claim
  - `X-Org-Id: <id>` header (test context)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path


# CRITICAL: we import `Request` at module level so FastAPI's type
# checker can recognise the special-casing of `Request` parameters
# in dependency functions. Without this, FastAPI treats `request`
# as a query parameter and returns 422.
from fastapi import Request as FastAPIRequest  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))


# Module-level dependency function. This MUST be module-level (not
# a closure inside _build_app) because FastAPI's Depends system
# needs to introspect the function's signature. Closures defined
# inside other functions don't get the right __module__/__qualname__
# and FastAPI sometimes treats their Request parameters as query
# parameters instead of auto-injecting them.
#
# CRITICAL: the `request` parameter MUST have a `Request` type
# annotation. Without it, FastAPI treats `request` as a query
# parameter and returns 422 ("Field required" for `request`).
# The type annotation is what triggers FastAPI's special-casing
# of `Request` (and a few other types) for dependency injection.
def _get_request(request: FastAPIRequest) -> dict:
    """Module-level dependency: capture the Request via FastAPI's
    special Request type annotation. Returns a dict containing
    `request` and `request.state.org_id` for the test route to use.
    """
    return {
        "request": request,
        "org_id": getattr(request.state, "org_id", None),
        "state_keys": list(vars(request.state).keys()) if hasattr(request.state, "__dict__") else [],
    }


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_jwt(org_id: str, secret: str = "test-secret-32-bytes-long-12345") -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"org_id": org_id, "sub": "test-user"}
    h_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url(sig)}"


def _build_app(jwt_secret: str | None = None):
    """Build a FastAPI app with the ASGI-based OrgResolverASGIMiddleware
    + a /debug/org route that exposes request.state.org_id.

    v1.2 (post-EXA research + runtime debugging 2026-06-26): the
    middleware is PURE ASGI (`OrgResolverASGIMiddleware`), NOT
    function-based (`@app.middleware("http")`) and NOT
    BaseHTTPMiddleware. Both previous approaches failed:
    - BaseHTTPMiddleware spawns a new task per request, breaking
      SQLAlchemy 2.0's contextvars-based session.execute().
    - @app.middleware("http") creates a NEW Request object between
      middleware and dependencies, so request.state writes are
      invisible to Depends(get_org_id).
    Pure ASGI writes directly to scope["state"], which IS the same
    dict the FastAPI Request exposes as request.state. This is the
    canonical Starlette pattern. See app/middleware/__init__.py
    for the full rationale.
    """
    from fastapi import FastAPI, Depends
    from app.middleware import OrgResolverASGIMiddleware, reset_jwt_secret_cache_for_tests

    # Reset the JWT secret cache so the env var is re-read for each
    # test (some tests change TL_JWT_SECRET between cases).
    reset_jwt_secret_cache_for_tests()
    if jwt_secret is not None:
        os.environ["TL_JWT_SECRET"] = jwt_secret
    else:
        os.environ.pop("TL_JWT_SECRET", None)

    app = FastAPI()
    # Pure ASGI middleware (not @app.middleware("http")).
    app.add_middleware(OrgResolverASGIMiddleware)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # /debug/org returns a JSON snapshot of what the middleware set.
    # We use Depends with a module-level function (_get_request) to
    # get the Request object. Module-level is critical: closures
    # defined inside _build_app don't get the right __module__/
    # __qualname__ and FastAPI treats the Request param as a query
    # parameter (returning 422).
    @app.get("/debug/org")
    def debug_org(ctx: dict = Depends(_get_request)):
        return {
            "state_org_id": ctx["org_id"],
            "state_keys": ctx["state_keys"],
        }

    return app


# =============================================================================
# Tests
# =============================================================================


def test_middleware_allows_public_path_without_auth() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(_build_app())
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_middleware_returns_401_when_no_auth_header() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(_build_app())
    resp = client.get("/debug/org")
    assert resp.status_code == 401, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["error"] == "org_id_required"
    assert "/debug/org" in body["path"]


def test_middleware_returns_401_when_jwt_present_but_no_secret_configured() -> None:
    """Per IC-3: missing TL_JWT_SECRET + bearer header = loud error
    (no silent default)."""
    from fastapi.testclient import TestClient

    client = TestClient(_build_app(jwt_secret=None))
    jwt = _make_jwt("acme")
    resp = client.get(
        "/debug/org",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert resp.status_code == 401


def test_middleware_accepts_x_org_id_header() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(_build_app())
    resp = client.get(
        "/debug/org",
        headers={"X-Org-Id": "acme"},
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["state_org_id"] == "acme"


def test_middleware_accepts_valid_jwt() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(_build_app(jwt_secret="test-secret-32-bytes-long-12345"))
    jwt = _make_jwt("acme", "test-secret-32-bytes-long-12345")
    resp = client.get(
        "/debug/org",
        headers={"Authorization": f"Bearer {jwt}"},
    )
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["state_org_id"] == "acme"


def test_middleware_rejects_invalid_jwt_signature() -> None:
    from fastapi.testclient import TestClient

    client = TestClient(_build_app(jwt_secret="real-secret-32-bytes-long-1234"))
    bad_jwt = _make_jwt("acme", "wrong-secret-32-bytes-long-12345")
    resp = client.get(
        "/debug/org",
        headers={"Authorization": f"Bearer {bad_jwt}"},
    )
    assert resp.status_code == 401


def test_middleware_tenant_isolation_acme_vs_globex() -> None:
    """Per Plan v1.2 Block 4 v1.2-US-1: 2 tenants cannot see each
    other's evidence. We simulate by checking that the org_id from
    the JWT is correctly propagated to the route's view of state.
    """
    from fastapi.testclient import TestClient

    secret = "shared-secret-32-bytes-long-1234"
    client = TestClient(_build_app(jwt_secret=secret))

    jwt_acme = _make_jwt("acme", secret)
    resp_acme = client.get(
        "/debug/org",
        headers={"Authorization": f"Bearer {jwt_acme}"},
    )
    assert resp_acme.json()["state_org_id"] == "acme"

    jwt_globex = _make_jwt("globex", secret)
    resp_globex = client.get(
        "/debug/org",
        headers={"Authorization": f"Bearer {jwt_globex}"},
    )
    assert resp_globex.json()["state_org_id"] == "globex"
    assert resp_acme.json()["state_org_id"] != resp_globex.json()["state_org_id"]
