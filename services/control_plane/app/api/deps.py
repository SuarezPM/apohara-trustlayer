"""FastAPI dependency helpers (v1.2-US-1: multi-tenant org_id resolution).

The `get_org_id` dependency reads `org_id` from the request state
(set by `OrgResolverMiddleware` on every authenticated request).
Routes that need tenant isolation use `Depends(get_org_id)`.

Production paths:
  1. JWT (Authorization: Bearer): org_id is the verified claim.
  2. X-Org-Id header: org_id is the literal header value.
  3. Missing both on non-public paths: 401 (loud, per IC-3).

Tests use X-Org-Id directly. Tests that need a clean
request state can override the dependency with a no-op.
"""
from __future__ import annotations

from fastapi import HTTPException, Request, status


def get_org_id(request: Request) -> str:
    """FastAPI dependency: return the org_id set by OrgResolverMiddleware.

    Raises 401 if the middleware didn't set org_id (which would be a
    misconfiguration — public paths are excluded from the middleware).
    """
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        # This branch shouldn't trigger in normal flows (the
        # OrgResolverMiddleware returns 401 before we get here for
        # non-public paths). It IS a safety net for misconfiguration.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="org_id_required (middleware misconfiguration?)",
        )
    return str(org_id)
