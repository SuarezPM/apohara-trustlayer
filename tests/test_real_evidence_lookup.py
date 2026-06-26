"""
Test the real evidence bundle lookup path (v1.1.0-US-12 + v1.1.0.x-US-3).

Per Plan v1.2 Block 3 v1.1.0-US-12 (AC-5):
- A bundle present in the lookup → 200 + real bundle.
- A bundle NOT present in the lookup → 404 + `{"error": "not_found", ...}`.

Per Plan v1.x v1.1.0.x-US-3 (AC-7):
- New tests for `DbBundleLookup` using SQLite async in-memory + httpx.AsyncClient.
- Tests the 200, 404, and concurrency paths.

Pattern: build a minimal FastAPI app with the evidence router + a
custom session/lookup override, exercise the route via TestClient
(sync tests) and httpx.AsyncClient (async tests).
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))

# Import after sys.path adjustment so the control_plane package is importable.
from app.api.evidence import (  # noqa: E402
    InMemoryBundleLookup,
    _select_content_type,
)


def _build_app_with_inmemory(lookup: InMemoryBundleLookup):
    """Build a FastAPI app with the evidence router + a custom async
    session that serves the in-memory bundle lookup. Used for fast
    unit tests of the route without a real DB.

    v1.1.0.x: the route uses `get_async_session_dep` (async). For
    sync tests, we override the dependency with a function that
    returns a `_SyncSessionAdapter` wrapping the in-memory lookup.
    The adapter's `execute(stmt)` simulates a SELECT on
    `disclosure_records` by delegating to `lookup.lookup(bundle_id)`.
    """
    from fastapi import FastAPI
    from tests.test_org_id_helpers import OrgIdTestClient
    from app.api.evidence import (
        get_async_session_dep,
        router as evidence_router,
    )

    class _SyncSessionAdapter:
        """Sync-compatible session that returns InMemoryBundleLookup results.

        Implements only the surface the route uses: `execute(stmt)`
        returning a result whose `scalar_one_or_none()` returns
        either a `DisclosureRecord`-shaped object or None.
        """
        def __init__(self, lookup: InMemoryBundleLookup) -> None:
            self._lookup = lookup

        async def execute(self, stmt):
            # v1.2-US-1: extract both bundle_id and org_id from the
            # WHERE clause. The query is `id == X AND org_id == Y`
            # (a BooleanClause). We walk the AND-clauses to extract
            # both values from their respective inner expressions.
            whereclause = getattr(stmt, "whereclause", None)
            bundle_id = None
            org_id_filter = None
            if whereclause is not None:
                if hasattr(whereclause, "clauses"):
                    for child in whereclause.clauses:
                        try:
                            k = getattr(child.left, "key", None)
                            v = getattr(child.right, "value", None)
                            if k == "id":
                                bundle_id = v
                            elif k == "org_id":
                                org_id_filter = v
                        except AttributeError:
                            pass
                elif whereclause is not None:
                    try:
                        k = getattr(whereclause.left, "key", None)
                        v = getattr(whereclause.right, "value", None)
                        if k == "id":
                            bundle_id = v
                        elif k == "org_id":
                            org_id_filter = v
                    except AttributeError:
                        pass
            if bundle_id is None:
                return _NullResult()
            bundle = self._lookup.lookup(bundle_id)
            if bundle is None:
                return _NullResult()
            if org_id_filter is not None and bundle.get("org_id") != org_id_filter:
                return _NullResult()
            return _RecordResult(bundle)

    def get_session():
        return _SyncSessionAdapter(lookup)

    app = FastAPI()
    app.dependency_overrides[get_async_session_dep] = get_session
    app.include_router(evidence_router, prefix="/v1")
    return OrgIdTestClient(app, org_id="acme")


def _make_empty_client():
    """TestClient for the 404 + 406 paths (no bundles injected)."""
    return _build_app_with_inmemory(InMemoryBundleLookup())


def test_real_bundle_lookup_200() -> None:
    """AC-2: bundle_id in lookup → 200 + real bundle."""
    lookup = InMemoryBundleLookup()
    # The bundle shape is what `_record_to_bundle_dict` returns: the
    # route reads from a `DisclosureRecord` (via `_BundleRecordAdapter`)
    # and the helper produces a dict with top-level fields. Our test
    # bundle mirrors that output shape.
    lookup.add("real-bundle-1", {
        "id": "real-bundle-1",
        "org_id": "acme",
        "bundle_id": "real-bundle-1",
        "created_at": "2026-06-25T12:00:00Z",
        "row_hash": "deadbeef" * 8,
        "prev_hash": "cafebabe" * 8,
        "cose_sign1_b64": "Z2VuZXJhdGVkLWJ5LXRlc3Q=",
        "tsa_token_b64": None,
        "tsa_url": None,
        "ai_system_id": "system-1",
        "deployer_name": "deployer-1",
        "deployer_country": "AR",
        "deployer_sector": "tech",
        "artifact_kind": "text",
        "artifact_content_hash": "abcdef" * 8 + "ab"[:0],
        "disclosure_text": "disclosure text",
        "compliance_rollup": "Compliant",
        "compliance_layers": {"disclosure": "Compliant"},
        "disclaimers": ["v1.1.0: real bundle retrieved from disclosure_records"],
    })

    client = _build_app_with_inmemory(lookup)
    r = client.get("/v1/evidence/real-bundle-1")
    assert r.status_code == 200, f"got {r.status_code}: {r.text}"
    body = r.json()
    assert body["bundle_id"] == "real-bundle-1"
    assert body["signature"]["row_hash"] == "deadbeef" * 8
    # The real-bundle disclaimer replaces the v1.0.5 synthetic disclaimer.
    assert any("disclosure_records" in d for d in body["disclaimers"])


def test_real_bundle_lookup_404_when_not_found() -> None:
    """AC-3: bundle_id NOT in lookup → 404 + `{"error": "not_found", ...}`."""
    client = _make_empty_client()
    r = client.get("/v1/evidence/nonexistent-bundle")
    assert r.status_code == 404, f"got {r.status_code}: {r.text}"
    body = r.json()
    assert body["error"] == "not_found"
    assert body["disclosure_id"] == "nonexistent-bundle"


def test_default_lookup_returns_404_when_not_initialized() -> None:
    """AC-4 (v1.1.0 regression check): when the session dep returns
    no rows, the route returns 404.

    v1.1.0.x: the route now uses `Depends(get_async_session_dep)`
    instead of `get_bundle_lookup`. For this regression check, we
    provide a session that returns a null result (no records found).
    """
    from fastapi import FastAPI
    from tests.test_org_id_helpers import OrgIdTestClient
    from app.api.evidence import (
        get_async_session_dep,
        router as evidence_router,
    )

    def get_session():
        return _NullSession()

    app = FastAPI()
    app.dependency_overrides[get_async_session_dep] = get_session
    app.include_router(evidence_router, prefix="/v1")
    client = OrgIdTestClient(app, org_id="acme")

    r = client.get("/v1/evidence/anything")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "not_found"


def test_synthetic_bundle_helper_still_works_for_tests() -> None:
    """AC-7: the synthetic bundle helper is preserved as test-only."""
    synthetic = InMemoryBundleLookup._synthetic_bundle_for_tests("test-id")
    assert synthetic["bundle_id"] == "test-id"
    assert any("synthetic" in d.lower() for d in synthetic["disclaimers"])


def test_content_negotiation_406_still_works() -> None:
    """Regression: 406 behavior preserved across the v1.0.5 → v1.1.0 refactor."""
    client = _make_empty_client()
    r = client.get(
        "/v1/evidence/anything",
        headers={"Accept": "text/xml"},
    )
    assert r.status_code == 406
    body = r.json()
    assert body["error"] == "not_acceptable"
    assert "application/scitt+json" in body["supported"]


def test_no_accept_header_still_defaults_to_json() -> None:
    """Regression: no Accept header → application/json default."""
    client = _build_app_with_inmemory(InMemoryBundleLookup())
    # Pre-load a bundle so we get 200 instead of 404.
    InMemoryBundleLookup().add("test", {"bundle_id": "test", "disclaimers": [], "org_id": "acme"})
    client = _build_app_with_inmemory(_LookupWith({"test": {"bundle_id": "test", "disclaimers": [], "org_id": "acme"}}))
    r = client.get("/v1/evidence/test")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


# Helper for the no-Accept regression test.
class _LookupWith(InMemoryBundleLookup):
    def __init__(self, bundles: dict) -> None:
        super().__init__(bundles)


# v1.1.0.x-US-3 AC-6: concurrency test (full async path).
# This is in test_async_wiring_concurrency.py; we keep the fast unit
# tests here for backward-compat with the v1.1.0 PR. The async test
# is a separate file because it requires a real async DB setup.


def _extract_bundle_id_from_stmt(stmt):
    """Best-effort extraction of the bundle_id from a SQLAlchemy stmt.

    The route does `select(DisclosureRecord).where(DisclosureRecord.id == bundle_id)`.
    The bundle_id is the right-hand side of the WHERE (a BindParameter
    with `.value` set to the bundle_id string).
    """
    try:
        right = stmt.whereclause.right
        if hasattr(right, "value"):
            return right.value
        return str(right)
    except Exception:
        return None


class _RecordResult:
    """Duck-typed SQLAlchemy result that returns a record from `scalar_one_or_none`."""

    def __init__(self, bundle: dict) -> None:
        self._record = _BundleRecordAdapter(bundle)

    def scalar_one_or_none(self):
        return self._record


class _NullResult:
    """Duck-typed SQLAlchemy result that returns None from `scalar_one_or_none`."""

    def scalar_one_or_none(self):
        return None


class _BundleRecordAdapter:
    """Adapter that exposes the fields the route reads from
    `DisclosureRecord` via attribute access.

    Maps a bundle dict (with keys like 'bundle_id') to the attribute
    names the route expects (e.g. 'id' for the primary key).
    """

    def __init__(self, bundle: dict) -> None:
        self.bundle = bundle
        # Map bundle_id -> id (primary key field on DisclosureRecord).
        if "id" not in self.bundle and "bundle_id" in self.bundle:
            self.bundle["id"] = self.bundle["bundle_id"]

    def __getattr__(self, name):
        return self.bundle.get(name)


class _NullSession:
    """Async-compatible session that always returns no rows.

    For the "default lookup returns 404" regression test: when the
    route's session.execute() returns a null result (no records),
    the route must return 404.
    """

    async def execute(self, _stmt):
        return _NullResult()
