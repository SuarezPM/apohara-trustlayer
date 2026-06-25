"""
Test the real evidence bundle lookup path (v1.1.0-US-12).

Per Plan v1.2 Block 3 v1.1.0-US-12 (AC-5):
- A bundle present in the lookup → 200 + the real bundle.
- A bundle NOT present in the lookup → 404 + `{"error": "not_found", ...}`.
- The v1.0.5 synthetic bundle generator is REMOVED from the production
  path; the production default is `InMemoryBundleLookup` with no entries
  (which is the 404 case).

Pattern: build a minimal FastAPI app with the evidence router + a
custom InMemoryBundleLookup, exercise the route via TestClient.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))

from app.api.evidence import (  # noqa: E402
    InMemoryBundleLookup,
    get_bundle_lookup,
)


def _make_app_with_lookup(lookup: InMemoryBundleLookup):
    """Build a FastAPI app with the evidence router + a custom lookup."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.evidence import router as evidence_router

    app = FastAPI()
    app.state.bundle_lookup = lookup
    # Override the dependency so get_bundle_lookup() returns our injected one
    # even if app.state.bundle_lookup is bypassed.
    app.dependency_overrides[get_bundle_lookup] = lambda: lookup
    app.include_router(evidence_router, prefix="/v1")
    return TestClient(app)


def test_real_bundle_lookup_200() -> None:
    """AC-2: bundle_id in lookup → 200 + real bundle."""
    lookup = InMemoryBundleLookup()
    lookup.add("real-bundle-1", {
        "bundle_id": "real-bundle-1",
        "created_at": "2026-06-25T12:00:00Z",
        "disclosures": [
            {"disclosure_id": "disc_real-bundle-1", "compliance_rollup": "Compliant"}
        ],
        "key_chain": {"active_key_id": "abc123", "algorithm": "Ed25519"},
        "signature": {
            "cose_sign1_b64": "Z2VuZXJhdGVkLWJ5LXRlc3Q=",
            "row_hash": "deadbeef" * 8,
        },
        "tsa_token": None,
        "verification_instructions": "POST /v1/verify/provenance with real-bundle-1",
        "disclaimers": ["v1.1.0: real bundle retrieved from disclosure_records"],
    })

    client = _make_app_with_lookup(lookup)
    r = client.get("/v1/evidence/real-bundle-1")
    assert r.status_code == 200, f"got {r.status_code}: {r.text}"
    body = r.json()
    assert body["bundle_id"] == "real-bundle-1"
    assert body["signature"]["row_hash"] == "deadbeef" * 8
    # The real-bundle disclaimer replaces the v1.0.5 synthetic disclaimer.
    assert any("disclosure_records" in d for d in body["disclaimers"])


def test_real_bundle_lookup_404_when_not_found() -> None:
    """AC-3: bundle_id NOT in lookup → 404 + `{"error": "not_found", ...}`."""
    lookup = InMemoryBundleLookup()  # empty
    client = _make_app_with_lookup(lookup)
    r = client.get("/v1/evidence/nonexistent-bundle")
    assert r.status_code == 404, f"got {r.status_code}: {r.text}"
    body = r.json()
    assert body["error"] == "not_found"
    assert body["disclosure_id"] == "nonexistent-bundle"


def test_real_bundle_lookup_scitt_response() -> None:
    """AC-2: real bundle + Accept: application/scitt+json → 200 + SCITT envelope."""
    lookup = InMemoryBundleLookup()
    lookup.add("scitt-bundle", {
        "bundle_id": "scitt-bundle",
        "created_at": "2026-06-25T12:00:00Z",
        "disclosures": [],
        "key_chain": {"active_key_id": "key1"},
        "signature": {
            "cose_sign1_b64": "Z2VuZXJhdGVkLWJ5LXRlc3Q=",
            "row_hash": "cafebabe" * 8,
        },
        "tsa_token": None,
        "verification_instructions": "test",
        "disclaimers": [],
    })

    client = _make_app_with_lookup(lookup)
    r = client.get(
        "/v1/evidence/scitt-bundle",
        headers={"Accept": "application/scitt+json"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/scitt+json")
    body = r.json()
    # SCITT envelope from real bundle
    assert "payload" in body
    assert "cose_sign1" in body
    assert body["cose_sign1"] == "Z2VuZXJhdGVkLWJ5LXRlc3Q="  # from real bundle
    # The kid in the SCITT envelope references the real bundle_id
    assert "scitt-bundle" in body["issuer_kid"]


def test_default_lookup_returns_404_when_not_initialized() -> None:
    """AC-4: when no bundle_lookup is set on app.state and not overridden,
    the default InMemoryBundleLookup is empty → 404. This is the production
    fallback that ensures we never accidentally serve synthetic data."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.evidence import router as evidence_router

    app = FastAPI()  # NO app.state.bundle_lookup set, NO dependency override
    app.include_router(evidence_router, prefix="/v1")
    client = TestClient(app)

    r = client.get("/v1/evidence/anything")
    assert r.status_code == 404
    body = r.json()
    assert body["error"] == "not_found"


def test_synthetic_bundle_helper_still_works_for_tests() -> None:
    """AC-7: the synthetic bundle helper is preserved as test-only.

    After v1.1.0-US-12, the synthetic generator is no longer in the
    production path but is still available for tests that want a
    deterministic bundle to assert content negotiation. This test
    documents the helper's behavior so future regressions are caught.
    """
    synthetic = InMemoryBundleLookup._synthetic_bundle_for_tests("test-id")
    assert synthetic["bundle_id"] == "test-id"
    # The v1.0.5 synthetic-only disclaimer is preserved on the helper
    # but NOT on the production path.
    assert any("synthetic" in d.lower() for d in synthetic["disclaimers"])


def test_content_negotiation_406_still_works() -> None:
    """Regression: 406 behavior preserved across the v1.0.5 → v1.1.0 refactor."""
    lookup = InMemoryBundleLookup()
    client = _make_app_with_lookup(lookup)
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
    lookup = InMemoryBundleLookup()
    lookup.add("test", {"bundle_id": "test", "disclaimers": []})
    client = _make_app_with_lookup(lookup)
    r = client.get("/v1/evidence/test")  # no Accept
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
