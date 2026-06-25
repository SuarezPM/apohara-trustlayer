"""
Test the content negotiation contract on GET /v1/evidence/{bundle_id}.

Per Plan v1.2 Block 2 v1.0.5-US-2 (AC-5):
  - Accept: application/json (explicit) OR no Accept OR */* → evidence_bundle_v1
  - Accept: application/scitt+json → SCITTReceipt envelope
  - Accept: anything else → 406 Not Acceptable

Pattern: spin up the FastAPI app via TestClient (no network, no
subprocess), exercise all 4 scenarios, assert (a) status code,
(b) content-type, (c) response body schema.

The bundle is synthetic for v1.0.5 (real lookup lands in US-12);
the synthetic content is deterministic per bundle_id.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

# Make the control_plane package importable. The control_plane
# service is a sub-project, not part of the root python package.
REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))

# Now we can import the FastAPI app and the evidence router.
from app.api.evidence import SUPPORTED_TYPES  # noqa: E402

# Importing main lazily because it triggers structlog config
# which needs the env vars set. We construct the app directly.
def _make_client():
    """Build a TestClient for the FastAPI app.

    v1.1.0 (US-12): the evidence route now requires a BundleLookup.
    We inject an InMemoryBundleLookup that auto-creates a synthetic
    bundle on lookup miss, so the 200-path tests work for any
    bundle_id used in this file. The auto-create is a TEST-ONLY
    fallback (the production path returns 404 on miss).
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.evidence import (
        BundleLookup,
        InMemoryBundleLookup,
        get_bundle_lookup,
        router as evidence_router,
    )

    class AutoCreateLookup(BundleLookup):
        """Test-only lookup that creates a synthetic bundle on miss."""

        def lookup(self, bundle_id: str):
            synthetic = InMemoryBundleLookup._synthetic_bundle_for_tests(bundle_id)
            return synthetic

    app = FastAPI()
    app.include_router(evidence_router, prefix="/v1")
    app.dependency_overrides[get_bundle_lookup] = lambda: AutoCreateLookup()
    return TestClient(app)


def _make_empty_client():
    """TestClient for the 404 + 406 paths (no bundles injected)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.evidence import (
        InMemoryBundleLookup,
        get_bundle_lookup,
        router as evidence_router,
    )

    lookup = InMemoryBundleLookup()  # empty
    app = FastAPI()
    app.state.bundle_lookup = lookup
    app.dependency_overrides[get_bundle_lookup] = lambda: lookup
    app.include_router(evidence_router, prefix="/v1")
    return TestClient(app)


# Hex64 regex for the BLAKE3 fingerprint.
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def test_accept_json_returns_evidence_bundle_v1() -> None:
    """AC-2/AC-3: Accept: application/json → evidence_bundle_v1."""
    client = _make_client()
    r = client.get("/v1/evidence/test-bundle-1", headers={"Accept": "application/json"})
    assert r.status_code == 200, f"got {r.status_code}: {r.text}"
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    # evidence_bundle_v1 has these required keys
    for key in ("bundle_id", "created_at", "disclosures", "key_chain",
                "signature", "verification_instructions", "disclaimers"):
        assert key in body, f"missing key {key!r} in response"
    assert body["bundle_id"] == "test-bundle-1"
    assert isinstance(body["disclaimers"], list)


def test_accept_scitt_returns_scitt_receipt() -> None:
    """AC-2: Accept: application/scitt+json → SCITTReceipt envelope."""
    client = _make_client()
    r = client.get(
        "/v1/evidence/test-bundle-2",
        headers={"Accept": "application/scitt+json"},
    )
    assert r.status_code == 200, f"got {r.status_code}: {r.text}"
    assert r.headers["content-type"].startswith("application/scitt+json")
    body = r.json()
    # SCITTReceipt has these required keys (matches Rust SCITTReceipt struct)
    for key in ("payload", "cose_sign1", "issuer_kid",
                "issuer_pubkey_fingerprint", "inclusion_proof",
                "issued_at", "registry_id"):
        assert key in body, f"missing key {key!r} in SCITT response"
    assert HEX64.match(body["issuer_pubkey_fingerprint"]), \
        f"fingerprint must be 64 hex chars: {body['issuer_pubkey_fingerprint']!r}"
    # payload is base64
    import base64
    payload_bytes = base64.b64decode(body["payload"])
    parsed = json.loads(payload_bytes)
    assert parsed["bundle_id"] == "test-bundle-2"


def test_no_accept_header_defaults_to_json() -> None:
    """AC-3: no Accept header → default to application/json (v1.0 default)."""
    client = _make_client()
    r = client.get("/v1/evidence/test-bundle-3")  # no Accept header
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    body = r.json()
    assert "bundle_id" in body
    assert "verification_instructions" in body


def test_accept_wildcard_returns_json() -> None:
    """AC-3: Accept: */* → default to application/json (v1.0 default)."""
    client = _make_client()
    r = client.get("/v1/evidence/test-bundle-4", headers={"Accept": "*/*"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")


def test_accept_unsupported_returns_406() -> None:
    """AC-4: Accept: text/xml → 406 Not Acceptable with supported list."""
    client = _make_client()
    r = client.get("/v1/evidence/test-bundle-5", headers={"Accept": "text/xml"})
    assert r.status_code == 406, f"got {r.status_code}: {r.text}"
    body = r.json()
    assert body["error"] == "not_acceptable"
    assert set(body["supported"]) == set(SUPPORTED_TYPES)


def test_accept_yaml_returns_406() -> None:
    """AC-4: another unsupported type for good measure."""
    client = _make_client()
    r = client.get("/v1/evidence/test-bundle-6", headers={"Accept": "application/yaml"})
    assert r.status_code == 406
    body = r.json()
    assert body["error"] == "not_acceptable"
    assert "application/scitt+json" in body["supported"]


def test_accept_q_prefers_higher_quality_scitt() -> None:
    """AC-2: q=0.9 scitt+json wins over q=0.5 application/json."""
    client = _make_client()
    r = client.get(
        "/v1/evidence/test-bundle-7",
        headers={"Accept": "application/json;q=0.5, application/scitt+json;q=0.9"},
    )
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/scitt+json")


def test_synthetic_bundle_is_deterministic() -> None:
    """AC-2/AC-3: synthetic bundle must be deterministic per bundle_id.

    The bundle_id is the only seed; same bundle_id must produce the
    same disclosure_id, the same row_hash, and the same issued_at
    in the SCITT envelope.
    """
    client = _make_client()
    r1 = client.get("/v1/evidence/deterministic-test", headers={"Accept": "application/scitt+json"})
    r2 = client.get("/v1/evidence/deterministic-test", headers={"Accept": "application/scitt+json"})
    assert r1.json() == r2.json(), "synthetic SCITT receipt must be deterministic"


def test_supported_types_constant() -> None:
    """AC-4: SUPPORTED_TYPES must be a tuple of the two valid content types."""
    assert isinstance(SUPPORTED_TYPES, tuple)
    assert "application/json" in SUPPORTED_TYPES
    assert "application/scitt+json" in SUPPORTED_TYPES
