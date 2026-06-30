"""
Test the v1.1.0.x+1+7 SCITT counter-signed receipt endpoint.

Per Plan v1.2 Block 4 v1.1.0.x+1+7:
- GET /v1/evidence/{bundle_id}/scitt-receipt exists
- Returns a counter-signed SCITT receipt JSON envelope
- 404 for unknown bundle
- Honest disclosure about mock CoSC ledger

Uses the _SyncSessionAdapter pattern from test_real_evidence_lookup.py
to avoid a real DB.
"""
from __future__ import annotations
from tests.test_org_id_helpers import OrgIdTestClient

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
CONTROL_PLANE = REPO_ROOT / "services" / "control_plane"
sys.path.insert(0, str(CONTROL_PLANE))

# Imports below require sys.path adjustment so the control_plane app is importable.


def _build_client(bundles=None):
    """Build a TestClient with the scitt-receipt endpoint wired up.

    Args:
        bundles: dict of bundle_id -> bundle dict; if None, empty lookup (404 expected).
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient  # noqa: F401
    from app.api.evidence import get_async_session_dep, router as evidence_router

    bundles = bundles or {}

    class _NullResult:
        def scalar_one_or_none(self):
            return None

    class _RecordResult:
        def __init__(self, bundle: dict) -> None:
            self._bundle = bundle

        def scalar_one_or_none(self):
            return _DisclosureRecordLike.from_dict(self._bundle)

    class _DisclosureRecordLike:
        """Duck-typed object: id, row_hash, cose_sign1_b64, etc."""

        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

        @classmethod
        def from_dict(cls, d: dict):
            return cls(
                id=d["bundle_id"],
                row_hash=d.get("row_hash", "deadbeef" * 8),
                cose_sign1_b64=d.get("cose_sign1_b64", ""),
                issuer_pubkey_fingerprint=d.get(
                    "issuer_pubkey_fingerprint", "11" * 32
                ),
                created_at=None,
                compliance_rollup=d.get("compliance_rollup", "Partial"),
            )

    class _SyncSessionAdapter:
        async def execute(self, stmt):
            # v1.2-US-1: extract both bundle_id AND org_id from the
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
            bundle = bundles.get(bundle_id)
            if bundle is None:
                return _NullResult()
            # Multi-tenant filter: bundle's org_id must match the filter.
            if org_id_filter is not None and bundle.get("org_id") != org_id_filter:
                return _NullResult()
            return _RecordResult(bundle)

    app = FastAPI()
    app.dependency_overrides[get_async_session_dep] = lambda: _SyncSessionAdapter()
    app.include_router(evidence_router, prefix="/v1")
    return OrgIdTestClient(app, org_id="acme")


def _make_bundle(bundle_id: str) -> dict:
    return {
        "bundle_id": bundle_id,
        "org_id": "acme",  # Must match the test client's org_id
        "row_hash": "abc123def456",
        "cose_sign1_b64": "AABBCCDD",  # synthetic placeholder
        "issuer_pubkey_fingerprint": "11" * 32,
        "compliance_rollup": "Partial",
    }


# =============================================================================
# Tests
# =============================================================================


def test_scitt_receipt_endpoint_returns_404_for_unknown_bundle() -> None:
    client = _build_client(bundles={})
    resp = client.get("/v1/evidence/unknown-bundle/scitt-receipt")
    assert resp.status_code == 404, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["error"] == "bundle_not_found"
    assert body["bundle_id"] == "unknown-bundle"


def test_scitt_receipt_endpoint_returns_envelope_for_known_bundle() -> None:
    bundle_id = "disc-test-scitt-001"
    client = _build_client(bundles={bundle_id: _make_bundle(bundle_id)})
    resp = client.get(f"/v1/evidence/{bundle_id}/scitt-receipt")
    assert resp.status_code == 200, f"got {resp.status_code}: {resp.text}"
    body = resp.json()
    # Envelope shape
    assert body["bundle_id"] == bundle_id
    assert "scitt_receipt" in body
    assert "countersignature" in body
    assert "disclaimers" in body

    # Honest disclosure about mock CoSC ledger (closes auditor-4 BRECHA 1).
    disclaimer_text = " ".join(body["disclaimers"])
    assert "MOCK" in disclaimer_text, (
        f"Honest disclosure: scitt-receipt disclaimers MUST call out "
        f"the mock CoSC ledger; got: {disclaimer_text!r}"
    )
    assert "draft-ietf-scitt-scrapi-09" in disclaimer_text, (
        f"Honest disclosure: scitt-receipt disclaimers MUST cite the "
        f"IETF draft that production must comply with; got: {disclaimer_text!r}"
    )


def test_scitt_receipt_endpoint_envelope_has_required_fields() -> None:
    """Per Plan v1.2 Block 4 v1.1.0.x+1+7: the envelope MUST have all
    required fields so an offline auditor can verify the countersignature.
    """
    bundle_id = "disc-test-scitt-002"
    client = _build_client(bundles={bundle_id: _make_bundle(bundle_id)})
    resp = client.get(f"/v1/evidence/{bundle_id}/scitt-receipt")
    assert resp.status_code == 200
    body = resp.json()

    scitt_receipt = body["scitt_receipt"]
    for field in ("payload_b64", "cose_sign1_b64", "issuer_pubkey_fingerprint"):
        assert field in scitt_receipt, f"scitt_receipt missing field: {field}"

    countersig = body["countersignature"]
    for field in ("cosc_pubkey_fingerprint", "cosc_signature_b64", "registry"):
        assert field in countersig, f"countersignature missing field: {field}"
