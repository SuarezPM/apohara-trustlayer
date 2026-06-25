"""GET /v1/evidence/{bundle_id} — public evidence bundle download.

Per Plan v1.2 Block 3 v1.1.0-US-12 (real evidence bundle lookup):

  - GET /v1/evidence/{bundle_id} looks up the disclosure in the
    disclosure_records table via the BundleLookup interface.
  - The BundleLookup interface is injected via FastAPI Depends so
    production uses the real DB-backed lookup and tests use an
    in-memory dict (no live Postgres required).
  - Accept header content negotiation (from v1.0.5) is preserved:
    - Accept: application/scitt+json → SCITTReceipt envelope
    - Accept: application/json / */* / no header → evidence_bundle_v1
    - Accept: anything else → 406

v1.0.5 used a synthetic bundle generator with disclaimers. v1.1.0
replaces that with real lookup. The synthetic path is preserved
ONLY in the test injection (`InMemoryBundleLookup`).
"""

from __future__ import annotations

import base64
import hashlib
import json
from abc import ABC, abstractmethod
from typing import Literal

from fastapi import APIRouter, Depends, Header, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

router = APIRouter()

# Supported content types for negotiation. Exposed as a module
# constant so the test in tests/test_content_negotiation.py can
# verify the 406 response.
SUPPORTED_TYPES = ("application/json", "application/scitt+json")


class SCITTReceipt(BaseModel):
    """SCITT-native receipt envelope (IETF draft-ietf-scitt-scrapi-09).

    Mirrors the Rust `tl_scitt::SCITTReceipt` struct field-by-field.
    The Rust side (crates/tl-scitt) and this schema MUST stay in
    lock-step — both are source of truth for the v1.0.5 wire format.
    """

    payload: str = Field(description="Base64-encoded payload")
    cose_sign1: str = Field(description="Base64-encoded CBOR COSE_Sign1")
    issuer_kid: str
    issuer_pubkey_fingerprint: str = Field(
        min_length=64,
        max_length=64,
        description="Hex-encoded 32-byte BLAKE3 fingerprint",
    )
    inclusion_proof: Literal["None"] | None = None
    issued_at: int
    registry_id: str


# =============================================================================
# BundleLookup interface (DI seam)
# =============================================================================


class BundleLookup(ABC):
    """Interface for looking up an evidence bundle by id.

    Production: DbBundleLookup (queries disclosure_records table).
    Tests: InMemoryBundleLookup (uses a dict, no DB required).
    """

    @abstractmethod
    def lookup(self, bundle_id: str) -> dict | None:
        """Return the bundle dict if found, None otherwise.

        The returned dict has the evidence_bundle_v1 schema (matches
        DisclosureRecord columns + key_chain + signature + disclaimers).
        """
        raise NotImplementedError


class InMemoryBundleLookup(BundleLookup):
    """Test-only bundle lookup backed by an in-memory dict.

    Per Plan v1.2 Block 3 v1.1.0-US-12 AC-4: the test path uses this
    so tests don't need a live Postgres. The v1.0.5 synthetic bundle
    generator was moved INTO this class as `_synthetic_bundle_for_tests`
    — that name is the documented "this is synthetic, for tests only"
    marker.
    """

    def __init__(self, bundles: dict[str, dict] | None = None) -> None:
        self._bundles: dict[str, dict] = bundles if bundles is not None else {}

    def add(self, bundle_id: str, bundle: dict) -> None:
        """Add or overwrite a bundle (test helper)."""
        self._bundles[bundle_id] = bundle

    def lookup(self, bundle_id: str) -> dict | None:
        return self._bundles.get(bundle_id)

    @staticmethod
    def _synthetic_bundle_for_tests(bundle_id: str) -> dict:
        """Build a synthetic bundle for tests only.

        Previously this was the production default in v1.0.5; v1.1.0
        moves it here so production goes through real lookup. Tests
        still get a deterministic synthetic bundle (call
        InMemoryBundleLookup().add(bundle_id, _synthetic_bundle_for_tests(bundle_id))).
        """
        seed = hashlib.sha256(bundle_id.encode("utf-8")).digest()
        return {
            "bundle_id": bundle_id,
            "created_at": "2026-06-25T00:00:00Z",
            "disclosures": [
                {
                    "disclosure_id": f"disc_{bundle_id}",
                    "compliance_rollup": "Partial",
                    "v1_disclaimers": [
                        "watermark layer: NotApplicable in v1.0",
                        "FreeTSA timestamp: dev-only, not forensically valid",
                    ],
                }
            ],
            "key_chain": {
                "active_key_id": seed[:8].hex(),
                "algorithm": "Ed25519",
                "rotated_at": "2026-06-24T00:00:00Z",
            },
            "signature": {
                "cose_sign1_b64": base64.b64encode(
                    b"\x84\x00" + b"\x00" * 64
                ).decode("ascii"),
                "row_hash": seed.hex(),
            },
            "tsa_token": None,
            "verification_instructions": (
                "POST /v1/verify/provenance with the bundle_id. "
                "This is a synthetic test bundle (v1.1.0-US-12)."
            ),
            "disclaimers": [
                "v1.1.0-US-12: synthetic bundle (test path only). "
                "Production uses DbBundleLookup against disclosure_records.",
            ],
        }


def _build_scitt_envelope_from_bundle(bundle: dict) -> dict:
    """Build a SCITTReceipt envelope from an evidence bundle.

    Replaces v1.0.5's `_synthetic_scitt_receipt`. The bundle's
    `cose_sign1_b64` from disclosure_records is the source of
    truth for the receipt; for synthetic bundles the placeholder
    is documented.
    """
    payload_bytes = json.dumps(bundle, sort_keys=True).encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    # The COSE_Sign1 bytes come from the bundle's signature column
    # (or a placeholder for synthetic bundles).
    signature = bundle.get("signature", {})
    cose_sign1_b64 = signature.get(
        "cose_sign1_b64",
        base64.b64encode(b"\x84\x00" + b"\x00" * 64).decode("ascii"),
    )

    # Empty key fingerprint (32 zero bytes) for the synthetic case.
    # Real receipts will BLAKE3 the issuer public key here.
    fingerprint_hex = "00" * 32

    # Deterministic issued_at from the bundle's row_hash (NOT
    # wall-clock). The SCITT property: same bundle → same receipt.
    issued_at = int.from_bytes(
        hashlib.sha256(
            (signature.get("row_hash", "default") + "issued").encode()
        ).digest()[:4],
        "big",
    )

    return {
        "payload": payload_b64,
        "cose_sign1": cose_sign1_b64,
        "issuer_kid": f"did:web:apohara.dev:trustlayer:v1.1.0:bundle:{bundle['bundle_id']}",
        "issuer_pubkey_fingerprint": fingerprint_hex,
        "inclusion_proof": "None",
        "issued_at": issued_at,
        "registry_id": "trustlayer-v1.1.0",
    }


def _parse_accept(accept_header: str | None) -> list[str]:
    """Parse an Accept header into a list of media types, in priority order."""
    if not accept_header or accept_header.strip() == "":
        return ["*/*"]
    items: list[tuple[float, str]] = []
    for raw in accept_header.split(","):
        raw = raw.strip()
        if not raw:
            continue
        parts = raw.split(";")
        media = parts[0].strip()
        q = 1.0
        for param in parts[1:]:
            param = param.strip()
            if param.startswith("q="):
                try:
                    q = float(param[2:])
                except ValueError:
                    q = 1.0
        items.append((q, media))
    items.sort(key=lambda t: -t[0])
    return [m for _, m in items]


def _select_content_type(accept_header: str | None) -> str | None:
    """Return the highest-priority supported content type, or None."""
    if accept_header is None:
        return "application/json"  # v1.0 default for absent header
    candidates = _parse_accept(accept_header)
    for c in candidates:
        cl = c.lower()
        if cl == "application/scitt+json":
            return "application/scitt+json"
        if cl == "application/json":
            return "application/json"
        if cl in ("*/*", "application/*"):
            return "application/json"
        if cl in SUPPORTED_TYPES:
            return cl
    return None


# =============================================================================
# FastAPI dependency injection
# =============================================================================


def get_bundle_lookup(request: Request) -> BundleLookup:
    """FastAPI dependency: returns the production BundleLookup.

    The control plane stores the lookup on `app.state.bundle_lookup`
    at startup. If unset (e.g. in unit tests), we fall back to an
    InMemoryBundleLookup with no entries — every lookup returns 404.
    The tests that need synthetic bundles construct their own
    FastAPI app with a different dependency override.
    """
    lookup = getattr(request.app.state, "bundle_lookup", None)
    if lookup is None:
        return InMemoryBundleLookup()
    return lookup


# =============================================================================
# Route
# =============================================================================


@router.get("/evidence/{bundle_id}")
async def get_evidence_bundle(
    bundle_id: str,
    accept: str | None = Header(default=None),
    lookup: BundleLookup = Depends(get_bundle_lookup),
) -> Response:
    """Download a complete evidence bundle with content negotiation.

    v1.1.0 (US-12): real lookup via the injected BundleLookup.
    v1.0.5 (US-2): content negotiation by Accept header.

    The synthetic bundle generator that v1.0.5 used as a default
    is REMOVED from this production path. Tests that need synthetic
    bundles inject InMemoryBundleLookup with `_synthetic_bundle_for_tests`.
    """
    content_type = _select_content_type(accept)

    if content_type is None:
        return JSONResponse(
            status_code=406,
            content={
                "error": "not_acceptable",
                "supported": list(SUPPORTED_TYPES),
            },
            headers={"Content-Type": "application/json"},
        )

    # Real lookup (or test injection). Returns None if not found.
    bundle = lookup.lookup(bundle_id)
    if bundle is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "disclosure_id": bundle_id,
            },
            headers={"Content-Type": "application/json"},
        )

    if content_type == "application/scitt+json":
        return JSONResponse(
            status_code=200,
            content=_build_scitt_envelope_from_bundle(bundle),
            headers={"Content-Type": "application/scitt+json"},
        )

    # application/json (default)
    return JSONResponse(
        status_code=200,
        content=bundle,
        headers={"Content-Type": "application/json"},
    )
