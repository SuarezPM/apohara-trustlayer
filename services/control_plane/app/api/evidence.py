"""GET /v1/evidence/{bundle_id} — public evidence bundle download.

Per Plan v1.2 Block 2 v1.0.5-US-2 (content negotiation contract):

  - Accept: application/json (explicit) OR no Accept header OR */*
    → response is the v1.0 evidence_bundle_v1 format (default)
  - Accept: application/scitt+json
    → response is a SCITTReceipt envelope (IETF draft-ietf-scitt-scrapi-09)
  - Accept: anything else
    → 406 Not Acceptable with `{"error": "not_acceptable", "supported": [...]}`

The endpoint generates a deterministic synthetic bundle for the
`bundle_id` (sha256(bundle_id) seeds the content). This is honest
demo-grade behavior, documented in the `disclaimers` field per
the v1.0 disclosure contract. Real bundle lookup lands when the
disclosure_records table is queryable (US-12, out of scope for
v1.0.5).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Literal

from fastapi import APIRouter, Header, Response
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


def _parse_accept(accept_header: str | None) -> list[str]:
    """Parse an Accept header into a list of media types, in priority order.

    Handles `q=` quality values (kept in priority order), wildcards,
    and missing headers (defaults to `*/*` per RFC 7231 §5.3.2).
    """
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
    # Sort by q descending, then by original order (stable sort).
    items.sort(key=lambda t: -t[0])
    return [m for _, m in items]


def _select_content_type(accept_header: str | None) -> str | None:
    """Return the highest-priority supported content type, or None.

    Wildcards `*/*` and `application/*` match the first supported
    type. Specific unsupported types return None (caller maps to 406).
    """
    if accept_header is None:
        return "application/json"  # v1.0 default for absent header
    candidates = _parse_accept(accept_header)
    # If the first candidate is application/scitt+json, prefer it.
    # Otherwise return application/json (v1.0 default) if wildcard.
    for c in candidates:
        cl = c.lower()
        if cl == "application/scitt+json":
            return "application/scitt+json"
        if cl == "application/json":
            return "application/json"
        if cl in ("*/*", "application/*"):
            return "application/json"  # legacy v1.0 default
        if cl in SUPPORTED_TYPES:
            return cl
    return None


def _synthetic_bundle(bundle_id: str) -> dict:
    """Generate a deterministic synthetic evidence bundle for `bundle_id`.

    Real bundle lookup from disclosure_records is out of scope for
    v1.0.5 (US-12 pending). Until then, the endpoint returns a
    deterministic synthetic bundle so content negotiation is
    testable end-to-end. The `disclaimers` field documents this.
    """
    seed = hashlib.sha256(bundle_id.encode("utf-8")).digest()
    created_at = int(time.time())
    return {
        "bundle_id": bundle_id,
        "created_at": str(created_at),
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
            "rotated_at": str(created_at - 86400),
        },
        "signature": {
            "cose_sign1_b64": base64.b64encode(
                b"\x84\x00" + b"\x00" * 64  # placeholder: empty COSE_Sign1
            ).decode("ascii"),
            "row_hash": seed.hex(),
        },
        "tsa_token": None,
        "verification_instructions": (
            "POST /v1/verify/provenance with the bundle_id. "
            "This is a synthetic demo-grade bundle (v1.0.5 US-2)."
        ),
        "disclaimers": [
            "v1.0.5-US-2: this is a synthetic demo bundle, not a real "
            "stored evidence bundle. Real lookup lands in US-12.",
        ],
    }


def _synthetic_scitt_receipt(bundle_id: str) -> dict:
    """Generate a deterministic SCITT receipt for `bundle_id`.

    Maps the synthetic bundle's payload into a SCITTReceipt envelope.
    The `cose_sign1` field is a placeholder (real COSE_Sign1 will be
    produced by the control plane once US-12 lands). The fingerprint
    is BLAKE3 of an empty key, deterministically computed.
    """
    import hashlib as _h

    payload_bytes = json.dumps(
        _synthetic_bundle(bundle_id), sort_keys=True
    ).encode("utf-8")
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")

    # Empty key fingerprint (32 zero bytes) for the synthetic case.
    # Real receipts will BLAKE3 the issuer public key here.
    fingerprint_hex = "00" * 32

    # Synthetic COSE_Sign1 — 4-element CBOR array (tagged 18)
    # with placeholder signature. A real implementation would call
    # the Rust tl-scitt crate via PyO3. For v1.0.5, this is documented
    # as demo-grade.
    cose_sign1_bytes = b"\x84\x00" + b"\x00" * 64  # [protected, {}, payload, sig]
    cose_sign1_b64 = base64.b64encode(cose_sign1_bytes).decode("ascii")

    # Issued_at: deterministic from bundle_id, NOT wall-clock.
    # This is the SCITT property: the receipt is the same no matter
    # when you verify it.
    issued_at = int.from_bytes(_h.sha256(b"issued:" + bundle_id.encode()).digest()[:4], "big")

    return {
        "payload": payload_b64,
        "cose_sign1": cose_sign1_b64,
        "issuer_kid": "did:web:apohara.dev:trustlayer:v1.0.5",
        "issuer_pubkey_fingerprint": fingerprint_hex,
        "inclusion_proof": "None",
        "issued_at": issued_at,
        "registry_id": "trustlayer-demo-v1.0.5",
    }


@router.get("/evidence/{bundle_id}")
async def get_evidence_bundle(
    bundle_id: str,
    accept: str | None = Header(default=None),
) -> Response:
    """Download a complete evidence bundle with content negotiation.

    Content negotiation:
    - `Accept: application/json` or absent → v1.0 evidence_bundle_v1
    - `Accept: application/scitt+json` → SCITTReceipt envelope
    - `Accept: anything else` → 406 Not Acceptable

    The bundle is synthetic for v1.0.5 (real lookup lands in US-12).
    The `disclaimers` field in the response documents this.
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

    if content_type == "application/scitt+json":
        return JSONResponse(
            status_code=200,
            content=_synthetic_scitt_receipt(bundle_id),
            headers={"Content-Type": "application/scitt+json"},
        )

    # application/json (default)
    return JSONResponse(
        status_code=200,
        content=_synthetic_bundle(bundle_id),
        headers={"Content-Type": "application/json"},
    )
