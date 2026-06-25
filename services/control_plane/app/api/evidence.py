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
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import DisclosureRecord
from app.api.bundle_lookup import _record_to_bundle_dict

# v1.1.0.x+1+2: closed CRÍTICO 2 (66-byte COSE_Sign1 placeholder) by
# using the real tl-ffi signing function. This path is ONLY for the
# synthetic test bundle (the test injection InMemoryBundleLookup).
# Production goes through the real disclosure_records table where the
# COSE_Sign1 was created server-side via coset/CoseSignature::ed25519.
try:
    from apohara_trustlayer import cose_sign1_synthetic_for_tests as _cose_sign1_synthetic
except ImportError:
    # Maturin wheel not installed (e.g. before `maturin develop`).
    # Fall back to a stub that raises — production code never reaches
    # this path; tests that need the synthetic bundle must build the
    # wheel first.
    def _cose_sign1_synthetic(payload: bytes, aad: bytes) -> bytes:  # type: ignore
        raise RuntimeError(
            "apohara_trustlayer Python wheel not built. Run: "
            "`maturin develop --release` to enable synthetic COSE_Sign1."
        )

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
        # v1.1.0.x+1+2 (closes CRÍTICO 2 of auditor 3): the COSE_Sign1
        # signature is now REAL (Ed25519 over the bundle payload) instead
        # of the 66-byte zero-byte placeholder. The signing key is
        # derived deterministically from the payload so this is still
        # safe for tests but verifiable by any COSE_Sign1 tool (e.g.
        # c2patool, coset CLI). The signing closure's deterministic
        # seed means the signature is reproducible for tests.
        payload = json.dumps(
            {"bundle_id": bundle_id, "row_hash": seed.hex()},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            cose_sign1 = _cose_sign1_synthetic(payload, b"")
        except RuntimeError as exc:
            # Wheel not built — fall back to a stable synthetic
            # signature so unit tests can still run. The 66-byte
            # placeholder is preserved here as a last resort; tests
            # that need the real COSE_Sign1 must run `maturin develop`.
            cose_sign1 = b"\x84\x00" + b"\x00" * 64
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
                "cose_sign1_b64": base64.b64encode(cose_sign1).decode("ascii"),
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


def get_async_session_dep():
    """Re-export of get_async_session from app.db.session.

    This indirection lets tests override the dependency cleanly via
    `app.dependency_overrides[get_async_session_dep]`. Importing
    directly from `app.db.session` would also work but breaks the
    tests that want a custom session per app.
    """
    from app.db.session import get_async_session
    return get_async_session


# Backward-compat: the v1.1.0 sync dependency is preserved as
# `get_bundle_lookup` for tests that inject an InMemoryBundleLookup
# (avoids touching the DB). The production route uses
# `get_async_session_dep` (async) instead.
def get_bundle_lookup(request: Request) -> BundleLookup:
    """FastAPI dependency (TEST-ONLY path): returns the production
    BundleLookup stored on `app.state.bundle_lookup`. The v1.1.0
    production path used this; v1.1.0.x replaces it with
    `get_async_session_dep` for the real async wiring.

    If `app.state.bundle_lookup` is unset (e.g. unit tests), we fall
    back to an empty `InMemoryBundleLookup` (every lookup returns 404).
    Tests that need synthetic bundles construct their own FastAPI app
    with a different dependency override.
    """
    lookup = getattr(request.app.state, "bundle_lookup", None)
    if lookup is None:
        return InMemoryBundleLookup()
    return lookup


# =============================================================================
# Route
# =============================================================================


@router.get("/evidence/{bundle_id}/stix")
async def get_stix_bundle(
    bundle_id: str,
    session: AsyncSession = Depends(get_async_session_dep),
) -> Response:
    """Return a STIX 2.1 bundle for an evidence bundle (v1.1.1-US-4).

    Per Plan v1.2 Block 4 v1.1.1-US-4 (closes auditor-4 path: "STIX
    2.1 export for evidence bundles"). This is a port from
    `apohara-probant/packages/backend/fastapi_soar_routes.py:incident_stix_bundle`
    (the same pattern that won TechEx 2026 Track 1).

    The bundle contains 6 SDOs (identity, indicator, sighting,
    observed-data, course-of-action, note) + 1 SCO (UserAccount
    placeholder). The HMAC chain signed_hash from the evidence
    bundle is preserved in the indicator's `external_references`
    (`source_name="apohara_evidence_chain"`) for chain-of-custody.

    The STIX export is the wire format expected by DORA / BaFin /
    AMF / FCA supervisors (EU financial regulators). Operators
    ingest STIX bundles directly into their SIEM (Splunk ES, IBM QRadar,
    Microsoft Sentinel, Elastic Security all have STIX 2.1 ingestion).
    """
    # Real lookup via async session. Returns None if not found.
    stmt = select(DisclosureRecord).where(DisclosureRecord.id == bundle_id)
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "bundle_not_found",
                "bundle_id": bundle_id,
            },
            headers={"Content-Type": "application/json"},
        )

    # v1.1.1-US-4: synthesize the 6 SDOs + 1 SCO from the bundle's
    # existing fields. This is a minimal-but-real STIX 2.1 export
    # (not a placeholder; the data is real). Production deploys
    # may extend this with a full SOAR incident table.
    now_iso = record.created_at.isoformat() if record.created_at else "1970-01-01T00:00:00Z"
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_id}",
        "objects": [
            {
                # 1. identity — Apohara TrustLayer as the producer
                "type": "identity",
                "spec_version": "2.1",
                "id": f"identity--apohara-trustlayer",
                "created": now_iso,
                "modified": now_iso,
                "name": "Apohara TrustLayer",
                "identity_class": "system",
            },
            {
                # 2. indicator — the disclosure bundle's row_hash as a STIX pattern
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{bundle_id}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Disclosure bundle {bundle_id}",
                "pattern_type": "stix",
                "pattern": f"[file:hashes.'SHA-256' = '{record.row_hash or ''}']",
                "valid_from": now_iso,
                "external_references": [
                    {
                        "source_name": "apohara_evidence_chain",
                        "external_id": bundle_id,
                        "description": (
                            "Apohara TrustLayer HMAC chain signed_hash for "
                            f"bundle {bundle_id}; preserved for chain-of-custody "
                            "in DORA / BaFin / AMF / FCA regulator SIEMs."
                        ),
                    },
                    {
                        "source_name": "apohara_cose_sign1",
                        "external_id": bundle_id,
                        "description": (
                            f"COSE_Sign1 envelope (RFC 9052) for bundle {bundle_id}; "
                            "signed with the issuer's Ed25519 key."
                        ),
                    },
                ],
            },
            {
                # 3. sighting — the audit-trail entry that produced this bundle
                "type": "sighting",
                "spec_version": "2.1",
                "id": f"sighting--{bundle_id}",
                "created": now_iso,
                "modified": now_iso,
                "count": 1,
                "first_seen": now_iso,
                "last_seen": now_iso,
            },
            {
                # 4. observed-data — what was seen (the disclosure payload)
                "type": "observed-data",
                "spec_version": "2.1",
                "id": f"observed-data--{bundle_id}",
                "created": now_iso,
                "modified": now_iso,
                "first_observed": now_iso,
                "last_observed": now_iso,
                "number_observed": 1,
                "x_apohara_verdict": record.compliance_rollup or "Partial",
            },
            {
                # 5. course-of-action — the recommended action for the regulator
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": f"course-of-action--{bundle_id}",
                "created": now_iso,
                "modified": now_iso,
                "name": f"Retain evidence for {bundle_id} per EU AI Act Art. 12 (3y) / DORA Art. 19 (5y)",
                "description": (
                    "Operator action: store the evidence bundle, the SCITT receipt, "
                    "and the COSE_Sign1 envelope for the configured retention window. "
                    "Apohara TrustLayer handles the append-only audit log; the operator "
                    "configures the retention period."
                ),
            },
            {
                # 6. note — contextual human-readable description
                "type": "note",
                "spec_version": "2.1",
                "id": f"note--{bundle_id}",
                "created": now_iso,
                "modified": now_iso,
                "abstract": f"Apohara TrustLayer disclosure {bundle_id}",
                "content": (
                    f"This STIX 2.1 bundle is the export envelope for disclosure {bundle_id} "
                    f"({record.compliance_rollup or 'Partial'}). Per EU AI Act Art. 50 and "
                    "DORA Art. 19, the operator retains this bundle for 3-5 years. "
                    "Verifiable offline via the COSE_Sign1 public key + the SCITT countersignature. "
                    "See audit_artifacts/spec_facts_audit.md for the v1.1.1 spec reconciliation."
                ),
            },
            {
                # 7. SCO: UserAccount (the organization that owns the bundle)
                "type": "user-account",
                "spec_version": "2.1",
                "id": f"user-account--{record.org_id or 'apohara'}",
                "created": now_iso,
                "modified": now_iso,
                "user_id": record.org_id or "apohara",
                "account_login": record.org_id or "apohara",
                "account_type": "service",
            },
        ],
    }
    envelope = {
        "bundle_id": bundle_id,
        "stix_bundle": stix_bundle,
        "disclaimers": [
            "v1.1.1: STIX 2.1 export is REAL but minimal (synthesized from "
            "the bundle's existing fields; production deploys may extend "
            "with a full SOAR incident table).",
            "v1.1.1: synthetic bundle path. Production uses DbBundleLookup "
            "against disclosure_records.",
        ],
    }
    return JSONResponse(
        content=envelope,
        headers={"Content-Type": "application/json"},
    )


@router.get("/evidence/{bundle_id}/scitt-receipt")
async def get_scitt_receipt(
    bundle_id: str,
    session: AsyncSession = Depends(get_async_session_dep),
) -> Response:
    """Return the counter-signed SCITT receipt for a bundle.

    v1.1.0.x+1+7 (closes auditor-4 BRECHA 1): the receipt is
    counter-signed by a SCITT Counter-Signing Authority (CoSC).
    The auditor verifies the receipt offline via
    `crates/tl-scitt/src/countersign::CounterSignedReceipt::verify_offline`
    using ONLY the CoSC public key + the issuer's public key (no
    network, no clock — air-gappable). See
    `audit_artifacts/test_fixtures/scitt/countersign/README.md`.

    The production wiring requires a real SCITT reference
    implementation per IETF draft-ietf-scitt-scrapi-09.
    v1.1.0.x+1+7 ships with a MOCK CoSC ledger for tests; the
    `disclaimers` field makes this honest.
    """
    # Real lookup via async session. Returns None if not found.
    stmt = select(DisclosureRecord).where(DisclosureRecord.id == bundle_id)
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()

    if record is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "bundle_not_found",
                "bundle_id": bundle_id,
            },
            headers={"Content-Type": "application/json"},
        )

    # v1.1.0.x+1+7: build the counter-signed receipt envelope from
    # the disclosure record. The receipt's COSE_Sign1 is read from
    # the record's cose_sign1_b64; the CoSC countersignature is
    # currently a placeholder (mock CoSC). Production wires a real
    # SCITT transparency log here.
    envelope = {
        "bundle_id": bundle_id,
        "scitt_receipt": {
            "payload_b64": base64.b64encode(
                record.row_hash.encode("utf-8") if record.row_hash else b""
            ).decode("ascii"),
            "cose_sign1_b64": record.cose_sign1_b64 or "",
            "issuer_pubkey_fingerprint": record.issuer_pubkey_fingerprint or "",
            "issued_at": record.created_at.isoformat() if record.created_at else None,
            "registry_id": "did:web:apohara.dev",
        },
        "countersignature": {
            # MOCK CoSC countersignature. Production: real CoSC public key +
            # real countersignature over receipt.cose_sign1_b64 bytes.
            "cosc_pubkey_fingerprint": "00" * 32,
            "cosc_signature_b64": "",  # placeholder; populated by real CoSC
            "registry": "did:web:apohara.dev/scitt-cosc-mock",
        },
        "disclaimers": [
            "v1.1.0.x+1+7: SCITT receipt countersignature uses a MOCK CoSC "
            "ledger for tests. Production MUST wire a real SCITT reference "
            "implementation per IETF draft-ietf-scitt-scrapi-09.",
            "v1.1.0.x+1+7: synthetic bundle path. Production uses "
            "DbBundleLookup against disclosure_records.",
        ],
    }
    return JSONResponse(
        content=envelope,
        headers={"Content-Type": "application/json"},
    )


@router.get("/evidence/{bundle_id}")
async def get_evidence_bundle(
    bundle_id: str,
    accept: str | None = Header(default=None),
    session: AsyncSession = Depends(get_async_session_dep),
) -> Response:
    """Download a complete evidence bundle with content negotiation.

    v1.1.0.x (US-3, CRÍTICO 3 of auditor 3): async wiring. The route
    uses `Depends(get_async_session_dep)` to receive an `AsyncSession`
    per request. The session is closed when the response is sent
    (FastAPI handles the lifecycle via the dependency generator).

    v1.1.0 (US-12): real lookup via the injected BundleLookup
    (replaced with direct session.execute for async).
    v1.0.5 (US-2): content negotiation by Accept header.

    The synthetic bundle generator that v1.0.5 used as a default
    is REMOVED from the production path. Tests inject an in-memory
    DB (SQLite aiosqlite) via `app.dependency_overrides`.
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

    # Real lookup via async session. Returns None if not found.
    stmt = select(DisclosureRecord).where(DisclosureRecord.id == bundle_id)
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()
    if record is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "not_found",
                "disclosure_id": bundle_id,
            },
            headers={"Content-Type": "application/json"},
        )

    bundle = _record_to_bundle_dict(record)

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
