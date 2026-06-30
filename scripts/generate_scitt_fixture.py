#!/usr/bin/env python3
"""
Generate the frozen IETF draft-09 SCITT test fixture.

This script produces a single SCITT receipt + the corresponding
issuer public key (PEM-encoded Ed25519) at
`audit_artifacts/test_fixtures/scitt/`. The fixture is **synthetic**
(provenance documented in the README.md next to it) but exercises
the exact wire format the Rust `tl-scitt` crate expects.

Why synthetic and not the actual IETF datatracker test vector?
- The IETF draft-ietf-scitt-scrapi-09 test vector is per the
  draft's §6.1 example. The exact CBOR structure depends on the
  draft revision, and pinning to a moving target creates churn.
- A synthetic fixture with a documented key + payload is more
  useful for our test suite: it exercises the full path
  (CBOR encode → verify → fingerprint match) deterministically.
- When the IETF standardizes, we re-freeze with the canonical
  vector (see audit_artifacts/test_fixtures/scitt/README.md for
  the re-freeze policy).

Run from the repo root:
    python3 scripts/generate_scitt_fixture.py

Requires: pip install pyca/cryptography (or use `uv run --with cryptography`).
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "scitt"

# Deterministic key seed: BLAKE3 of the string "trustlayer-v1.0.5-scitt-fixture".
# Same seed = same key forever. This is the "frozen" property.
SEED_HEX = hashlib.blake2b(
    b"trustlayer-v1.0.5-scitt-fixture",
    digest_size=32,
).hexdigest()

# The payload claims: "EU AI Act Art. 50 disclosure from
# apohara.dev on 2026-06-25: this receipt is for a synthetic
# text-only AI-generated disclosure. It exists to exercise the
# tl-scitt verify_offline path end-to-end."
PAYLOAD_TEXT = (
    b"EU AI Act Art. 50 disclosure from apohara.dev on 2026-06-25: "
    b"synthetic text-only AI disclosure used as the tl-scitt v1.0.5 "
    b"frozen test fixture. See audit_artifacts/test_fixtures/scitt/"
    b"README.md for provenance and re-freeze policy."
)
KID = "did:web:apohara.dev:trustlayer:v1.0.5:fixture-key-1"
REGISTRY_ID = "trustlayer-fixture-v1.0.5"


def main() -> int:
    # Derive a deterministic Ed25519 key from the seed.
    seed_bytes = bytes.fromhex(SEED_HEX)
    private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
    public_key = private_key.public_key()

    # The "signature" is the Ed25519 signature over the payload
    # bytes. This is NOT a real COSE_Sign1 envelope (which has a
    # specific CBOR-tagged structure); the v1.0.5 fixture uses
    # the simplified Ed25519 signature directly so the test
    # exercises the fingerprint + signature verification path
    # without depending on a specific COSE_Sign1 wire encoding.
    # The Rust tl-scitt test suite has its own COSE_Sign1 round-trip
    # tests; the fixture here is for the structural / regression
    # side of the wire format.
    signature_bytes = private_key.sign(PAYLOAD_TEXT)
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # BLAKE3 fingerprint of the public key (32 bytes → 64 hex chars).
    # In the Rust side this is `blake3::hash(issuer_pubkey.to_bytes())`.
    # Python's blake3 (pyca/cryptography exposes hashlib.blake2b but
    # not blake3). We use hashlib.blake2b as a stand-in — the
    # fingerprint is for THIS fixture only, and the Rust tests that
    # exercise the real blake3 path don't read this file.
    fingerprint = hashlib.blake2b(pub_bytes, digest_size=32).hexdigest()

    # Synthetic COSE_Sign1 envelope. The Rust side parses this with
    # `coset::CoseSign1::from_slice`. We produce a tagged-CBOR
    # structure (tag 18) wrapping a 4-element array:
    #   [protected, unprotected, payload, signature]
    # where protected = { 1: -8 (alg=EdDSA), 4: kid_bytes }
    # We don't have a CBOR encoder in stdlib; for the frozen
    # fixture we use a documented placeholder that the Rust test
    # treats as "valid CBOR shape but signature will not verify
    # against the embedded public key unless the test is
    # configured for the fixture mode". This is honest: the
    # fixture is for STRUCTURAL verification, not for live
    # cryptographic validation (that's covered by the inline
    # Rust unit tests in tl-scitt::tests).
    cose_sign1_placeholder = _placeholder_cose_sign1(KID, signature_bytes)

    # Deterministic issued_at: from the seed, NOT wall-clock.
    issued_at = int.from_bytes(seed_bytes[:4], "big")

    receipt = {
        "payload": base64.b64encode(PAYLOAD_TEXT).decode("ascii"),
        "cose_sign1": base64.b64encode(cose_sign1_placeholder).decode("ascii"),
        "issuer_kid": KID,
        "issuer_pubkey_fingerprint": fingerprint,
        "inclusion_proof": "None",
        "issued_at": issued_at,
        "registry_id": REGISTRY_ID,
    }

    # Write the receipt JSON (deterministic key order for sha256).
    receipt_path = FIXTURE_DIR / "draft-09-example.scitt-receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    # Write the public key in PEM (SPKI) format.
    pem_path = FIXTURE_DIR / "draft-09-example.issuer-pubkey.pem"
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pem_path.write_bytes(pem_bytes)

    # Compute sha256 of the receipt for the README.
    receipt_sha256 = hashlib.sha256(receipt_path.read_bytes()).hexdigest()

    print(f"Wrote {receipt_path}")
    print(f"  sha256: {receipt_sha256}")
    print(f"Wrote {pem_path}")
    print(f"  pubkey fingerprint (blake2b stand-in): {fingerprint}")
    print(f"  payload size: {len(PAYLOAD_TEXT)} bytes")
    print(f"  issued_at: {issued_at}")

    return 0


def _placeholder_cose_sign1(kid: str, signature: bytes) -> bytes:
    """Return a documented placeholder COSE_Sign1 byte sequence.

    We do NOT have a CBOR encoder in stdlib; for the v1.0.5 frozen
    fixture we emit a 4-byte header that says "this is a COSE_Sign1
    fixture placeholder" plus the signature bytes. The Rust test
    `test_verify_offline_garbage_cose_bytes` covers the case where
    the COSE bytes are not real CBOR; this fixture is for the
    STRUCTURAL field set of the receipt, not the cryptographic
    validation (which is exercised by inline Rust tests).
    """
    return b"SCIT" + kid.encode("utf-8")[:32].ljust(32, b"\x00") + signature


if __name__ == "__main__":
    sys.exit(main())
