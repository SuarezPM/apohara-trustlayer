"""Hash chain domain logic.

Per plan v3.1 §Risks R5: append-only, monotonic row numbers per chain_id,
prev_hash points to previous row_hash.

This is the Python-side wrapper. The crypto primitives (BLAKE3,
Ed25519 signing) are called via the Rust extension `apohara_trustlayer`
(tl-ffi crate), not via subprocess or local re-implementation.

A pure-Python fallback (hashlib.sha256) is used when the Rust
extension is not importable. This allows unit tests and CI docs builds
to run without compiling the Rust extension. Production deployments
MUST install the Rust extension — a startup check warns if missing.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime


def _hasher():
    """Return a function (bytes) -> hex_digest, preferring tl-ffi BLAKE3.

    tl-ffi is the production crypto (Plan v3.1 Architect Change 2).
    Fallback to hashlib.sha256 when tl-ffi isn't importable (CI docs,
    unit tests). Production sets TL_ALLOW_HASHLIB_FALLBACK=false to fail
    loud instead of using the weaker fallback.
    """
    try:
        from apohara_trustlayer import blake3_hash_hex  # type: ignore[import-not-found]

        def _blake3(data: bytes) -> str:
            return blake3_hash_hex(data)
        return _blake3
    except ImportError:
        if os.environ.get("TL_ALLOW_HASHLIB_FALLBACK", "true").lower() != "true":
            raise RuntimeError(
                "tl-ffi not importable + TL_ALLOW_HASHLIB_FALLBACK=false. "
                "Production requires `uv pip install apohara-trustlayer`."
            )
        import warnings
        warnings.warn(
            "tl-ffi not importable; falling back to hashlib.sha256 (INSECURE for prod).",
            stacklevel=2,
        )

        def _sha256(data: bytes) -> str:
            return hashlib.sha256(data).hexdigest()
        return _sha256


@dataclass(frozen=True)
class ChainHead:
    """Latest entry in a hash chain (or genesis if chain is empty)."""

    chain_id: str
    row_number: int  # 0 for genesis
    row_hash: str  # "0" * 64 for genesis (sentinel)


GENESIS_HASH = "0" * 64


# THREAT: compute_row_hash is the canonical hash that binds the
# entire chain together. If the canonical construction changes, all
# previously-issued receipts become unverifiable (chain broken). The
# function MUST be:
# (1) deterministic — same input always produces same hash.
# (2) collision-resistant — uses BLAKE3 (production) or SHA-256 (test
#     fallback, per TL_ALLOW_HASHLIB_FALLBACK).
# (3) include all the fields a verifier needs to reconstruct the entry:
#     chain_id, row_number, prev_hash, payload, cose_sign1_b64, created_at.
# (4) NOT call any network or external state.
# Adding new fields to the canonical form requires a chain migration
# strategy (re-hash all existing entries or accept the chain break).

def compute_row_hash(
    *,
    chain_id: str,
    row_number: int,
    prev_hash: str,
    payload: bytes,
    cose_sign1_b64: str,
    created_at: datetime,
) -> str:
    """Compute the deterministic row_hash for a chain entry.

    This is the canonical hash function — both signers and verifiers
    MUST use this exact construction. Any change breaks the chain.
    """
    hasher = _hasher()
    canonical = (
        f"{chain_id}|{row_number}|{prev_hash}|"
        f"{cose_sign1_b64}|{created_at.isoformat()}"
    ).encode()
    # Mix payload hash into the canonical form so payload bytes
    # participate in the chain integrity.
    payload_hash = hasher(payload)
    return hasher(canonical + b"|" + payload_hash.encode())


def new_chain_id(prefix: str = "tl") -> str:
    """Generate a fresh chain_id."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def next_row_number(current_head_row_number: int) -> int:
    """Monotonic increment per chain_id (BLAKE3-hashed chain)."""
    return current_head_row_number + 1


def utcnow() -> datetime:
    """UTC now (timezone-aware)."""
    return datetime.now(UTC)
