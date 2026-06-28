"""P5.5: SCITT/Rekor inclusion-proof verification on the verify page.

When the SCITT client persists the full inclusion-proof payload to
`rekor_entry_json`, the verify page's L3 step calls
`rfc9162_verifier.verify_inclusion_proof` locally (no fetch from the
SCITT log at verify time). When the payload is missing, the page falls
back to [PRESENT] (just the entry ID) — the dev/mock path.

These tests cover the L3 step in isolation (no FastAPI TestClient) so
we avoid the pre-existing test-pollution issues with the
watermarking integration tests.
"""
from __future__ import annotations

import json

from app.verification_page import compute_verification_steps
from app.rfc9162_verifier import reconstruct_root_rfc9162


# ============================================================================
# L3 fallback paths
# ============================================================================


def test_l3_falls_back_to_present_when_no_rekor_entry() -> None:
    cert = {
        "cert_id": "cert_no_rekor",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": None,
        "rekor_entry_json": None,
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_no_rekor", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[ABSENT] SCITT/Rekor entry not stored" in l3


def test_l3_falls_back_to_present_when_only_id_persisted() -> None:
    """Mock SCITT persists only the ID, not the full inclusion proof.

    The page reports [PRESENT] (just the ID) with a note that full
    crypto verification is deferred.
    """
    cert = {
        "cert_id": "cert_id_only",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": "rekor-mock-12345",
        "rekor_entry_json": None,
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_id_only", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[PRESENT]" in l3
    assert "rekor-mock-12345" in l3
    assert "not persisted" in l3 or "deferred" in l3


def test_l3_falls_back_to_present_when_proof_fields_incomplete() -> None:
    """The entry JSON is present but missing required proof fields.

    The page reports [PRESENT] with a note that proof fields are
    incomplete.
    """
    cert = {
        "cert_id": "cert_incomplete",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": "rekor-12345",
        "rekor_entry_json": json.dumps({
            "uuid": "rekor-12345",
            # missing: leaf_hash (we fall back to uuid),
            # missing: log_index, tree_size, root_hash
        }),
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_incomplete", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[PRESENT]" in l3
    assert "incomplete" in l3


# ============================================================================
# L3 cryptographic verification — valid + invalid proof
# ============================================================================


def test_l3_verifies_valid_inclusion_proof() -> None:
    """A valid inclusion proof (audit_path reconstructs to expected
    root) yields [VERIFIED]. The proof is constructed below by
    computing an audit_path from a known tree.
    """
    # Build a tiny Merkle tree (4 leaves) per RFC 9162 §2.1.4. The
    # reconstruction algorithm is hash(h || sibling) on RAW BYTES
    # (not concatenated hex strings), so we use bytes.fromhex here.
    # Tree: root = SHA256( H01 || H23 ) where
    #   H01 = SHA256( L0 || L1 ), H23 = SHA256( L2 || L3 )
    # audit_path for leaf index 2 in a size-4 tree = [L3]
    # (one sibling at the top level — leaf 2 is the right child of H23).
    import hashlib
    L0 = hashlib.sha256(b"leaf-0").digest()
    L1 = hashlib.sha256(b"leaf-1").digest()
    L2 = hashlib.sha256(b"leaf-2-cose-statement").digest()
    L3 = hashlib.sha256(b"leaf-3").digest()
    H01 = hashlib.sha256(L0 + L1).digest()
    H23 = hashlib.sha256(L2 + L3).digest()
    root = hashlib.sha256(H01 + H23).hexdigest()

    # Use leaf_hash = L2 (our cert's COSE_Sign1 statement hash)
    # Audit path for leaf 2 in a 4-leaf tree = [L3, H01] (two siblings:
    # bottom sibling L3, top sibling H01).
    L2_hex = L2.hex()
    entry = {
        "uuid": "rekor-12345",
        "leaf_hash": L2_hex,
        "log_index": 2,
        "tree_size": 4,
        "root_hash": root,
        "audit_path": [L3.hex(), H01.hex()],
    }

    # Sanity: reconstruct_root_rfc9162 should reconstruct to our root.
    assert reconstruct_root_rfc9162(L2_hex, 2, 4, [L3.hex(), H01.hex()]) == root

    cert = {
        "cert_id": "cert_p5_5_verified",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": "rekor-12345",
        "rekor_entry_json": json.dumps(entry),
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_p5_5_verified", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[VERIFIED]" in l3, f"expected [VERIFIED], got: {l3}"


def test_l3_rejects_invalid_inclusion_proof() -> None:
    """A proof with a wrong audit_path yields [FAILED]."""
    import hashlib
    L2 = hashlib.sha256(b"leaf-2").hexdigest()
    # The audit_path is WRONG (just a garbage hash) — reconstruct_root
    # will not match the expected root.
    cert = {
        "cert_id": "cert_p5_5_failed",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": "rekor-12345",
        "rekor_entry_json": json.dumps({
            "uuid": "rekor-12345",
            "leaf_hash": L2,
            "log_index": 2,
            "tree_size": 4,
            "root_hash": "0" * 64,  # WRONG root
            "audit_path": ["1" * 64],  # WRONG sibling
        }),
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_p5_5_failed", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[FAILED]" in l3, f"expected [FAILED], got: {l3}"


def test_l3_handles_malformed_json_gracefully() -> None:
    """Malformed JSON in rekor_entry_json → [FAILED] with parse error."""
    cert = {
        "cert_id": "cert_p5_5_broken",
        "content_hash": "sha256:" + "a" * 64,
        "tsa_url": None,
        "rekor_entry_id": "rekor-12345",
        "rekor_entry_json": "{not valid json",  # malformed
        "primary_key_fingerprint": "ed25519:abc",
    }
    steps = compute_verification_steps("cert_p5_5_broken", cert)
    l3 = next((s for s in steps if "Rekor" in s or "SCITT" in s), None)
    assert l3 is not None
    assert "[FAILED]" in l3
    assert "parse error" in l3.lower()
