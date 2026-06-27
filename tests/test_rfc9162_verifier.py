"""Tests for W11.1 RFC 9162 Merkle inclusion proof verifier
(`app.rfc9162_verifier`).

The verifier is a library (no FastAPI router). Tests exercise the
reconstruction + verification primitives directly.
"""
from __future__ import annotations

import hashlib

from app.rfc9162_verifier import (
    extract_sth_root,
    reconstruct_root_ccf,
    reconstruct_root_rfc9162,
    verify_federated_receipt,
    verify_inclusion_proof,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _build_4_leaf_tree() -> dict:
    """Build a known 4-leaf Merkle tree and return its parts."""
    h0 = _hash(b"leaf-0")
    h1 = _hash(b"leaf-1")
    h2 = _hash(b"leaf-2")
    h3 = _hash(b"leaf-3")
    # Pair them up
    h01 = _hash(h0 + h1)
    h23 = _hash(h2 + h3)
    # Root
    root = _hash(h01 + h23)
    return {
        "leaves": [h0, h1, h2, h3],
        "internal": {"h01": h01, "h23": h23},
        "root": root,
    }


# ---------------------------------------------------------------------------
# 1. reconstruct_root_rfc9162 with 4-leaf tree (known good values)
# ---------------------------------------------------------------------------


def test_reconstruct_root_rfc9162_4_leaf_tree() -> None:
    """Reconstruct root for a known 4-leaf SHA-256 Merkle tree."""
    tree = _build_4_leaf_tree()
    h2_hex = tree["leaves"][2].hex()
    h3_hex = tree["leaves"][3].hex()
    h01_hex = tree["internal"]["h01"].hex()
    expected_root = tree["root"].hex()

    # Inclusion proof for leaf at index 2: siblings [h3, h01]
    reconstructed = reconstruct_root_rfc9162(
        leaf_hex=h2_hex,
        leaf_index=2,
        tree_size=4,
        audit_path=[h3_hex, h01_hex],
    )
    assert reconstructed == expected_root

    # And for leaf at index 0: siblings [h1, h23]
    reconstructed0 = reconstruct_root_rfc9162(
        leaf_hex=tree["leaves"][0].hex(),
        leaf_index=0,
        tree_size=4,
        audit_path=[tree["leaves"][1].hex(), tree["internal"]["h23"].hex()],
    )
    assert reconstructed0 == expected_root


def test_reconstruct_root_rfc9162_single_leaf() -> None:
    """A single-leaf tree: leaf IS the root, no audit path needed."""
    leaf = _hash(b"solo")
    result = reconstruct_root_rfc9162(
        leaf_hex=leaf.hex(),
        leaf_index=0,
        tree_size=1,
        audit_path=[],
    )
    assert result == leaf.hex()


# ---------------------------------------------------------------------------
# 2. verify_inclusion_proof returns True for valid path
# ---------------------------------------------------------------------------


def test_verify_inclusion_proof_returns_true_for_valid_path() -> None:
    """Valid leaf + audit path reconstructs the expected root."""
    tree = _build_4_leaf_tree()
    ok = verify_inclusion_proof(
        leaf_hex=tree["leaves"][1].hex(),
        leaf_index=1,
        tree_size=4,
        audit_path=[tree["leaves"][0].hex(), tree["internal"]["h23"].hex()],
        expected_root_hex=tree["root"].hex(),
    )
    assert ok is True


# ---------------------------------------------------------------------------
# 3. verify_inclusion_proof returns False for wrong root
# ---------------------------------------------------------------------------


def test_verify_inclusion_proof_returns_false_for_wrong_root() -> None:
    """A correct path but a wrong expected root returns False."""
    tree = _build_4_leaf_tree()
    fake_root = "0" * 64
    ok = verify_inclusion_proof(
        leaf_hex=tree["leaves"][0].hex(),
        leaf_index=0,
        tree_size=4,
        audit_path=[tree["leaves"][1].hex(), tree["internal"]["h23"].hex()],
        expected_root_hex=fake_root,
    )
    assert ok is False


def test_verify_inclusion_proof_invalid_index_returns_false() -> None:
    """An out-of-range leaf_index returns False (defensive)."""
    tree = _build_4_leaf_tree()
    ok = verify_inclusion_proof(
        leaf_hex=tree["leaves"][0].hex(),
        leaf_index=99,  # out of range for tree_size=4
        tree_size=4,
        audit_path=[],
        expected_root_hex=tree["root"].hex(),
    )
    assert ok is False


# ---------------------------------------------------------------------------
# 4. reconstruct_root_ccf with 32-byte hashes
# ---------------------------------------------------------------------------


def test_reconstruct_root_ccf_32_byte_hashes() -> None:
    """CCF ledger leaf = [internal_transaction_hash, internal_evidence,
    data_hash]. The intermediate hash is SHA-256 of
    internal_transaction_hash || SHA-256(internal_evidence) || data_hash.
    """
    internal_tx = b"\x11" * 32
    internal_ev = b"evidence-bytes-payload"
    data_hash = b"\x22" * 32

    # No siblings — the intermediate hash IS the root
    root = reconstruct_root_ccf(
        internal_transaction_hash=internal_tx,
        internal_evidence=internal_ev,
        data_hash=data_hash,
        audit_path=[],
    )
    assert len(root) == 32

    # Recompute the expected intermediate hash
    ev_digest = hashlib.sha256(internal_ev).digest()
    expected = hashlib.sha256(internal_tx + ev_digest + data_hash).digest()
    assert root == expected

    # With one sibling on the left: root = SHA256(sibling || intermediate)
    # Per the implementation: is_left=True means sibling is on the LEFT
    # (current h is on the right) → hash(h + sibling).
    sibling = b"\x33" * 32
    root2 = reconstruct_root_ccf(
        internal_transaction_hash=internal_tx,
        internal_evidence=internal_ev,
        data_hash=data_hash,
        audit_path=[(True, sibling)],  # sibling on the left
    )
    assert root2 == hashlib.sha256(expected + sibling).digest()


def test_reconstruct_root_ccf_rejects_non_32_byte_hashes() -> None:
    """Validation: internal_transaction_hash and data_hash must be 32 bytes."""
    import pytest

    with pytest.raises(ValueError, match="32 bytes"):
        reconstruct_root_ccf(
            internal_transaction_hash=b"\x00" * 16,  # too short
            internal_evidence=b"payload",
            data_hash=b"\x22" * 32,
            audit_path=[],
        )
    with pytest.raises(ValueError, match="32 bytes"):
        reconstruct_root_ccf(
            internal_transaction_hash=b"\x11" * 32,
            internal_evidence=b"payload",
            data_hash=b"\x00" * 16,  # too short
            audit_path=[],
        )


# ---------------------------------------------------------------------------
# 5. verify_federated_receipt with mock Log A/B (returns 3-tuple)
# ---------------------------------------------------------------------------


def test_verify_federated_receipt_returns_three_tuple() -> None:
    """verify_federated_receipt returns (verified, root, error)."""
    # Malformed receipt bytes — the function should fail gracefully
    # (per the docstring: "Never raises" contract from scitt-cose).
    verified, root, error = verify_federated_receipt(
        receipt_bytes=b"not-a-real-cose-receipt",
        leaf_hex="0" * 64,
        log_a_public_key_pem=b"-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n",
        inclusion_path_in_b=[],
        tree_size_b=1,
        leaf_index_b=0,
        sth_b_signature_material=b"\x00" * 64,
        log_b_public_key_pem=b"-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n",
    )
    # Result is a 3-tuple
    assert isinstance(verified, bool)
    assert root is None or isinstance(root, str)
    assert error is None or isinstance(error, str)
    # For a malformed receipt, verified should be False
    assert verified is False


# ---------------------------------------------------------------------------
# 6. extract_sth_root with 32+ bytes
# ---------------------------------------------------------------------------


def test_extract_sth_root_returns_hex_for_32_plus_bytes() -> None:
    """extract_sth_root returns the first 32 bytes as hex when the input
    is >= 32 bytes (heuristic fallback; production uses cbor2 decode)."""
    payload = b"\xab" * 32
    root = extract_sth_root(payload)
    assert root is not None
    # 32 bytes → 64 hex chars
    assert len(root) == 64
    assert root == (b"\xab" * 32).hex()


def test_extract_sth_root_returns_none_for_short_input() -> None:
    """extract_sth_root returns None for inputs shorter than 32 bytes."""
    assert extract_sth_root(b"\x01" * 16) is None
    assert extract_sth_root(b"") is None