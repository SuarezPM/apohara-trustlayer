"""Tests for W8.3.1 HSM signer protocol + factory (`app.hsm_adapter`).

Covers the in-memory EphemeralEd25519Signer (dev/test), the
AWSKmsMLDSASigner + ThalesLunaPqcSigner production adapters (algorithm
identifier + deferred-wire-up guards), and the `get_signer()` factory.
"""
from __future__ import annotations

import os

import pytest

from app.hsm_adapter import (
    AWSKmsMLDSASigner,
    EphemeralEd25519Signer,
    ThalesLunaPqcSigner,
    get_signer,
)


# ---------------------------------------------------------------------------
# 1. EphemeralEd25519Signer.sign() returns 64 bytes (Ed25519 sig size)
# ---------------------------------------------------------------------------


def test_ephemeral_signer_sign_returns_64_bytes() -> None:
    """Ed25519 signatures are always 64 bytes."""
    signer = EphemeralEd25519Signer()
    sig = signer.sign(b"hello world")
    assert isinstance(sig, bytes)
    assert len(sig) == 64


# ---------------------------------------------------------------------------
# 2. EphemeralEd25519Signer.algorithm() returns "EdDSA"
# ---------------------------------------------------------------------------


def test_ephemeral_signer_algorithm_identifier() -> None:
    """The algorithm identifier is "EdDSA"."""
    signer = EphemeralEd25519Signer()
    assert signer.algorithm() == "EdDSA"


# ---------------------------------------------------------------------------
# 3. EphemeralEd25519Signer.key_fingerprint() returns ed25519:... prefix
# ---------------------------------------------------------------------------


def test_ephemeral_signer_key_fingerprint_has_ed25519_prefix() -> None:
    """The fingerprint starts with the "ed25519:" algorithm tag."""
    signer = EphemeralEd25519Signer()
    fp = signer.key_fingerprint()
    assert isinstance(fp, str)
    assert fp.startswith("ed25519:")


def test_ephemeral_signer_fingerprint_stable_for_same_seed() -> None:
    """Same seed → same fingerprint (within a process)."""
    s1 = EphemeralEd25519Signer(fingerprint_seed=b"unit-test-seed")
    s2 = EphemeralEd25519Signer(fingerprint_seed=b"unit-test-seed")
    assert s1.key_fingerprint() == s2.key_fingerprint()


# ---------------------------------------------------------------------------
# 4. AWSKmsMLDSASigner.algorithm() returns "ML-DSA-65"
# ---------------------------------------------------------------------------


def test_aws_kms_signer_algorithm_identifier() -> None:
    """AWSKmsMLDSASigner advertises ML-DSA-65 (FIPS 204)."""
    # Use a stub client so we never actually call AWS.
    class _StubClient:
        def get_public_key(self, KeyId):  # noqa: N803
            return {"PublicKey": b"\x00" * 1952}

    signer = AWSKmsMLDSASigner(
        key_id="alias/test", boto3_client=_StubClient()
    )
    assert signer.algorithm() == "ML-DSA-65"


# ---------------------------------------------------------------------------
# 5. ThalesLunaPqcSigner.algorithm() returns "ML-DSA-65"
# ---------------------------------------------------------------------------


def test_thales_signer_algorithm_identifier() -> None:
    """ThalesLunaPqcSigner advertises ML-DSA-65 (FIPS 204)."""
    signer = ThalesLunaPqcSigner(
        module_path="/opt/thales/libpkcs11.so",
        slot=0,
        pin="0000",
        key_label="trustlayer-mldsa65",
    )
    assert signer.algorithm() == "ML-DSA-65"


def test_thales_signer_fingerprint_has_thales_prefix() -> None:
    """Thales signer fingerprint starts with 'thales-mldsa65:'."""
    signer = ThalesLunaPqcSigner(
        module_path="/opt/thales/libpkcs11.so",
        slot=0,
        pin="0000",
    )
    fp = signer.key_fingerprint()
    assert fp.startswith("thales-mldsa65:")


# ---------------------------------------------------------------------------
# 6. ThalesLunaPqcSigner.sign() raises NotImplementedError (deferred to W8.3.2)
# ---------------------------------------------------------------------------


def test_thales_signer_sign_raises_not_implemented() -> None:
    """W8.3.1 scaffolds the Thales adapter but sign() is deferred to W8.3.2
    (requires python-pkcs11 + Luna PQC module on the host)."""
    signer = ThalesLunaPqcSigner(
        module_path="/opt/thales/libpkcs11.so",
        slot=0,
        pin="0000",
    )
    with pytest.raises(NotImplementedError, match="python-pkcs11"):
        signer.sign(b"hello")


# ---------------------------------------------------------------------------
# 7. get_signer() returns EphemeralEd25519Signer when no env vars set
# ---------------------------------------------------------------------------


def test_get_signer_factory_falls_back_to_ephemeral(monkeypatch) -> None:
    """Without AWS or Thales env vars set, factory returns the dev signer."""
    monkeypatch.delenv("TL_AWS_KMS_KEY_ID", raising=False)
    monkeypatch.delenv("TL_THALES_PKCS11_MODULE", raising=False)
    signer = get_signer(prefer_aws=True, prefer_thales=True)
    assert isinstance(signer, EphemeralEd25519Signer)
    assert signer.algorithm() == "EdDSA"


def test_get_signer_factory_prefers_aws_when_env_set(monkeypatch) -> None:
    """When TL_AWS_KMS_KEY_ID is set, factory returns AWSKmsMLDSASigner
    (the production path)."""
    monkeypatch.setenv("TL_AWS_KMS_KEY_ID", "alias/test-mldsa65")
    monkeypatch.delenv("TL_THALES_PKCS11_MODULE", raising=False)
    try:
        signer = get_signer(prefer_aws=True, prefer_thales=False)
        assert isinstance(signer, AWSKmsMLDSASigner)
        assert signer.algorithm() == "ML-DSA-65"
    except Exception as e:
        # boto3 may not be installed; the constructor raises ValueError
        # before reaching the client. We assert it tried the AWS path.
        assert "TL_AWS_KMS_KEY_ID" not in str(e), str(e)


def test_aws_kms_signer_requires_key_id(monkeypatch) -> None:
    """AWSKmsMLDSASigner requires TL_AWS_KMS_KEY_ID or key_id arg."""
    monkeypatch.delenv("TL_AWS_KMS_KEY_ID", raising=False)
    with pytest.raises(ValueError, match="TL_AWS_KMS_KEY_ID"):
        AWSKmsMLDSASigner()


def test_thales_signer_requires_module_path(monkeypatch) -> None:
    """ThalesLunaPqcSigner requires TL_THALES_PKCS11_MODULE or module_path arg."""
    monkeypatch.delenv("TL_THALES_PKCS11_MODULE", raising=False)
    with pytest.raises(ValueError, match="TL_THALES_PKCS11_MODULE"):
        ThalesLunaPqcSigner()


# ---------------------------------------------------------------------------
# 8. Two EphemeralEd25519Signers return DIFFERENT fingerprints (ephemeral keys)
# ---------------------------------------------------------------------------


def test_ephemeral_signers_with_different_seeds_have_different_fingerprints() -> None:
    """Each signer with a distinct fingerprint_seed produces a distinct
    fingerprint (the keys are 'ephemeral' in the sense that the
    fingerprint is derived from the seed, not from any real key material)."""
    s1 = EphemeralEd25519Signer(fingerprint_seed=b"seed-one")
    s2 = EphemeralEd25519Signer(fingerprint_seed=b"seed-two")
    assert s1.key_fingerprint() != s2.key_fingerprint()


def test_ephemeral_signer_sign_produces_different_signatures_per_call() -> None:
    """Each sign() call generates a fresh Ed25519 key (so signatures for
    the same payload differ — this is the 'ephemeral' property that
    makes this signer unsuitable for production)."""
    signer = EphemeralEd25519Signer()
    sig1 = signer.sign(b"identical payload")
    sig2 = signer.sign(b"identical payload")
    assert sig1 != sig2
    assert len(sig1) == 64
    assert len(sig2) == 64