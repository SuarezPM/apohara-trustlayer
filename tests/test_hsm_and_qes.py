"""Tests for `app.hsm_adapter` and `app.qes_adapter`.

RED→GREEN coverage for the W8.3 (HSM) + W8.8 (QES) production
wire-ups.
"""
from __future__ import annotations

import warnings
from datetime import datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from app.hsm_adapter import (
    EphemeralEd25519Signer,
    get_signer,
)
from app.qes_adapter import (
    EU_TRUST_LIST_FINGERPRINTS,
    OID_ES_I4_QTST_STATEMENT_1,
    OID_ETSI_TSTS,
    qtsp_qualified_for_jurisdiction,
    validate_qtsp_certificate,
)


# ============================================================================
# HSM adapter tests
# ============================================================================


def test_ephemeral_signer_ed25519_signature_length() -> None:
    """Ed25519 signatures are always 64 bytes."""
    signer = EphemeralEd25519Signer()
    sig = signer.sign(b"hello world" * 10)
    assert len(sig) == 64


def test_ephemeral_signer_deterministic_fingerprint() -> None:
    """The fingerprint is stable across re-instantiations within a process."""
    s1 = EphemeralEd25519Signer(fingerprint_seed=b"unit-test-key")
    s2 = EphemeralEd25519Signer(fingerprint_seed=b"unit-test-key")
    assert s1.key_fingerprint() == s2.key_fingerprint()


def test_ephemeral_signer_ephemeral_keys_per_call() -> None:
    """Each sign() call generates a fresh key (NOT for production)."""
    signer = EphemeralEd25519Signer()
    sig1 = signer.sign(b"identical payload")
    sig2 = signer.sign(b"identical payload")
    assert sig1 != sig2  # different ephemeral keys → different signatures


def test_ephemeral_signer_algorithm_identifier() -> None:
    signer = EphemeralEd25519Signer()
    assert signer.algorithm() == "EdDSA"


def test_factory_falls_back_to_ephemeral() -> None:
    """Without env vars, factory returns EphemeralEd25519Signer."""
    import os

    # Make sure no HSM env vars are set in this test.
    for k in ("TL_AWS_KMS_KEY_ID", "TL_THALES_PKCS11_MODULE"):
        os.environ.pop(k, None)
    signer = get_signer(prefer_aws=True, prefer_thales=True)
    assert isinstance(signer, EphemeralEd25519Signer)
    assert signer.algorithm() == "EdDSA"


def test_aws_kms_signer_requires_key_id() -> None:
    from app.hsm_adapter import AWSKmsMLDSASigner

    import os

    os.environ.pop("TL_AWS_KMS_KEY_ID", None)
    with pytest.raises(ValueError, match="TL_AWS_KMS_KEY_ID"):
        AWSKmsMLDSASigner()


def test_thales_signer_requires_module_path() -> None:
    from app.hsm_adapter import ThalesLunaPqcSigner

    import os

    os.environ.pop("TL_THALES_PKCS11_MODULE", None)
    with pytest.raises(ValueError, match="TL_THALES_PKCS11_MODULE"):
        ThalesLunaPqcSigner()


def test_aws_kms_mu_computation() -> None:
    """Test the μ derivation independently (without AWS calls)."""
    from app.hsm_adapter import AWSKmsMLDSASigner

    # Use a stub client that returns a known public key.
    class StubClient:
        def get_public_key(self, KeyId: str) -> dict[str, bytes]:
            return {"PublicKey": b"\x00" * 1952}  # ML-DSA-65 pubkey size

    signer = AWSKmsMLDSASigner(key_id="alias/test", boto3_client=StubClient())
    mu = signer._compute_mu(b"\x00" * 1952, b"test payload")
    assert len(mu) == 64  # NIST FIPS 204 §6.2: μ is exactly 64 bytes


# ============================================================================
# QES adapter tests
# ============================================================================


def _make_test_cert(with_qc: bool = True, with_esi4: bool = True) -> bytes:
    """Build a self-signed RSA test certificate with optional qcStatements."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qtsp-test")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qtsp-test")]))
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
        )
        if with_qc:
            qc_oid = ObjectIdentifier("1.3.6.1.5.5.7.1.3")
            if with_esi4:
                # OID 0.4.0.19422.1.1 in DER (per ITU-T X.690 §8.19)
                esi4 = bytes.fromhex("0400cbf60101")
                qc_inner = bytes([0x06, len(esi4)]) + esi4
                qc_der = bytes([0x30, len(qc_inner)]) + qc_inner
            else:
                # qcStatements present but missing esi4-qtstStatement-1
                other_oid = bytes.fromhex("0400cbf60102")  # fake
                qc_inner = bytes([0x06, len(other_oid)]) + other_oid
                qc_der = bytes([0x30, len(qc_inner)]) + qc_inner
            builder = builder.add_extension(
                x509.UnrecognizedExtension(qc_oid, qc_der), critical=False
            )
        cert = builder.sign(key, hashes.SHA256(), default_backend())
        return cert.public_bytes(serialization.Encoding.DER)


def test_qes_no_qc_statements_extension() -> None:
    result = validate_qtsp_certificate(_make_test_cert(with_qc=False))
    assert result.has_eu_compliance_statement is False
    assert result.is_qualified is False
    assert any("qcStatements extension not present" in i for i in result.issues)


def test_qes_qc_present_without_esi4() -> None:
    result = validate_qtsp_certificate(_make_test_cert(with_qc=True, with_esi4=False))
    assert result.has_eu_compliance_statement is False
    assert result.is_qualified is False
    assert any("esi4-qtstStatement-1" in i for i in result.issues)


def test_qes_with_esi4_qtst_statement_1() -> None:
    result = validate_qtsp_certificate(_make_test_cert(with_qc=True, with_esi4=True))
    assert result.has_eu_compliance_statement is True
    assert result.regulatory_basis  # non-empty when esi4 present
    assert "Reg (EU) No 910/2014" in str(result.regulatory_basis)
    assert "ETSI EN 319 422" in str(result.regulatory_basis)


def test_qes_invalid_cert_returns_error() -> None:
    result = validate_qtsp_certificate(b"not-a-cert")
    assert result.is_qualified is False
    assert any("X.509 parse failed" in i for i in result.issues)


def test_qtsp_qualified_for_jurisdiction_actalis() -> None:
    assert qtsp_qualified_for_jurisdiction("http://timestamp.actalis.com") is True
    assert (
        qtsp_qualified_for_jurisdiction("http://timestamp.actalis.com", jurisdiction="EU")
        is True
    )


def test_qtsp_qualified_for_jurisdiction_non_eu() -> None:
    """Only EU jurisdiction grants eIDAS presumption."""
    assert (
        qtsp_qualified_for_jurisdiction("http://timestamp.actalis.com", jurisdiction="US")
        is False
    )


def test_qtsp_qualified_for_jurisdiction_freetsa_rejected() -> None:
    """FreeTSA is NOT on the EU Trust List (per audit-8)."""
    assert qtsp_qualified_for_jurisdiction("https://freetsa.org/tsr") is False


def test_qtsp_qualified_for_jurisdiction_unknown_rejected() -> None:
    assert qtsp_qualified_for_jurisdiction("https://unknown-tsa.example.com/tsr") is False


def test_qes_oid_constants() -> None:
    """Per ETSI EN 319 422 v1.1.1 Annex B (RFC 9162 §8.19 DER encoding)."""
    assert OID_ETSI_TSTS == "0.4.0.19422.1"
    assert OID_ES_I4_QTST_STATEMENT_1 == "0.4.0.19422.1.1"


def test_eu_trust_list_fingerprints_populated() -> None:
    """The 3 eIDAS-qualified TSA root CAs are listed."""
    assert "actalis_eu_qualified_ts_ca_g1" in EU_TRUST_LIST_FINGERPRINTS
    assert "sectigo_eidas_qualified" in EU_TRUST_LIST_FINGERPRINTS
    assert "digicert_eidas_qualified" in EU_TRUST_LIST_FINGERPRINTS
    for fp in EU_TRUST_LIST_FINGERPRINTS.values():
        # SHA-1 fingerprint is 20 bytes = 40 hex chars.
        assert len(fp) == 40
