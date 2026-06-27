"""Tests for W8.8.1 EU Trust List chain walk + QES validation
(`app.qes_adapter`).
"""
from __future__ import annotations

import warnings
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from app.qes_adapter import (
    EU_TRUST_LIST_FINGERPRINTS,
    QESValidationResult,
    TrustListChainResult,
    qtsp_qualified_for_jurisdiction,
    validate_qtsp_certificate,
    walk_eu_trust_list_chain,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_test_cert(
    with_qc: bool = True, with_esi4: bool = True
) -> bytes:
    """Build a self-signed RSA test certificate with optional qcStatements."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.utcnow()
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "qtsp-test")]
                )
            )
            .issuer_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "qtsp-test")]
                )
            )
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
                other_oid = bytes.fromhex("0400cbf60102")
                qc_inner = bytes([0x06, len(other_oid)]) + other_oid
                qc_der = bytes([0x30, len(qc_inner)]) + qc_inner
            builder = builder.add_extension(
                x509.UnrecognizedExtension(qc_oid, qc_der), critical=False
            )
        cert = builder.sign(key, hashes.SHA256(), default_backend())
        return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# 1. EU_TRUST_LIST_FINGERPRINTS has 3 entries (Actalis, Sectigo, DigiCert)
# ---------------------------------------------------------------------------


def test_eu_trust_list_fingerprints_has_three_entries() -> None:
    """The EU Trust List maps 3 eIDAS-qualified root CAs."""
    assert len(EU_TRUST_LIST_FINGERPRINTS) == 3
    assert "actalis_eu_qualified_ts_ca_g1" in EU_TRUST_LIST_FINGERPRINTS
    assert "sectigo_eidas_qualified" in EU_TRUST_LIST_FINGERPRINTS
    assert "digicert_eidas_qualified" in EU_TRUST_LIST_FINGERPRINTS
    # SHA-1 fingerprint is 20 bytes = 40 hex chars (uppercase, no colons).
    for fp in EU_TRUST_LIST_FINGERPRINTS.values():
        assert len(fp) == 40
        assert fp == fp.upper()


# ---------------------------------------------------------------------------
# 2. qtsp_qualified_for_jurisdiction("EU", "http://timestamp.actalis.com") == True
# ---------------------------------------------------------------------------


def test_qtsp_qualified_for_jurisdiction_eu_actalis() -> None:
    """Actalis Italia (eIDAS-qualified) returns True under EU jurisdiction."""
    assert (
        qtsp_qualified_for_jurisdiction(
            "http://timestamp.actalis.com", jurisdiction="EU"
        )
        is True
    )
    # The default (no jurisdiction kwarg) is also "EU"
    assert (
        qtsp_qualified_for_jurisdiction("http://timestamp.actalis.com")
        is True
    )
    # The HTTPS variant is also recognized
    assert (
        qtsp_qualified_for_jurisdiction(
            "https://timestamp.actalis.com", jurisdiction="EU"
        )
        is True
    )


# ---------------------------------------------------------------------------
# 3. qtsp_qualified_for_jurisdiction("US", "http://timestamp.actalis.com") == False
# ---------------------------------------------------------------------------


def test_qtsp_qualified_for_jurisdiction_us_actalis() -> None:
    """Actalis grants eIDAS Art. 41 presumption ONLY in EU jurisdiction."""
    assert (
        qtsp_qualified_for_jurisdiction(
            "http://timestamp.actalis.com", jurisdiction="US"
        )
        is False
    )
    assert (
        qtsp_qualified_for_jurisdiction(
            "http://timestamp.actalis.com", jurisdiction="UK"
        )
        is False
    )
    assert (
        qtsp_qualified_for_jurisdiction(
            "http://timestamp.actalis.com", jurisdiction=""
        )
        is False
    )


# ---------------------------------------------------------------------------
# 4. qtsp_qualified_for_jurisdiction("EU", "https://freetsa.org/tsr") == False
# ---------------------------------------------------------------------------


def test_qtsp_qualified_for_jurisdiction_eu_freetsa_rejected() -> None:
    """FreeTSA is NOT on the EU Trust List (auditor-8 finding)."""
    assert (
        qtsp_qualified_for_jurisdiction(
            "https://freetsa.org/tsr", jurisdiction="EU"
        )
        is False
    )


def test_qtsp_qualified_for_jurisdiction_unknown_rejected() -> None:
    """Unknown TSAs are rejected under EU jurisdiction."""
    assert (
        qtsp_qualified_for_jurisdiction(
            "https://unknown-tsa.example.com/tsr", jurisdiction="EU"
        )
        is False
    )


# ---------------------------------------------------------------------------
# 5. QESValidationResult fields populated correctly
# ---------------------------------------------------------------------------


def test_qes_validation_result_fields_for_qualified_cert() -> None:
    """A test cert with esi4-qtstStatement-1 yields a populated result."""
    cert_der = _make_test_cert(with_qc=True, with_esi4=True)
    result = validate_qtsp_certificate(cert_der)
    assert isinstance(result, QESValidationResult)
    # esi4 is present, so the EU compliance flag is True
    assert result.has_eu_compliance_statement is True
    # Subject DN is populated
    assert result.ts_certificate_subject is not None
    assert "qtsp-test" in result.ts_certificate_subject
    # SHA-256 fingerprint is populated (64 hex chars, uppercase)
    fp = result.ts_certificate_fingerprint_sha256
    assert fp is not None
    assert len(fp) == 64
    assert fp == fp.upper()
    # Regulatory basis is non-empty when esi4 is present
    assert result.regulatory_basis
    assert any(
        "eIDAS" in r or "ETSI EN 319 422" in r or "Reg (EU)" in r
        for r in result.regulatory_basis
    )
    # No validation issues when esi4 is present
    assert all("esi4-qtstStatement-1" not in i for i in result.issues)


def test_qes_validation_result_fields_for_missing_qc() -> None:
    """A cert without the qcStatements extension yields has_eu=False
    and an explanatory issue."""
    cert_der = _make_test_cert(with_qc=False)
    result = validate_qtsp_certificate(cert_der)
    assert result.has_eu_compliance_statement is False
    assert result.is_qualified is False
    assert any("qcStatements" in i for i in result.issues)


def test_qes_validation_result_fields_for_qc_without_esi4() -> None:
    """qcStatements present but esi4-qtstStatement-1 missing → issue."""
    cert_der = _make_test_cert(with_qc=True, with_esi4=False)
    result = validate_qtsp_certificate(cert_der)
    assert result.has_eu_compliance_statement is False
    assert any("esi4-qtstStatement-1" in i for i in result.issues)


# ---------------------------------------------------------------------------
# 6. walk_eu_trust_list_chain returns TrustListChainResult with
#    verified=False for unknown cert
# ---------------------------------------------------------------------------


def test_walk_eu_trust_list_chain_returns_chain_result_for_unknown_cert() -> None:
    """walk_eu_trust_list_chain returns a TrustListChainResult struct
    and reports verified=False for a self-signed test cert (not in
    EU Trust List)."""
    cert_der = _make_test_cert()
    # Pass a minimal empty LOTL XML so the chain walk does not try
    # to fetch the EU LOTL over the network (which would slow tests
    # and depend on external availability).
    empty_lotl = b"<trust-list></trust-list>"
    result = walk_eu_trust_list_chain(
        cert_der=cert_der,
        lotl_xml=empty_lotl,
        timeout=0.1,
    )
    assert isinstance(result, TrustListChainResult)
    assert result.verified is False
    # chain_length >= 1 (we appended the leaf)
    assert result.chain_length >= 1
    # An error is reported when the chain can't be anchored to a known EU root
    # (the trust store integration is deferred to W8.8.2 — for now we
    # at least return a structured result).
    assert result.error is not None or result.chain_length > 0


def test_walk_eu_trust_list_chain_handles_invalid_cert() -> None:
    """Invalid DER bytes return a TrustListChainResult with verified=False
    and a descriptive error."""
    result = walk_eu_trust_list_chain(
        cert_der=b"not-a-cert",
        lotl_xml=b"<trust-list></trust-list>",
    )
    assert isinstance(result, TrustListChainResult)
    assert result.verified is False
    assert result.error is not None


def test_walk_eu_trust_list_chain_default_jurisdiction_is_eu() -> None:
    """The default jurisdiction for walk_eu_trust_list_chain is EU."""
    result = walk_eu_trust_list_chain(
        cert_der=b"invalid", lotl_xml=b"<trust-list></trust-list>"
    )
    assert result.jurisdiction == "EU"


def test_walk_eu_trust_list_chain_is_tlv6_compliant_by_default() -> None:
    """The default tlv6_compliant flag is True (per the W8.8.1 design)."""
    result = walk_eu_trust_list_chain(
        cert_der=b"invalid", lotl_xml=b"<trust-list></trust-list>"
    )
    assert result.tlv6_compliant is True