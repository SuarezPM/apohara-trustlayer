#!/usr/bin/env python3
"""
Generate a synthetic TimeStampResp signed with ECDSA P-256.

Per Plan v1.x v1.1.0.x+1+2-US-1 (auditor's fixed plan):
- USE Python `cryptography` library (NOT pyasn1) + `asn1crypto` for high-level CMS types
- USE ECDSA P-256 + SHA-256 (NOT Ed25519)
- signedAttrs IMPLICIT [0] ↔ SET tag swap per RFC 5652 §5.4
- Output: audit_artifacts/test_fixtures/digicert/sample-response.der
- Exit criterion: `openssl ts -verify` returns "Verification: OK"

This version uses asn1crypto for the high-level CMS/SignedData structure
(which has the correct CHOICE/IMPLICIT/EXPLICIT tag handling built in)
and cryptography for the cert + signature primitives.

Run from repo root:
    uv run --with cryptography --with asn1crypto python3 scripts/generate_digicert_sample_response.py
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from asn1crypto import cms, tsp, x509 as a1_x509, core
from asn1crypto.algos import DigestAlgorithm

REPO_ROOT = Path(__file__).resolve().parent.parent
DIGICERT_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "digicert"
OUTPUT = DIGICERT_DIR / "sample-response.der"

# OIDs
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ID_SHA256 = "2.16.840.1.101.3.4.2.1"
ID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"


def build_test_cert(private_key) -> bytes:
    """Build a self-signed X.509 cert with TimeStamping EKU + EC public key."""
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "TrustLayer Test TSA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def build_tst_info(message_digest: bytes, gen_time: datetime.datetime) -> bytes:
    """TSTInfo using asn1crypto's high-level tsp.TSTInfo class."""
    tst = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.5",
        "message_imprint": {
            "hash_algorithm": {
                "algorithm": "sha256",
            },
            "hashed_message": message_digest,
        },
        "serial_number": 1,
        "gen_time": gen_time,
    })
    return tst.dump()


def build_signed_data(
    tst_info_der: bytes,
    cert_der: bytes,
    private_key,
) -> bytes:
    """Build CMS SignedData using asn1crypto's high-level cms.SignedData."""
    # The eContent is the DER-encoded TSTInfo wrapped in an OCTET STRING.
    # Per RFC 5652 §5.1, encapContentInfo ::= SEQUENCE {
    #   eContentType OID,
    #   eContent [0] EXPLICIT OCTET STRING
    # }
    encap = cms.EncapsulatedContentInfo({
        "content_type": ID_CT_TST_INFO,
        "content": tst_info_der,
    })

    digest_algorithm = {
        "algorithm": "sha256",
    }

    # Build the cert structure
    cert_obj = a1_x509.Certificate.load(cert_der)

    # Compute the message digest that will be in the signedAttrs
    # Per RFC 5652 §5.4: digest is over the eContent OCTET STRING value
    # (the tst_info_der itself)
    message_digest = hashlib.sha256(tst_info_der).digest()

    # Build signedAttrs (SET OF Attribute) — DER encoded with SET tag
    # (not IMPLICIT [0]) for digest calculation per RFC 5652 §5.4
    # The IMPLICIT [0] tag is applied at the SignerInfo level when
    # embedding the signedAttrs into the SignerInfo.
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": ID_CONTENT_TYPE,
            "values": cms.CMSAttributeValues([
                cms.ContentType(ID_CT_TST_INFO),
            ]),
        }),
        cms.CMSAttribute({
            "type": ID_MESSAGE_DIGEST,
            "values": cms.CMSAttributeValues([
                cms.OctetString(message_digest),
            ]),
        }),
    ])

    # Sign the signedAttrs (DER encoded with SET tag, not IMPLICIT [0])
    signed_attrs_der = signed_attrs.dump()
    signature = private_key.sign(
        signed_attrs_der,
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )

    # Build the SignerInfo using asn1crypto
    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.IssuerAndSerialNumber({
            "issuer": cert_obj.subject,
            "serial_number": cert_obj.serial_number,
        }),
        "digest_algorithm": digest_algorithm,
        "signed_attrs": signed_attrs,
        "signature_algorithm": {
            "algorithm": "ecdsa_with_sha256",
        },
        "signature": signature,
    })

    # Build SignedData
    sd = cms.SignedData({
        "version": "v1",
        "digest_algorithms": cms.DigestAlgorithms([
            DigestAlgorithm({"algorithm": "sha256"}),
        ]),
        "encap_content_info": encap,
        "certificates": cms.Certificates([
            cert_obj,
        ]),
        "signer_infos": cms.SignerInfos([signer_info]),
    })
    return sd.dump()


def build_content_info(signed_data_der: bytes) -> bytes:
    """ContentInfo using asn1crypto's high-level cms.ContentInfo."""
    sd = cms.SignedData.load(signed_data_der)
    ci = cms.ContentInfo({
        "content_type": ID_SIGNED_DATA,
        "content": sd,
    })
    return ci.dump()


def build_ts_resp(content_info_der: bytes) -> bytes:
    """TimeStampResp using asn1crypto's high-level tsp.TimeStampResp."""
    ci = cms.ContentInfo.load(content_info_der)
    pki_status = tsp.PKIStatusInfo({
        "status": tsp.PKIStatus("granted"),
    })
    ts_resp = tsp.TimeStampResp({
        "status": pki_status,
        "time_stamp_token": ci,
    })
    return ts_resp.dump()


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # 1. Generate ECDSA P-256 keypair
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # 2. Build the test cert
    cert_der = build_test_cert(private_key)

    # 3. Build the TSTInfo
    data_bytes = b"trustlayer-v1.1.0.x+1+2"
    message_digest = hashlib.sha256(data_bytes).digest()
    gen_time = datetime.datetime(2026, 6, 25, 15, 0, 0, tzinfo=datetime.timezone.utc)
    tst_info_der = build_tst_info(message_digest, gen_time)

    # 4. Build the SignedData (using asn1crypto for correct ASN.1)
    signed_data_der = build_signed_data(tst_info_der, cert_der, private_key)

    # 5. Build the ContentInfo
    content_info_der = build_content_info(signed_data_der)

    # 6. Build the TimeStampResp
    ts_resp_der = build_ts_resp(content_info_der)

    # Write
    OUTPUT.write_bytes(ts_resp_der)
    print(f"Wrote {OUTPUT} ({len(ts_resp_der)} bytes)")
    print(f"messageImprint.hashedMessage = {message_digest.hex()}")
    print(f"public_key = {public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
