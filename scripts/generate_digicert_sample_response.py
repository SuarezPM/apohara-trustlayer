#!/usr/bin/env python3
"""
Generate a synthetic TimeStampResp signed with ECDSA P-256.

Per Plan v1.x v1.1.0.x+1+2-US-1 (auditor's fixed plan):
- USE Python `cryptography` library (NOT pyasn1) + `asn1crypto` for high-level CMS types
- USE ECDSA P-256 + SHA-256 (NOT Ed25519)
- signedAttrs IMPLICIT [0] ↔ SET tag swap per RFC 5652 §5.4
- ESS SigningCertificateV2 attribute per RFC 5816 §3 (openssl ts -verify REQUIRES this)
- SignedData version v3 (because we include X.509 certs per RFC 5652 §5.1)
- Output: audit_artifacts/test_fixtures/digicert/sample-response.der
- Exit criterion: `openssl ts -verify -token_in` returns "Verification: OK"

Per RFC 5816, ESSCertIDv2 (with explicit hash_alg) is used instead of ESSCertID
(which openssl hardcodes to SHA-1). This is the only way to get openssl ts -verify
to accept the fixture.

Run from repo root:
    uv run --with cryptography --with asn1crypto python3 scripts/generate_digicert_sample_response.py
"""
from __future__ import annotations

import datetime
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as crypto_utils
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from asn1crypto import cms, tsp, x509 as a1_x509
from asn1crypto.algos import DigestAlgorithm

REPO_ROOT = Path(__file__).resolve().parent.parent
DIGICERT_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "digicert"
OUTPUT = DIGICERT_DIR / "sample-response.der"
TOKEN_OUTPUT = DIGICERT_DIR / "token.der"
CHAIN_OUTPUT = DIGICERT_DIR / "chain.pem"

# OIDs (RFC 5652 + RFC 5816)
ID_SIGNED_DATA = "1.2.840.113549.1.7.2"
ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4"
ID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
ID_AA_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"


def build_root_ca_cert() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Build a self-signed root CA cert with ECDSA P-256.

    Returns (cert, private_key). The cert has CA:TRUE (basicConstraints).
    The TSA cert (build_tsa_cert) is signed by this root CA; chain.pem
    contains BOTH the TSA cert and the root CA cert.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Apohara TrustLayer (test)"),
        x509.NameAttribute(NameOID.COMMON_NAME, "TrustLayer Test Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert, private_key


def build_tsa_cert(ca_cert, ca_key) -> tuple[bytes, ec.EllipticCurvePrivateKey]:
    """Build a TSA cert signed by the given CA cert/key.

    Returns (cert_der, tsa_private_key). The cert carries the
    `id-kp-timeStamping` ExtendedKeyUsage (RFC 3161) and
    basicConstraints=CA:FALSE (a TSA cert is not itself a CA).
    """
    tsa_private_key = ec.generate_private_key(ec.SECP256R1())
    tsa_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "TrustLayer Test TSA"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(tsa_private_key.public_key())
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
        .sign(ca_key, hashes.SHA256())
    )
    return tsa_cert.public_bytes(serialization.Encoding.DER), tsa_private_key


def build_test_cert(private_key) -> bytes:
    """Backwards-compatible wrapper: builds a self-signed TSA cert.

    Prefer build_root_ca_cert + build_tsa_cert for new code.
    """
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
    return cert.public_bytes(serialization.Encoding.DER)


def build_ess_signing_cert_v2(cert_obj: a1_x509.Certificate) -> tsp.SigningCertificateV2:
    """Build ESS SigningCertificateV2 attribute (RFC 5816 §3).

    openssl ts -verify REQUIRES this attribute (per OSSL_ESS_check_signing_certs).
    We use ESSCertIDv2 (not ESSCertID) because openssl hardcodes ESSCertID to SHA-1.
    ESSCertIDv2 carries an explicit hash_alg so we use SHA-256.
    """
    import hashlib
    cert_der = cert_obj.dump()
    cert_hash = hashlib.sha256(cert_der).digest()

    # IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
    # GeneralNames is SEQUENCE OF GeneralName (CHOICE); use directoryName [4] IMPLICIT Name
    issuer_name = a1_x509.Name.load(cert_obj.subject.dump())
    general_names = a1_x509.GeneralNames([
        a1_x509.GeneralName({'directory_name': issuer_name}),
    ])

    issuer_serial = tsp.IssuerSerial({
        'issuer': general_names,
        'serial_number': int(cert_obj.serial_number),
    })

    # ESSCertIDv2 ::= SEQUENCE {
    #     hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
    #     certHash OCTET STRING,
    #     issuerSerial IssuerSerial OPTIONAL
    # }
    ess_cert_id = tsp.ESSCertIDv2({
        'hash_algorithm': {'algorithm': 'sha256'},
        'cert_hash': cert_hash,
        'issuer_serial': issuer_serial,
    })

    return tsp.SigningCertificateV2({'certs': [ess_cert_id]})


def build_tst_info(message_digest: bytes, gen_time: datetime.datetime) -> tsp.TSTInfo:
    """TSTInfo using asn1crypto's high-level tsp.TSTInfo class."""
    return tsp.TSTInfo({
        'version': 'v1',
        'policy': '1.2.3.4.5',
        'message_imprint': {
            'hash_algorithm': {'algorithm': 'sha256'},
            'hashed_message': message_digest,
        },
        'serial_number': 1,
        'gen_time': gen_time,
    })


def build_time_stamp_resp(
    tst: tsp.TSTInfo,
    cert_der: bytes,
    cert_obj: a1_x509.Certificate,
    private_key,
) -> tuple[bytes, bytes]:
    """Build a complete TimeStampResp per RFC 3161 + RFC 5652 + RFC 5816.

    Returns (TimeStampResp DER, ContentInfo DER). ContentInfo is what
    `openssl ts -verify -token_in` expects as input.
    """
    # RFC 5652 §5.1: encapContentInfo ::= SEQUENCE {
    #     eContentType ContentType,
    #     eContent [0] EXPLICIT OCTET STRING OPTIONAL
    # }
    # asn1crypto's EncapsulatedContentInfo wraps the content in OCTET STRING inside [0] EXPLICIT.
    encap = cms.EncapsulatedContentInfo({
        'content_type': ID_CT_TST_INFO,
        'content': tst,  # parsed TSTInfo, not DER bytes
    })

    # ESS SigningCertificateV2 (RFC 5816 §3) — REQUIRED by openssl ts -verify
    signing_cert_v2 = build_ess_signing_cert_v2(cert_obj)

    # RFC 5652 §5.4: signedAttrs are hashed for the signature.
    # Per asn1crypto internals: signed_attrs.dump() emits SET tag (0x31), NOT [0] IMPLICIT.
    # The [0] IMPLICIT tag is applied only when embedding in SignerInfo.
    # This is the correct behavior per RFC 5652 §5.4 ("SET OF tag used").
    tst_info_der = tst.dump()
    message_digest_attr = hashlib.sha256(tst_info_der).digest()

    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            'type': ID_CONTENT_TYPE,
            'values': [cms.ContentType(ID_CT_TST_INFO)],
        }),
        cms.CMSAttribute({
            'type': ID_MESSAGE_DIGEST,
            'values': [cms.OctetString(message_digest_attr)],
        }),
        cms.CMSAttribute({
            'type': ID_AA_SIGNING_CERTIFICATE_V2,
            'values': [signing_cert_v2],
        }),
    ])

    # ECDSA per RFC 5754 §3.2: compute SHA-256 over signed_attrs_der, sign with ECDSA.
    signed_attrs_der = signed_attrs.dump()
    sha256 = hashes.Hash(hashes.SHA256())
    sha256.update(signed_attrs_der)
    digest = sha256.finalize()
    signature = private_key.sign(
        digest,
        ec.ECDSA(crypto_utils.Prehashed(hashes.SHA256())),
    )

    signer_info = cms.SignerInfo({
        'version': 'v1',
        'sid': cms.IssuerAndSerialNumber({
            'issuer': cert_obj.subject,
            'serial_number': cert_obj.serial_number,
        }),
        'digest_algorithm': {'algorithm': 'sha256'},
        'signed_attrs': signed_attrs,
        'signature_algorithm': {'algorithm': 'sha256_ecdsa'},
        'signature': signature,
    })

    # SignedData version v3 because X.509 certs are present (RFC 5652 §5.1)
    sd = cms.SignedData({
        'version': 'v3',
        'digest_algorithms': cms.DigestAlgorithms([
            DigestAlgorithm({'algorithm': 'sha256'}),
        ]),
        'encap_content_info': encap,
        'certificates': cms.CertificateSet([cert_obj]),  # CertificateSet, not Certificates
        'signer_infos': cms.SignerInfos([signer_info]),
    })

    ci = cms.ContentInfo({
        'content_type': ID_SIGNED_DATA,
        'content': sd,
    })
    ci_der = ci.dump()

    ts_resp = tsp.TimeStampResp({
        'status': tsp.PKIStatusInfo({'status': tsp.PKIStatus('granted')}),
        'time_stamp_token': ci,
    })
    return ts_resp.dump(), ci_der


def main() -> int:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # 1. Generate ECDSA P-256 keypair.
    private_key = ec.generate_private_key(ec.SECP256R1())

    # 2. Build the test cert (self-signed, TimeStamping EKU). We use
    # a self-signed TSA cert here because openssl 3.6.3 has a known
    # parsing issue with multi-cert chains in CMS (PKCS7_get0_signers
    # fails when the chain has more than one cert + the cert is also
    # embedded in the CMS). The Rust verifier (cryptographic-message-syntax)
    # handles multi-cert chains correctly; only openssl ts -verify is
    # affected. Production uses DigiCert's actual chain in v1.1+; this
    # fixture is for unit tests only.
    cert_der = build_test_cert(private_key)
    cert_obj = a1_x509.Certificate.load(cert_der)

    # 3. Build the TSTInfo
    data_bytes = b"trustlayer-v1.1.0.x+1+2"
    message_digest = hashlib.sha256(data_bytes).digest()
    gen_time = datetime.datetime(2026, 6, 25, 15, 0, 0, tzinfo=datetime.timezone.utc)
    tst = build_tst_info(message_digest, gen_time)

    # 4. Build the TimeStampResp
    ts_resp_der, ci_der = build_time_stamp_resp(tst, cert_der, cert_obj, private_key)

    # 5. Write outputs
    OUTPUT.write_bytes(ts_resp_der)
    TOKEN_OUTPUT.write_bytes(ci_der)
    # Re-serialize the cert to PEM using cryptography's load_der_x509_certificate API
    from cryptography.x509 import load_der_x509_certificate
    cert_obj_crypto = load_der_x509_certificate(cert_der)
    cert_pem = cert_obj_crypto.public_bytes(serialization.Encoding.PEM)
    CHAIN_OUTPUT.write_bytes(cert_pem)

    print(f"Wrote {OUTPUT} ({len(ts_resp_der)} bytes)")
    print(f"Wrote {TOKEN_OUTPUT} ({len(ci_der)} bytes)")
    print(f"Wrote {CHAIN_OUTPUT}")
    print(f"messageImprint.hashedMessage = {message_digest.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
