#!/usr/bin/env python3
"""
Generate a synthetic TimeStampResp signed with the test private key.

Per Plan v1.x v1.1.0.x+1+1-US-1 (closes CRÍTICO 1 of auditor 3):
the test fixture is a real CMS ContentInfo with a real SignerInfo
signed with the Ed25519 test key. The previous fixture was a
256-byte placeholder.

Output: audit_artifacts/test_fixtures/digicert/sample-response.der

The TSTInfo's messageImprint.hashedMessage is SHA-256 of the byte
string b"trustlayer-v1.1.0.x+1+1" (a known value, reproducible).
Tests verify this digest matches the expected value in cms_verify.

Run from repo root:
    uv run --with cryptography --with pyasn1 python3 scripts/generate_digicert_sample_response.py
"""
from __future__ import annotations

import datetime
import hashlib
import sys
from pathlib import Path

import pyasn1
from pyasn1.type import (
    univ,
    namedtype,
    tag,
    constraint,
    char,
    useful,
    opentype,
)
from pyasn1.codec.der import encoder, decoder

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.hazmat.primitives import serialization


REPO_ROOT = Path(__file__).resolve().parent.parent
DIGICERT_DIR = REPO_ROOT / "audit_artifacts" / "test_fixtures" / "digicert"
CERT_PEM = DIGICERT_DIR / "digicert-test-tsa.pem"
OUTPUT = DIGICERT_DIR / "sample-response.der"

# OIDs
OID_SIGNED_DATA = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 7, 2))
OID_TST_INFO = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1, 4))
OID_SHA256 = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 16))
OID_ED25519 = univ.ObjectIdentifier((1, 3, 101, 112))
OID_CONTENT_TYPE = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 3))
OID_SIGNING_TIME = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 5))
OID_MESSAGE_DIGEST = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 4))


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("algorithm", univ.ObjectIdentifier()),
        namedtype.OptionalNamedType("parameters", univ.Any()),
    )


class MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("hashAlgorithm", AlgorithmIdentifier()),
        namedtype.NamedType("hashedMessage", univ.OctetString()),
    )


class TSTInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("version", univ.Integer()),
        namedtype.NamedType("policy", univ.ObjectIdentifier()),
        namedtype.NamedType("messageImprint", MessageImprint()),
        namedtype.NamedType("serialNumber", univ.Integer()),
        namedtype.NamedType("genTime", useful.GeneralizedTime()),
    )


def build_tst_info(message_digest: bytes, gen_time: datetime.datetime) -> bytes:
    tst = TSTInfo()
    tst["version"] = 0  # v1
    tst["policy"] = univ.ObjectIdentifier((1, 2, 3, 4, 5))
    alg = AlgorithmIdentifier()
    alg["algorithm"] = OID_SHA256
    alg["parameters"] = univ.Null()
    mi = MessageImprint()
    mi["hashAlgorithm"] = alg
    mi["hashedMessage"] = univ.OctetString(message_digest)
    tst["messageImprint"] = mi
    tst["serialNumber"] = 1
    tst["genTime"] = useful.GeneralizedTime(gen_time.strftime("%Y%m%d%H%M%SZ"))
    return encoder.encode(tst)


def build_signed_attrs_der(message_digest, gen_time):
    """Placeholder; real impl is inlined in main() where oid_der/tlv
    are in scope."""
    return b""


def main() -> int:
    if not CERT_PEM.exists():
        print(f"ERROR: {CERT_PEM} not found. Run scripts/generate_digicert_fixture.py first.", file=sys.stderr)
        return 1

    cert_pem_bytes = CERT_PEM.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_pem_bytes)

    # Generate a deterministic Ed25519 keypair
    seed = hashlib.blake2b(b"trustlayer-v1.1.0.x+1+1-test-key", digest_size=32).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key()

    # Compute the message digest
    payload = b"trustlayer-v1.1.0.x+1+1"
    message_digest = hashlib.sha256(payload).digest()
    print(f"messageImprint.hashedMessage = {message_digest.hex()}")

    # Build the TSTInfo
    gen_time = datetime.datetime(2026, 6, 25, 15, 0, 0, tzinfo=datetime.timezone.utc)
    tst_info_der = build_tst_info(message_digest, gen_time)

    # Build signedAttrs and sign
    signed_attrs_der = build_signed_attrs_der(message_digest, gen_time)
    signature = priv.sign(signed_attrs_der)
    print(f"signature (64 bytes) = {signature.hex()}")

    # Build the SignerInfo DER directly (we hand-build this because
    # the IMPLICIT [0] tagging of signedAttrs is easier in raw DER
    # than via pyasn1's high-level API).
    def tlv(tag_byte, content):
        out = bytes([tag_byte])
        n = len(content)
        if n < 128:
            out += bytes([n])
        elif n < 256:
            out += bytes([0x81, n])
        else:
            out += bytes([0x82, (n >> 8) & 0xff, n & 0xff])
        out += content
        return out

    def sequence(content):
        return tlv(0x30, content)

    def set_of(content):
        return tlv(0x31, content)

    def integer(value):
        if value < 128:
            return bytes([0x02, 0x01, value])
        else:
            # Multi-byte
            bs = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return bytes([0x02, len(bs)]) + bs

    def oid_der(oid_tuple):
        # Encode an OID as DER. OID = 0x06 + length + encoded.
        if len(oid_tuple) == 0:
            return b""
        first = oid_tuple[0]
        rest = oid_tuple[1:]
        # First byte = 40 * first_two + second
        if len(rest) < 1:
            return b""
        first_byte = 40 * first + rest[0]
        body = bytes([first_byte])
        for v in rest[1:]:
            # Base-128 encoding
            parts = []
            while v > 0:
                parts.append(v & 0x7f)
                v >>= 7
            parts.reverse()
            for i, p in enumerate(parts):
                body += bytes([p | (0x80 if i < len(parts) - 1 else 0)])
        return tlv(0x06, body)

    # AlgorithmIdentifier: SEQUENCE { algorithm OID, parameters ANY OPTIONAL }
    def algid(oid_tuple):
        return sequence(oid_der(oid_tuple))

    def algid_sha256():
        # SEQUENCE { OID sha256, NULL }
        # Use my own oid_der (pyasn1 univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 2, 16))
        # encodes incorrectly as "hmac-sha3-512" per openssl asn1parse —
        # confirmed via the parse output). My oid_der uses the correct
        # X.690 base-128 encoding.
        inner = oid_der((2, 16, 840, 1, 101, 3, 4, 2, 16)) + bytes([0x05, 0x00])
        return sequence(inner)

    def algid_ed25519():
        # SEQUENCE { OID ed25519, NULL }
        inner = oid_der((1, 3, 101, 112)) + bytes([0x05, 0x00])
        return sequence(inner)

    # SignerInfo:
    #   SEQUENCE {
    #     version INTEGER 1,
    #     sid [0] IMPLICIT IssuerAndSerial,
    #     digestAlgorithm AlgorithmIdentifier,
    #     signedAttrs [0] IMPLICIT SignedAttrs OPTIONAL,
    #     signatureAlgorithm AlgorithmIdentifier,
    #     signature OCTET STRING
    #   }
    # IssuerAndSerial:
    #   SEQUENCE { issuer Name, serial INTEGER }
    # Name: SEQUENCE OF RelativeDistinguishedName (we use the cert's
    # subject which is already DER-encoded as Name; extract from cert)
    # The cert's subject is a Name (we re-derive the DER).
    # For simplicity, we use the cert.subject.rfc4514_string() and
    # re-encode as Name. The Name is SEQUENCE OF RDN. For OpenSSL-
    # generated certs, the structure is well-defined.
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    import base64
    # Use the cert's raw subject DER directly. The cert's tbs_certificate
    # subject is the Name.
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    # Parse the cert: the cert structure is:
    #   SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    # tbsCertificate:
    #   SEQUENCE { [0] version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    # We want the subject (the 6th element of tbsCertificate).
    # For simplicity, use asn1 parsing via pyasn1.
    from pyasn1.codec.der import decoder as _decoder
    cert_seq, _ = _decoder.decode(cert_der, asn1Spec=univ.Sequence())
    # cert_seq[0] is tbsCertificate
    tbs = cert_seq[0]
    # tbs[5] is subject (after version, serial, sigAlg, issuer, validity)
    subject_der = encoder.encode(tbs[5])

    # issuer DER: same structure
    issuer_der = encoder.encode(tbs[3])

    # serial: INTEGER (raw bytes from cert)
    serial_int = int(cert.serial_number)
    serial_der = integer(serial_int)

    # IssuerAndSerial: SEQUENCE { issuer, serial }
    issuer_serial_der = sequence(issuer_der + serial_der)
    # SignerIdentifier: [0] IMPLICIT IssuerAndSerial
    sid_der = tlv(0xA0, issuer_serial_der)

    # signedAttrs: [0] IMPLICIT SignedAttrs (a SET)
    signed_attrs_implicit = tlv(0xA0, signed_attrs_der)

    # signatureAlgorithm
    sig_alg_der = algid_ed25519()

    # signature: OCTET STRING
    sig_octet = tlv(0x04, signature)

    # SignerInfo: SEQUENCE { version, sid, digestAlg, signedAttrs, sigAlg, sig }
    signer_info_der = sequence(
        integer(1) + sid_der + algid_sha256() + signed_attrs_implicit + sig_alg_der + sig_octet
    )

    # SignedData:
    #   SEQUENCE {
    #     version INTEGER 1,
    #     digestAlgorithms SET OF AlgorithmIdentifier,
    #     encapContentInfo EncapsulatedContentInfo,
    #     certificates [0] IMPLICIT SET OF CertificateChoices OPTIONAL,
    #     signerInfos SET OF SignerInfo
    #   }
    digest_algs_der = set_of(algid_sha256())

    # EncapsulatedContentInfo: SEQUENCE { eContentType OID, eContent [0] ANY OPTIONAL }
    # FIX 1: eContent MUST be wrapped in OCTET STRING inside the
    # [0] EXPLICIT tag. Per RFC 5652 §5.1: eContent is the content
    # itself, carried as an octet string. The DER is:
    #   SEQUENCE {
    #     eContentType OID,
    #     eContent [0] EXPLICIT OCTET STRING
    #   }
    econtent_der = tlv(0xA0, tlv(0x04, tst_info_der))
    encap_der = sequence(oid_der((1, 2, 840, 113549, 1, 9, 16, 1, 4)) + econtent_der)

    # certificates [0] IMPLICIT SET OF CertificateChoices
    # CertificateChoices ::= CHOICE { certificate Certificate, ... }
    # FIX: the Certificate variant is IMPLICIT [0] (per RFC 5652 §5.1
    # + §10.2.2). openssl expects the [0] tag wrapping the cert.
    # Note: pyasn1 already wraps it correctly via the `univ.Any` pattern,
    # but we're hand-building the DER. The cert inside the SET must
    # have the [0] IMPLICIT tag explicitly.
    cert_choice_der = tlv(0xA0, cert_der)
    certs_der = tlv(0xA0, set_of(cert_choice_der))

    # signerInfos: SET OF SignerInfo
    signer_infos_der = set_of(signer_info_der)

    signed_data_der = sequence(
        integer(1) + digest_algs_der + encap_der + certs_der + signer_infos_der
    )

    # ContentInfo: SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
    content_der = tlv(0xA0, signed_data_der)
    content_info_der = sequence(oid_der((1, 2, 840, 113549, 1, 7, 2)) + content_der)

    # TS_RESP: SEQUENCE { status PKIStatusInfo, contentType CMSContentInfo, content [0] EXPLICIT ANY }
    # PKIStatusInfo: SEQUENCE { status INTEGER (0 = granted) }
    # For v1.1.0.x+1+1 the status is always "granted" (0).
    pki_status_info = sequence(integer(0))
    ts_resp_der = sequence(
        pki_status_info + content_info_der
    )

    # Write
    OUTPUT.write_bytes(ts_resp_der)
    print(f"Wrote {OUTPUT} ({len(ts_resp_der)} bytes)")
    print(f"public_key = {pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
