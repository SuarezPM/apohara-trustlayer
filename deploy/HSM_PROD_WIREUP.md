# P5.3 — HSM Production Wire-Up (AWS KMS / Thales Luna)

Companion to `tests/test_hsm_signing.py`. The control plane's COSE_Sign1
envelope algorithm (`alg` field in the protected header) is driven by
`signer.algorithm()`. This doc covers production wire-up of the two
real HSM adapters — `AWSKmsMLDSASigner` (AWS KMS, FIPS 140-3 L3) and
`ThalesLunaPqcSigner` (on-prem HSM, FIPS 140-3 L3 + PQC). The default
`EphemeralEd25519Signer` is **dev-only** (per auditor finding 8) and
must be replaced before any production notarization.

## Algorithm registry

| Algorithm  | IANA COSE alg | Key size | Sig size | Use case |
|------------|---------------|----------|----------|----------|
| EdDSA      | `-8` (`EdDSA`)| 32 B     | 64 B     | Dev only (per audit-8). |
| ML-DSA-44  | `-48`         | 1312 B   | 2420 B   | Small payloads, constrained devices. |
| ML-DSA-65  | `-49` (`ML-DSA-65`) | 1952 B | 3309 B | **Default for production** (Plan v1.2 IC-8). |
| ML-DSA-87  | `-50`         | 2592 B   | 4627 B   | High-assurance (NIST FIPS 204 max security). |

The signer.algorithm() string is what populates the COSE_Sign1
protected header `alg` field. Verifiers (tl-verify on the Rust side)
read this field and dispatch to the matching verification path.

## AWS KMS ML-DSA wire-up

### 1. Provision the KMS key

```bash
# AWS supports ML-DSA in KMS since June 2025 in us-west-1 / eu-south-1.
aws kms create-key \
    --description "TrustLayer notary signing key" \
    --key-spec ML_DSA_65 \
    --key-usage SIGN_VERIFY \
    --region eu-south-1

# Capture the KeyId (KeyMetadata.KeyId, e.g.
#   "1234abcd-12ab-34cd-56ef-1234567890ab").
```

### 2. IAM policy

The IAM principal the control plane runs as needs:

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "TrustLayerSign",
        "Effect": "Allow",
        "Action": [
            "kms:Sign",
            "kms:GetPublicKey",
            "kms:DescribeKey"
        ],
        "Resource": "arn:aws:kms:eu-south-1:<account>:key/<key-id>"
    }]
}
```

Note: `kms:Sign` is the only mutating permission — `Sign` on ML-DSA
keys is a NIST-approved signing operation (not a generic encrypt).

### 3. Install boto3 + configure the control plane

```bash
# 1. Add boto3 to the deployment image.
pip install 'boto3[crt]>=1.34'

# 2. Configure env vars (the control plane reads these at startup).
export TL_AWS_KMS_KEY_ID="arn:aws:kms:eu-south-1:<account>:key/<key-id>"
export AWS_REGION="eu-south-1"
# Standard AWS credential chain: env vars, ~/.aws/credentials, IMDS, etc.
```

The control plane's `hsm_adapter.get_signer()` factory will select
`AWSKmsMLDSASigner` because `TL_AWS_KMS_KEY_ID` is set. The signer:

1. Calls `boto3.client("kms").get_public_key(KeyId=...)` once at
   construction to derive the `mldsa65:<sha256-prefix>` fingerprint.
2. Per `sign()` call, computes `μ = SHAKE256(public_key || payload, 64)`
   per NIST FIPS 204 §6.2, then calls `kms.sign(KeyId, SigningAlgorithm:
   ML_DSA_SHAKE_256, MessageType: RAW, Message=μ)`.

The 4 KB message cap of `MessageType: RAW` is met by sending only the
64-byte μ (the pre-hashed Sig_structure from RFC 9052 §4.4).

## Thales Luna PQC wire-up

### 1. Provision the HSM module

```bash
# 1. Install the PKCS#11 driver and module.
# See Thales 2026 Q1 product brief for the .so path on your platform.

# 2. Initialize the slot + load the key (one-time).
pkcs11-tool --module /usr/lib/Thales/pqc/libthales_pqc.so \
    --init-token --label "trustlayer-slot" --pin 1234
pkcs11-tool --module /usr/lib/Thales/pqc/libthales_pqc.so \
    --keypair-gen --key-type CKM_ML_DSA_65 --label "trustlayer-mldsa65"

# 3. Verify the key fingerprint (used in the cert's
# `primary_key_fingerprint` column).
pkcs11-tool --module /usr/lib/Thales/pqc/libthales_pqc.so \
    --list-objects --type pubkey
```

### 2. Configure the control plane

```bash
export TL_THALES_PKCS11_MODULE="/usr/lib/Thales/pqc/libthales_pqc.so"
export TL_THALES_PKCS11_SLOT="0"
export TL_THALES_PKCS11_PIN="1234"
export TL_THALES_KEY_LABEL="trustlayer-mldsa65"
```

The control plane's `hsm_adapter.get_signer()` factory will select
`ThalesLunaPqcSigner` (or `AWSKmsMLDSASigner` if `TL_PREFER_AWS=1` is
also set — precedence is controlled by `TL_PREFER_AWS` /
`TL_PREFER_THALES`). The signer:

1. Loads the .so via `dlopen` once at construction.
2. Per `sign()` call, computes μ and calls
   `C_SignInit(CKM_ML_DSA_65, ...)` + `C_Sign(...)`.

## Selection precedence

| `TL_AWS_KMS_KEY_ID` | `TL_THALES_PKCS11_MODULE` | Result |
|---------------------|---------------------------|--------|
| unset              | unset                    | `EphemeralEd25519Signer` (dev only — **not for production**). |
| set                | (any)                    | `AWSKmsMLDSASigner` (if `TL_PREFER_AWS=1`, default). |
| unset              | set                      | `ThalesLunaPqcSigner`. |
| set                | set                      | `TL_PREFER_AWS=1` → AWS, else `TL_PREFER_THALES=1` → Thales, else error at startup. |

The selection happens at startup — `get_signer()` is called once by
`main.py` lifespan, and the result is stored in `app.state.signer`.
A misconfiguration produces an immediate startup error (the HSM adapter
raises `ValueError` if the env vars point at invalid resources).

## Verifying the wire-up

The `test_hsm_signing.py` test suite (9 tests) verifies the contract
end-to-end without touching real HSM hardware:

```bash
PYTHONPATH=services/control_plane \
    uv run --no-project --with pytest --with cryptography \
            --with 'pydantic[email]' --with pydantic-settings \
            --with sqlalchemy --with asyncpg --with structlog \
            --with pyjwt --with fastapi --with uvicorn --with httpx \
    python -m pytest tests/test_hsm_signing.py -v
```

The critical assertion: `protected_header["alg"]` in the COSE_Sign1
envelope equals `signer.algorithm()` — verified for all 4 algorithms
(EdDSA, ML-DSA-44, ML-DSA-65, ML-DSA-87). When production swaps
`EphemeralEd25519Signer` for `AWSKmsMLDSASigner`, the wire format's
`alg` field automatically reads `ML-DSA-65` without touching
`_cose_sign1` in `notary/service.py`.

## Key rotation

Both adapters support the same rotation pattern (the production
target is quarterly rotation per Plan v1.2 IC-8):

1. Provision a new KMS key (or Thales keypair) with the same `KeySpec`.
2. Set `TL_AWS_KMS_KEY_ID` (or `TL_THALES_KEY_LABEL`) to the new
   identifier.
3. Restart the control plane — the new signer's fingerprint flows
   through to all new certificates.
4. Old certificates remain verifiable because the public key is
   persisted in each certificate's `cwt_claims` (the verifier can
   resolve the key from the issuer + kid header).

For emergency rotation (compromised key), invalidate the old key in
KMS + revoke at the Thales level. The control plane logs an alert
when it detects a `kms:Sign` failure.

## Compliance notes

- **EU AI Act Art. 12**: HSM-backed signatures are tamper-evident
  (NIST FIPS 140-3 Level 3 for both adapters). The control plane's
  `primary_key_fingerprint` column + `cwt_claims` chain provide
  non-repudiation for every notarization.
- **DORA Art. 17**: HSM key management policies are auditable via
  AWS CloudTrail (KMS) or Thales HSM audit logs.
- **FIPS 204**: ML-DSA-65 is NIST-approved (August 2024 final).
  Auditors must verify the `alg` field reads `ML-DSA-65` (per the
  `test_cose_sign1_protected_header_uses_signer_algorithm` test) and
  that the `primary_key_fingerprint` resolves to a key bound to a
  certified HSM partition.

## References

- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- AWS KMS ML-DSA: https://docs.aws.amazon.com/kms/latest/developerguide/mldsa.html
- Thales 2026 Q1 product brief (PQC HSM modules)
- RFC 9052 (CBOR Object Signing and Encryption): https://www.rfc-editor.org/rfc/rfc9052
- Plan v1.2 IC-8: HSM signing key management policy
