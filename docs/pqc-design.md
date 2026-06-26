# TrustLayer PQC (Post-Quantum Cryptography) Design Document

> **Status**: W1.1 design COMPLETE, implementation deferred to W4.1
> **Driver**: EU AI Act Art. 50(2) marking + Attestix v0.4.1 PQC parity
> **Audience**: Future implementer (W4.1, target 2027 Q1) and auditor

## 1. Goal

Per Plan v3.0 W1.1, TrustLayer v3.0 needs **Post-Quantum Cryptography (PQC) hybrid signing** that:

1. Matches Attestix v0.4.1 cryptosuites: `mldsa65-jcs-2026` and `hybrid-ed25519-mldsa65-jcs-2026`
2. Closes the auditor-4 weakness #3 (PQC roadmap gap — TrustLayer was 10 days behind Attestix)
3. Provides **crypto-agility**: rotation from Ed25519 to ML-DSA-65 without re-issuing keys
4. Provides **harvest-now-decrypt-later protection**: evidence bundles signed in 2026 remain verifiable when ML-DSA-65 trust is established in 2027+

## 2. Design decision: Attestix weak-non-separability pattern

After researching IETF composite signatures, NIST SP 800-208, W3C di-quantum-safe v0.3, and Attestix v0.4.1:

**Decision**: Use Attestix v0.4.1's pattern (weak non-separability with `~` separator), NOT IETF LAMPS composite (strong non-separability with SHA-512 prehash).

Rationale:
- Attestix v0.4.1 ships the only production reference (AWS KMS, Google Cloud KMS, Cloudflare are NOT yet doing Ed25519+ML-DSA hybrid)
- The Attestix pattern fits cleanly into TrustLayer's existing COSE_Sign1 envelopes without redesign
- The IETF composite pattern would require changing the wire format of evidence bundles, breaking v2.0 backwards compatibility
- The cryptographic weakness (weak vs strong non-separability) is mitigated by: (a) requiring BOTH signatures to verify (anti-stripping), (b) context binding via FIPS 204 §5.2

## 3. Cryptosuite specifications

### 3.1 `hybrid-ed25519-mldsa65-jcs-2026`

- **Pattern**: Attestix v0.4.1 `attestix/auth/pqc.py`
- **Canonicalization**: JCS RFC 8785 (same as TrustLayer's existing evidence pipeline)
- **Wire format**: `"<ed25519_sig_b64u>~<mldsa65_sig_b64u>"` (tilde separator, base64url, no padding)
- **Verification**: BOTH signatures MUST validate against the identical JCS bytes
- **Context string** (FIPS 204 §5.2): `"trustlayer-v3.0-hybrid-ed25519-mldsa65-jcs-2026"` (max 255 bytes per FIPS 204)
- **Size**: ~4499 chars per proof value (86 for Ed25519 + 1 for `~` + 4412 for ML-DSA-65)

### 3.2 `mldsa65-jcs-2026` (standalone)

- For callers that don't need Ed25519 fallback (e.g., pure post-quantum deployments after 2030)
- Same wire format but no `~` separator (just the ML-DSA-65 signature)
- Context string: `"trustlayer-v3.0-mldsa65-jcs-2026"`

### 3.3 did:key ML-DSA-65 (multicodec 0x1211)

- Multicodec varint `0x1211` encoded as LEB128 unsigned: `bytes([0x91, 0x24])`
- base58btc encoding prefixed with `did:key:z`
- Total identifier length: ~2594 chars for a 1952-byte public key

## 4. Cryptographic primitives

| Primitive | Algorithm | Parameters | Reference |
|-----------|-----------|------------|-----------|
| Classical | Ed25519 | RFC 8032 (already in TrustLayer) | `ed25519-dalek` |
| PQC | ML-DSA-65 | FIPS 204, Cat 3 security level | `ml-dsa = "0.1.1"` (RustCrypto) |
| Hash | SHA-256 | FIPS 180-4 (already in TrustLayer) | `sha2 = "0.10"` |
| Canonicalization | JCS | RFC 8785 | custom impl or `serde_jcs` |
| Multibase | base58btc | multiformats | `bs58 = "0.5"` |

## 5. Key and signature sizes (FIPS 204 §4 Table 1)

| Parameter | Size (bytes) |
|-----------|--------------|
| ML-DSA-65 public key | 1952 |
| ML-DSA-65 private key (expanded) | 4032 |
| ML-DSA-65 signature | 3309 |

## 6. Rust implementation plan (W4.1 deferred)

### 6.1 Crate selection

**Primary**: `ml-dsa = "0.1.1"` (RustCrypto, pure Rust, MSRV 1.85, published 2026-06-05)

| Crate | Version | Decision |
|-------|---------|----------|
| `ml-dsa` (RustCrypto) | 0.1.1 | **PRIMARY** — pure Rust, MSRV 1.85, aligns with RustCrypto ecosystem already used for Ed25519 |
| `fips204` (integritychain) | 0.4.6 | Secondary — older but battle-tested |
| `pqcrypto-mldsa` (rustpq) | 0.1.2 | Avoid — C FFI to PQClean adds native-build burden |
| `oqs` (liboqs-rs) | 0.11.0 | Avoid — requires std, no no_std path, needs cmake + openssl |

### 6.2 API design

```rust
// crates/tl-evidence/src/pqc/mod.rs
pub mod did_key;
pub mod hybrid;
pub mod ml_dsa_65;

// Public re-exports
pub use ml_dsa_65::{
    MlDsa65KeyPair, MlDsa65Signature, MlDsa65VerifyError,
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SECRET_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
pub use hybrid::{
    hybrid_sign, hybrid_verify, HybridSignatureError,
    SUITE_HYBRID, SUITE_MLDSA65, TRUSTLAYER_HYBRID_CONTEXT, TRUSTLAYER_MLDSA65_CONTEXT,
};
pub use did_key::{
    mldsa65_public_key_to_did_key, ML_DSA_65_MULTICODEC_PREFIX,
};
```

### 6.3 Open question (W4.1 implementation blocker)

The ml-dsa 0.1.1 crate uses `generic-array::GenericArray<T, N>` for fixed-size byte arrays (Seed, EncodedVerifyingKey, EncodedSignature). Constructing these from a `&[u8]` slice requires `Array::from_slice` which is awkward in the public API.

**Decision for W1.1**: Defer the implementation to W4.1 (Q1 2027). By then, either:
- ml-dsa stabilizes beyond 0.1.x with a cleaner public API
- An alternative crate (e.g., `fips204` 0.5+) provides a simpler `from_bytes` constructor
- We implement an `oqs-sys` FFI wrapper that bypasses the generic-array complexity entirely

**Interim solution for W1.1**: Document the design + Attestix wire format compatibility. Provide a `pqc_design` module that exposes:
- The cryptosuite name constants (`SUITE_HYBRID`, `SUITE_MLDSA65`)
- The wire format helpers (`format_hybrid_proof(ed_b64, pq_b64) -> String`, `parse_hybrid_proof(s: &str) -> Result<(String, String), Error>`)
- The context string constants (`TRUSTLAYER_HYBRID_CONTEXT`, `TRUSTLAYER_MLDSA65_CONTEXT`)
- The multicodec prefix constant (`ML_DSA_65_MULTICODEC_PREFIX`)

This allows other modules to reference the PQC design without needing the full ml-dsa integration.

## 7. Test plan (W4.1)

When implementation resumes:

1. **Known Answer Tests (KAT)**: NIST CAVP ML-DSA-65 sigVer test vectors (file: `SigVerML-DSA-65.rsp`)
2. **Hybrid roundtrip**: sign 1000 random messages, verify all succeed
3. **Tampering detection**: modify 1 byte in each of {message, signature_ed, signature_pq}, verify ALL fail
4. **Context binding**: verify signature with wrong context fails
5. **did:key roundtrip**: encode/decode 1000 random ML-DSA-65 public keys
6. **Cross-implementation**: sign in Python with `pqcrypto`, verify in Rust (or vice versa)
7. **Performance**: benchmark sign/verify against Ed25519 baseline (expect ~5-10× slowdown for ML-DSA-65)

## 8. Honest limitations to document in disclaimers

Per Plan v3.0 W1.1 + auditor's weak #4:

- The "weak" non-separability is documented in the IETF composite-sigs draft as a known limitation. For "strong" non-separability (cryptographic proof that both signatures are over identical logical message), switch to `draft-ietf-lamps-pq-composite-sigs-19` SHA-512 prehash construction. This is on W4.1 roadmap.
- The `mldsa65-jcs-2026` cryptosuite name is ahead of W3C di-quantum-safe v0.3 (Apr 2026), which only specifies ML-DSA-44. The W3C VC-DI-Quantum-Resistant issue #31 proposes adding ML-DSA-65. If W3C ratifies a different cryptosuite name later (e.g., `mldsa65-jcs-2024`), switch to it.
- The `0x1211` ML-DSA-65 public key multicodec prefix is `draft` in multiformats. The constant is hardcoded so any future change is a single-line fix.
- Harvest-now-decrypt-later protection only applies once ML-DSA-65 verifier trust is established in production. Until then, Ed25519 signatures remain the production security path.

## 9. References (all primary, no marketing)

- Attestix v0.4.1 `attestix/auth/pqc.py` — https://github.com/VibeTensor/attestix/blob/main/attestix/auth/pqc.py
- FIPS 204 final (Aug 2024) — https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf
- IETF LAMPS composite-sigs draft-19 — https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
- W3C di-quantum-safe v0.3 (Apr 2026) — https://www.w3.org/community/reports/credentials/CG-FINAL-di-quantum-safe-20260422/
- multiformats/multicodec table.csv (ML-DSA-65 varint 0x1211) — https://github.com/multiformats/multicodec/blob/master/table.csv
- AWS KMS ML-DSA launch (Jun 2025, GA) — https://aws.amazon.com/about-aws/whats-new/2025/06/aws-kms-post-quantum-ml-dsa-digital-signatures/
- ml-dsa crate 0.1.1 (RustCrypto, 2026-06-05) — https://github.com/RustCrypto/signatures/tree/master/ml-dsa
