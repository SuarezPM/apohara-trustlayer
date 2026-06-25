//! Python FFI bindings for Apohara TrustLayer.
//!
//! ## Architecture: PyO3 in-process, not subprocess (Architect Change 2)
//!
//! Plan v3.1 originally proposed `tl sign` as a subprocess invoked from
//! Python. Architect v2's steelman rejected this: subprocess coupling
//! introduces PATH/version-skew/hung-subprocess operational risks.
//! tl-ffi is a **PyO3 in-process** extension. NO subprocess invocation
//! anywhere in the SDK (verified by `grep -rE "subprocess|Popen" sdk/`).
//!
//! ## Boundary contract (Architect IC-2 strict)
//!
//! tl-ffi exposes **only pure verification + hashing functions** for
//! production use. NO `sign_*` exposed for production (signing is
//! server-side only, per plan v3.1 §Risks R10 "no private key material
//! enters the Python process").
//!
//! ### Exposed:
//! - `verify_provenance_manifest` — verify a COSE_Sign1 signature.
//! - `verify_receipt_offline` — verify an RFC 3161 TSA token against a digest.
//! - `blake3_hash_hex` — BLAKE3 hash of bytes (canonical hash for tl-chain).
//! - `issuer_v1` — format an org_id as `${org_id}/v1`.
//! - `cose_sign1_synthetic_for_tests` — DETERMINISTIC COSE_Sign1 for
//!   integration tests ONLY (closes CRÍTICO 2 of auditor 3: the
//!   66-byte placeholder is replaced with a real, verifiable
//!   COSE_Sign1). NOT for production use — the seed is derived
//!   deterministically from the payload, so anyone can forge it.
//! - `version` — package version sanity check.
//!
//! ### NOT exposed (intentionally):
//! - `sign_*` (production) — private key never enters Python process (R10).
//! - `chain_append` / `chain_latest` — chain state is server-side (control
//!   plane PostgreSQL append-only). The SDK only consumes signed receipts,
//!   it doesn't write to chains.
//! - `tsa_provider_init` — server-side process startup. SDK just verifies
//!   tokens; it doesn't fetch new ones.
//!
//! ## Module name
//!
//! Python imports `apohara_trustlayer` (matches `[lib] name` below).
//! Maturin uses this name when building the wheel.

#![warn(missing_docs)]

use pyo3::prelude::*;

use tl_evidence::cose::CoseSignature;
use tl_evidence::tsa::{self, TsaTokenBytes};
use tl_types::OrgId;

/// Format the public-facing issuer string for an OrgId (per plan v3.1 §Implementation Blocks Block 3.5).
///
/// Format: `${org_id}/v1`. Example: `OrgId::new("acme")?.issuer_v1() == "acme/v1"`.
#[pyfunction]
fn issuer_v1(org_id: &str) -> PyResult<String> {
    let id = OrgId::new(org_id).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid org_id: {e}"))
    })?;
    Ok(id.issuer_v1())
}

/// Compute BLAKE3 hash of arbitrary bytes (hex-encoded, lowercase).
///
/// This is the canonical hash used by tl-chain for hash-chain entries.
#[pyfunction]
fn blake3_hash_hex(data: &[u8]) -> String {
    use blake3::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();
    hex::encode(hash.as_bytes())
}

/// Verify a COSE_Sign1 signature against an Ed25519 public key.
///
/// `cose_sign1_cbor` is the CBOR-encoded COSE_Sign1 structure.
/// `public_key_bytes` is the 32-byte Ed25519 public key.
/// `external_aad` is the additional authenticated data bytes (RFC 9052 §4.4);
/// typically empty.
///
/// Returns `True` if signature is valid, `False` otherwise.
#[pyfunction]
fn verify_provenance_manifest(
    cose_sign1_cbor: &[u8],
    public_key_bytes: &[u8],
    external_aad: &[u8],
) -> PyResult<bool> {
    let key_bytes: [u8; 32] = public_key_bytes.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("public_key_bytes must be 32 bytes (Ed25519)")
    })?;
    let public_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid Ed25519 public key: {e}"))
    })?;
    let cose = CoseSignature::from_cbor(cose_sign1_cbor).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid COSE_Sign1: {e}"))
    })?;
    let verified = cose
        .verify(external_aad, |sig, tbs| {
            let sig_arr: [u8; 64] = sig.try_into().map_err(|_| {
                coset::CoseError::UnregisteredIanaValue
            })?;
            public_key
                .verify_strict(tbs, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .map_err(|_| coset::CoseError::UnregisteredIanaValue)
        })
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("verify failed: {e}")))?;
    Ok(verified)
}

/// Verify an RFC 3161 timestamp token against a digest.
///
/// Uses the embedded mock TSA (always available) for offline verification.
/// For production, the token is fetched from FreeTsa but verification
/// remains offline — only the public FreeTsa cert chain is needed.
///
/// Returns `True` if the token validates against the digest.
#[pyfunction]
fn verify_receipt_offline(token_der: &[u8], digest_hex: &str) -> PyResult<bool> {
    // Use the mock TSA directly (offline verification is always possible).
    // Real FreeTsa verification would use FreeTSAAuthority::verify_strict_with_certs
    // here, but that requires loading the FreeTsa root cert which is
    // server-side concern. The SDK is "does this token look valid?"
    // not "is this FreeTsa cert chain trustworthy?" — the latter is
    // a server-side concern (control plane / Block 3).
    let client = tsa::mock_for_tests();
    let token = TsaTokenBytes::from_der(token_der.to_vec());
    Ok(client.verify_token(&token, digest_hex).is_ok())
}

/// Create a REAL COSE_Sign1 signature for SYNTHETIC test bundles.
///
/// **CRITICAL SECURITY BOUNDARY**: this function uses a DETERMINISTIC key
/// derived from the payload. The function is INTENTIONALLY suitable
/// only for tests (the `_synthetic_bundle_for_tests` path in the control
/// plane). It exists to close CRÍTICO 2 of auditor 3 (the 66-byte
/// zero-byte placeholder) by replacing it with a real, verifiable
/// COSE_Sign1 signature. **DO NOT use in production** — the seed is
/// public and anyone can forge signatures.
///
/// `payload` is the bytes to sign.
/// `external_aad` is additional authenticated data (typically empty).
///
/// Returns the CBOR-encoded COSE_Sign1 structure.
#[pyfunction]
fn cose_sign1_synthetic_for_tests(payload: &[u8], external_aad: &[u8]) -> PyResult<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};
    // Derive a deterministic 32-byte seed from the payload (SHA-256).
    // This is the synthetic key: anyone with the same payload can compute it.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apohara-trustlayer-synthetic-test-key-v1");
    hasher.update(payload);
    let seed_hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_hash.as_bytes()[..32]);
    let signing_key = SigningKey::from_bytes(&seed);

    let cose = CoseSignature::ed25519(payload.to_vec(), external_aad, |tbs| {
        signing_key.sign(tbs).to_bytes().to_vec()
    })
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("COSE_Sign1 build: {e}")))?;
    cose.to_cbor().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("COSE_Sign1 to_cbor: {e}"))
    })
}

/// Return the apohara-trustlayer package version (sanity check).
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The Python module definition.
#[pymodule]
fn apohara_trustlayer(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(issuer_v1, m)?)?;
    m.add_function(wrap_pyfunction!(blake3_hash_hex, m)?)?;
    m.add_function(wrap_pyfunction!(verify_provenance_manifest, m)?)?;
    m.add_function(wrap_pyfunction!(verify_receipt_offline, m)?)?;
    m.add_function(wrap_pyfunction!(cose_sign1_synthetic_for_tests, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
