//! HMAC chain from chain root + `tenant_id` binding.
//!
//! Per Plan v1.2 Block 4 v1.1.0.x+1+8 (auditor-4 prior art port):
//! HMAC-SHA256 over a canonical serialization of the chain entries
//! + the `tenant_id`. The `verify_chain` function is **independent
//! of the COSE signer key** — it only requires the HMAC key (from
//! `APOHARA_LEDGER_HMAC_KEY` env var) and the `tenant_id`. This means
//! an auditor can verify the chain root without knowing the issuer
//! key, decoupling chain integrity from issuer rotation.
//!
//! ## Ported from
//!
//! `reference/apohara-probant/packages/backend/verdict_vault.py:69-128`
//! (signed_hash + tenant_id binding; see `THIRD_PARTY_NOTICES.md`).
//! Adapted to Rust with a tenant_id-bounded canonical payload.
//!
//! ## Why HMAC + tenant_id?
//!
//! Two properties we need for forensic evidence:
//!
//! 1. **Tenant isolation** (closing auditor-2 BRECHA in v1.2): each
//!    tenant's chain root is bound to its `tenant_id` so a leaked
//!    `tenant_a` chain root cannot be replayed as `tenant_b`'s root.
//!
//! 2. **Independent verifier** (port from probant): the chain root
//!    can be verified without the COSE signer key. The HMAC key
//!    comes from the deployment env (`APOHARA_LEDGER_HMAC_KEY`)
//!    and can be rotated independently of the issuer keys.
//!
//! ## Failure mode
//!
//! If a single byte of any entry changes, `verify_chain` returns
//! `HmacChainError::RowMismatch` — the chain root changes. If the
//! HMAC key changes (rotation), the chain root changes. If the
//! `tenant_id` is wrong, the chain root changes. All three are loud
//! errors that point at the cause directly.

#![warn(missing_docs)]

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

use themis_evidence::chain::ChainEntry;

/// HMAC chain errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HmacChainError {
    /// The recomputed chain root does not match the expected one.
    /// Caused by: (a) a tampered entry, (b) wrong HMAC key, (c) wrong
    /// `tenant_id`, (d) any combination of the above.
    #[error("HMAC chain root mismatch: expected {expected}, got {actual}")]
    RootMismatch {
        /// The chain root the caller provided.
        expected: String,
        /// The chain root we recomputed.
        actual: String,
    },
}

/// A chain root bound to a `tenant_id` and a HMAC key.
///
/// The root is a 32-byte (64-hex-char) HMAC-SHA256 of the canonical
/// chain serialization. The same `entries + tenant_id + hmac_key`
/// triple always produces the same root (deterministic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HmacChainRoot {
    /// 32-byte (hex-encoded, 64 chars) HMAC-SHA256 root.
    pub hex: String,
}

/// Compute the HMAC chain root for `entries` under `hmac_key` and
/// `tenant_id`.
///
/// The canonical payload is the JSON serialization of
/// `{"entries": <serialized entries>, "tenant_id": <tenant_id>}`
/// (sorted keys for determinism). The HMAC-SHA256 of this payload
/// (key-prefixed with `tenant_id` to namespace the key per tenant)
/// is the root.
///
/// **Pure function** (no I/O, no clock, no env). Same input → same
/// output forever.
pub fn chain_root(
    entries: &[ChainEntry],
    tenant_id: &str,
    hmac_key: &[u8],
) -> HmacChainRoot {
    // Build the canonical payload: sorted-keys JSON of {entries, tenant_id}.
    let mut payload = serde_json::Map::new();
    payload.insert("entries".to_string(), serde_json::to_value(entries).expect(
        "ChainEntry serialization must succeed (no float / non-string keys)",
    ));
    payload.insert(
        "tenant_id".to_string(),
        serde_json::Value::String(tenant_id.to_string()),
    );
    let canonical = serde_json::to_vec(&payload)
        .expect("canonical payload serialization must succeed");

    // Prefix the HMAC key with tenant_id to namespace it. This is a
    // cheap defense against key reuse across tenants: an attacker
    // who learns the HMAC key for tenant_a cannot directly forge
    // tenant_b roots without also knowing tenant_b's id (the
    // tenant_id is part of the HMAC key derivation).
    let mut key_with_namespace = Vec::with_capacity(hmac_key.len() + tenant_id.len());
    key_with_namespace.extend_from_slice(hmac_key);
    key_with_namespace.extend_from_slice(tenant_id.as_bytes());

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key_with_namespace)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(&canonical);
    let result = mac.finalize().into_bytes();

    let mut hex = String::with_capacity(64);
    for byte in result.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    HmacChainRoot { hex }
}

/// Verify that `expected_root` matches the recomputed chain root for
/// `entries + tenant_id + hmac_key`. Returns `Ok(())` on match,
/// `Err(HmacChainError::RootMismatch)` on mismatch.
pub fn verify_chain(
    entries: &[ChainEntry],
    tenant_id: &str,
    hmac_key: &[u8],
    expected_root: &str,
) -> Result<(), HmacChainError> {
    let actual = chain_root(entries, tenant_id, hmac_key);
    if actual.hex != expected_root {
        return Err(HmacChainError::RootMismatch {
            expected: expected_root.to_string(),
            actual: actual.hex,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_evidence::chain::{ChainEntry, HashChain};

    fn make_entry(seq: u64, prev_hash: &str, payload: &str) -> ChainEntry {
        ChainEntry {
            sequence: seq,
            payload: payload.to_string(),
            blake3_hash: format!("hash_{seq}"),
            prev_hash: prev_hash.to_string(),
            created_at_ms: 1_700_000_000_000i64 + (seq as i64),
        }
    }

    #[test]
    fn test_chain_root_is_deterministic() {
        // Same input + same key + same tenant → same root.
        let entries = vec![make_entry(0, &"0".repeat(64), "hello")];
        let key = b"hmac-key-1";
        let r1 = chain_root(&entries, "tenant-a", key);
        let r2 = chain_root(&entries, "tenant-a", key);
        assert_eq!(r1, r2, "chain_root must be deterministic");
    }

    #[test]
    fn test_chain_root_binds_tenant_id() {
        // Same entries + different tenant_id → different root.
        let entries = vec![make_entry(0, &"0".repeat(64), "hello")];
        let key = b"hmac-key-1";
        let r_a = chain_root(&entries, "tenant-a", key);
        let r_b = chain_root(&entries, "tenant-b", key);
        assert_ne!(
            r_a, r_b,
            "chain_root MUST be tenant-bound (auditor-2 multi_tenant_isolation closure)"
        );
    }

    #[test]
    fn test_verify_chain_detects_tampered_row() {
        // Tamper with one entry → root mismatch.
        let mut entries = vec![
            make_entry(0, &"0".repeat(64), "hello"),
            make_entry(1, &"hash_0", "world"),
        ];
        let key = b"hmac-key-1";
        let original = chain_root(&entries, "tenant-a", key);

        // Tamper: change payload of entry 1.
        entries[1].payload = "WORLD_TAMPERED".to_string();
        let tampered = chain_root(&entries, "tenant-a", key);
        assert_ne!(original.hex, tampered.hex);

        // verify_chain returns Err.
        let result = verify_chain(&entries, "tenant-a", key, &original.hex);
        assert!(matches!(result, Err(HmacChainError::RootMismatch { .. })));
    }

    #[test]
    fn test_verify_chain_independent_of_cose_signer_key() {
        // The HMAC key is decoupled from the COSE signer key. Two
        // HMAC verifications with different keys on the same entries
        // produce different roots.
        let entries = vec![make_entry(0, &"0".repeat(64), "hello")];
        let r1 = chain_root(&entries, "tenant-a", b"hmac-key-A");
        let r2 = chain_root(&entries, "tenant-a", b"hmac-key-B");
        assert_ne!(r1, r2, "different HMAC keys MUST produce different roots");
    }

    #[test]
    fn test_empty_chain_returns_deterministic_genesis() {
        // Empty chain + tenant_id + key → deterministic root.
        let r1 = chain_root(&[], "tenant-a", b"key");
        let r2 = chain_root(&[], "tenant-a", b"key");
        assert_eq!(r1, r2);
        // The root is 32 bytes (64 hex chars).
        assert_eq!(r1.hex.len(), 64);
    }

    #[test]
    fn test_hash_chain_append_then_hmac_root_stable() {
        // Integration: a real HashChain.append → hmac_chain.chain_root
        // is stable across calls (deterministic) and changes when
        // we add a new entry.
        let mut chain = HashChain::new();
        chain
            .append("first")
            .expect("genesis append should succeed");
        let r1 = chain_root(&chain.entries, "tenant-a", b"key");
        chain
            .append("second")
            .expect("second append should succeed");
        let r2 = chain_root(&chain.entries, "tenant-a", b"key");
        assert_ne!(r1, r2, "appending MUST change the root");
        // But recomputing r1 is stable:
        let r1_recomputed = chain_root(&chain.entries[..1], "tenant-a", b"key");
        assert_eq!(r1.hex, r1_recomputed.hex);
    }

    #[test]
    fn test_verify_chain_accepts_correct_root() {
        let entries = vec![make_entry(0, &"0".repeat(64), "hello")];
        let key = b"hmac-key-1";
        let r = chain_root(&entries, "tenant-a", key);
        let result = verify_chain(&entries, "tenant-a", key, &r.hex);
        assert!(result.is_ok(), "verify_chain with correct root must pass");
    }
}
