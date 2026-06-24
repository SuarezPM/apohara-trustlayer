//! End-to-end tests for the DID-signed Band message flow
//! (C-04 / G20 / ASI07).
//!
//! These tests exercise `TrustGate` against real (not mocked)
//! Ed25519 keypairs to verify the production signing path:
//! 32-byte seed -> SigningKey -> did:key -> canonical JCS body
//! -> Ed25519 signature -> hex-encoded SignedMessage wire format.

use ed25519_dalek::SigningKey;
use rand::RngCore;
use themis_band_client::signed_message::{sign, Did, SignedMessage};
use themis_band_client::trust_gate::TrustGate;

const NOW_MS: i64 = 1_700_000_000_000;

fn fresh_key() -> SigningKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    SigningKey::from_bytes(&bytes)
}

#[test]
fn test_trust_gate_full_flow() {
    // Two trusted peers + one rogue.
    let sk_a = fresh_key();
    let sk_b = fresh_key();
    let sk_rogue = fresh_key();

    let did_a = Did::from_verifying_key(&sk_a.verifying_key());
    let did_b = Did::from_verifying_key(&sk_b.verifying_key());
    let did_rogue = Did::from_verifying_key(&sk_rogue.verifying_key());

    let mut gate = TrustGate::new(false);
    gate.trust(did_a.clone(), sk_a.verifying_key());
    gate.trust(did_b.clone(), sk_b.verifying_key());
    assert_eq!(gate.len(), 2);

    // Both trusted senders pass.
    let msg_a: SignedMessage = sign(serde_json::json!({"from": "A"}), &sk_a, NOW_MS);
    let msg_b: SignedMessage = sign(serde_json::json!({"from": "B"}), &sk_b, NOW_MS);
    assert!(gate.check(&msg_a, NOW_MS).is_ok());
    assert!(gate.check(&msg_b, NOW_MS).is_ok());

    // The rogue is signed correctly but is NOT in the trust set.
    let msg_rogue: SignedMessage = sign(serde_json::json!({"from": "rogue"}), &sk_rogue, NOW_MS);
    let err = gate.check(&msg_rogue, NOW_MS).unwrap_err();
    let err_str = format!("{err}");
    assert!(
        err_str.contains(&did_rogue.to_string()),
        "expected untrusted DID in error, got: {err_str}"
    );
}

#[test]
fn test_trust_gate_rejects_tampered_message() {
    let sk = fresh_key();
    let did = Did::from_verifying_key(&sk.verifying_key());
    let mut gate = TrustGate::new(false);
    gate.trust(did, sk.verifying_key());

    let mut msg: SignedMessage = sign(serde_json::json!({"action": "approve"}), &sk, NOW_MS);
    assert!(gate.check(&msg, NOW_MS).is_ok());

    // Mutate the body after signing — the signature must no longer verify.
    msg.body = serde_json::json!({"action": "halt"});
    assert!(gate.check(&msg, NOW_MS).is_err());
}

#[test]
fn test_trust_gate_rejects_old_message() {
    let sk = fresh_key();
    let did = Did::from_verifying_key(&sk.verifying_key());
    let mut gate = TrustGate::new(false);
    gate.trust(did, sk.verifying_key());

    // Sign 2 minutes in the past — beyond the 60s skew window.
    let old_ts = NOW_MS - 120_000;
    let msg: SignedMessage = sign(serde_json::json!({"action": "approve"}), &sk, old_ts);
    let err = gate.check(&msg, NOW_MS).unwrap_err();
    assert!(
        format!("{err}").contains("skew"),
        "expected TimestampSkew error, got: {err}"
    );
}
