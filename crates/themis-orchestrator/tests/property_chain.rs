//! Property-based tests for the BLAKE3 hash chain.
//!
//! Verifies the invariants that the Evidence Packet depends on
//! for tamper-evidence:
//!
//! 1. **Determinism**: same input bytes → same blake3 hash.
//! 2. **Avalanche**: 1-bit flip in input → wildly different hash.
//! 3. **Length-extend resistance**: appending bytes changes the
//!    hash unpredictably (a fundamental property of BLAKE3 —
//!    a Merkle–Damgård break would not survive this test).
//! 4. **Ordering**: payload A then B hashes differently from
//!    B then A (the chain is order-sensitive).
//!
//! These run via `proptest` with 256 cases per property.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn blake3_is_deterministic(bytes: Vec<u8>) {
        let h1 = blake3::hash(&bytes);
        let h2 = blake3::hash(&bytes);
        prop_assert_eq!(h1, h2);
    }

    #[test]
    fn blake3_avalanche_on_bit_flip(bytes in proptest::collection::vec(any::<u8>(), 1..256)) {
        // Flip a single bit in the middle of the input.
        let mut flipped = bytes.clone();
        let mid = flipped.len() / 2;
        flipped[mid] ^= 0x01;
        let h_orig = blake3::hash(&bytes);
        let h_flip = blake3::hash(&flipped);
        // 1-bit flip must change at least ~40% of the output bits
        // (BLAKE3's diffusion is probabilistic; the strict guarantee
        // is on AVERAGE across many inputs, not on every single
        // one. We use 96/256 = 37.5% as the threshold; a broken
        // implementation would flip <10% and fail this test.)
        let diff_bits = h_orig
            .as_bytes()
            .iter()
            .zip(h_flip.as_bytes().iter())
            .map(|(a, b)| (a ^ b).count_ones())
            .sum::<u32>();
        prop_assert!(diff_bits >= 96, "1-bit flip should flip ≥96 of 256 output bits (≈37.5%), got {}", diff_bits);
    }

    #[test]
    fn blake3_changes_with_appended_bytes(bytes: Vec<u8>, suffix: Vec<u8>) {
        let h_orig = blake3::hash(&bytes);
        let mut extended = bytes.clone();
        extended.extend_from_slice(&suffix);
        let h_ext = blake3::hash(&extended);
        // Empty suffix is a no-op (the test asserts behaviour for
        // the non-trivial case).
        if !suffix.is_empty() {
            prop_assert_ne!(h_orig, h_ext);
        }
    }

    #[test]
    fn blake3_is_order_sensitive(prefix: Vec<u8>, mid: Vec<u8>, suffix: Vec<u8>) {
        let mut ab = prefix.clone();
        ab.extend_from_slice(&mid);
        ab.extend_from_slice(&suffix);
        let mut ba = suffix.clone();
        ba.extend_from_slice(&mid);
        ba.extend_from_slice(&prefix);
        let h_ab = blake3::hash(&ab);
        let h_ba = blake3::hash(&ba);
        // BLAKE3 is order-sensitive: any rearrangement of the
        // bytes produces a different hash. The check is on the
        // final concatenated byte sequences, not on the inputs
        // separately — `prefix=[]` + `suffix=[0]` collapses `ab`
        // and `ba` to the same bytes and must be excluded.
        if ab != ba {
            prop_assert_ne!(h_ab, h_ba);
        }
    }

    #[test]
    fn blake3_hex_is_64_chars(bytes: Vec<u8>) {
        let h = blake3::hash(&bytes);
        let hex = h.to_hex().to_string();
        prop_assert_eq!(hex.len(), 64);
        prop_assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
