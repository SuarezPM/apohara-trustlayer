//! WASM SDK for TrustLayer — browser/edge verification of evidence bundles.
//!
//! Per Plan v1.1 (Block 4 v1.1.0-US-11): provide a WASM-compiled SDK
//! so browsers and edge runtimes can verify evidence bundles WITHOUT
//! a network round-trip to the control plane.
//!
//! ## What this crate does
//!
//! Exposes a minimal JS-compatible API for:
//!
//! 1. **Bundle hash verification** — recompute the BLAKE3 hash of a
//!    bundle's canonical JSON and compare to the `row_hash` field.
//! 2. **OrgId validation** — DNS-safe org id validation matching
//!    `tl-types::OrgId` (Architect IC-4).
//! 3. **SCITT receipt parsing** — extract the COSE_Sign1 payload +
//!    issuer fingerprint from a SCITT receipt envelope.
//!
//! ## Architecture: pure logic + thin wasm shims
//!
//! The crate is structured so the **pure Rust logic** is in
//! `pub(crate)` helper functions that can be unit-tested on native
//! targets (x86_64/aarch64). The `#[wasm_bindgen]` functions are
//! thin shims that convert between `serde_wasm_bindgen` types and
//! the pure types. This lets `cargo test -p tl-wasm` run all tests
//! natively (without the wasm32 target) — wasm-bindgen-test is
//! optional for full JS interop coverage.
//!
//! ## What this crate does NOT do
//!
//! - No COSE_Sign1 cryptographic verification (requires Ed25519 verify
//!   which adds ~50KB to the WASM bundle; deferred to v1.1.1 with a
//!   feature-gated `verify` module).
//! - No RFC 3161 timestamp parsing (use the Rust `cryptographic-message-syntax`
//!   crate; too heavy for browser bundle).
//! - No network I/O — pure computation, fully offline.
//!
//! ## Usage from JavaScript
//!
//! ```js
//! import init, { verify_bundle_hash, parse_scitt_receipt } from "./tl_wasm.js";
//! await init();
//!
//! const bundle = { bundle_id: "...", row_hash: "...", disclosures: [...] };
//! const isValid = verify_bundle_hash(JSON.stringify(bundle));
//!
//! const receipt = { payload: "...", cose_sign1: "...", issuer_pubkey_fingerprint: "..." };
//! const parsed = parse_scitt_receipt(JSON.stringify(receipt));
//! ```
//!
//! ## Bundle size budget
//!
//! Target: < 100KB gzipped (per Plan v1.1 v1.1.0-US-11). Current
//! estimate with `blake3 + serde + tl-types`: ~40KB gzipped.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use tl_types::OrgId;

// ============================================================================
// Pure types + helpers (testable on native target)
// ============================================================================

/// Errors exposed to JavaScript.
#[derive(Debug, Error, Clone, Serialize, Deserialize)]
pub enum WasmError {
    #[error("invalid bundle JSON: {0}")]
    InvalidJson(String),
    #[error("invalid org_id: {0}")]
    InvalidOrgId(String),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("missing field: {0}")]
    MissingField(String),
    #[error("base64 decode error: {0}")]
    Base64Error(String),
    #[error("utf8 decode error: {0}")]
    Utf8Error(String),
}

/// Parsed SCITT receipt envelope (subset for browser display).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedScittReceipt {
    /// Base64-decoded payload (the disclosure JSON).
    pub payload_json: String,
    /// Hex-encoded issuer public key fingerprint (32 bytes).
    pub issuer_pubkey_fingerprint_hex: String,
    /// Hex-encoded kid (key identifier).
    pub issuer_kid: String,
    /// UNIX timestamp (seconds) when the receipt was issued.
    pub issued_at: u64,
    /// Registry identifier (e.g. "apohara-trustlayer-v1").
    pub registry_id: String,
}

/// Compute the BLAKE3 hash of a byte slice and return hex.
pub(crate) fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Canonical JSON serialization for hash verification.
///
/// We sort object keys recursively to ensure the same logical bundle
/// always produces the same hash. `serde_json` does NOT sort by default.
pub(crate) fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(map) => {
            let mut sorted: std::collections::BTreeMap<String, Value> =
                std::collections::BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), canonicalize_json(v));
            }
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonicalize_json).collect()),
        other => other.clone(),
    }
}

/// Pure logic: verify that a bundle's `row_hash` matches the BLAKE3
/// hash of its canonical JSON (excluding the `row_hash` field itself).
///
/// Returns `Ok(true)` if hashes match, `Ok(false)` if they differ.
pub(crate) fn verify_bundle_hash_pure(bundle_json: &str) -> Result<bool, WasmError> {
    let value: serde_json::Value =
        serde_json::from_str(bundle_json).map_err(|e| WasmError::InvalidJson(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| WasmError::InvalidJson("expected JSON object".into()))?;
    let expected = obj
        .get("row_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WasmError::MissingField("row_hash".into()))?;
    let mut without_hash = obj.clone();
    without_hash.remove("row_hash");
    let canonical = canonicalize_json(&serde_json::Value::Object(without_hash));
    let bytes =
        serde_json::to_vec(&canonical).map_err(|e| WasmError::InvalidJson(e.to_string()))?;
    let actual = blake3_hex(&bytes);
    Ok(actual == expected)
}

/// Pure logic: compute the BLAKE3 hash of a JSON value (canonical form).
pub(crate) fn compute_canonical_hash_pure(json_str: &str) -> Result<String, WasmError> {
    let value: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| WasmError::InvalidJson(e.to_string()))?;
    let canonical = canonicalize_json(&value);
    let bytes =
        serde_json::to_vec(&canonical).map_err(|e| WasmError::InvalidJson(e.to_string()))?;
    Ok(blake3_hex(&bytes))
}

/// Pure logic: validate an org_id string matches DNS-safe rules.
pub(crate) fn validate_org_id_pure(org_id: &str) -> Result<String, WasmError> {
    OrgId::new(org_id)
        .map(String::from)
        .map_err(|e| WasmError::InvalidOrgId(e.to_string()))
}

/// Pure logic: parse a SCITT receipt JSON envelope.
pub(crate) fn parse_scitt_receipt_pure(
    receipt_json: &str,
) -> Result<ParsedScittReceipt, WasmError> {
    let value: serde_json::Value =
        serde_json::from_str(receipt_json).map_err(|e| WasmError::InvalidJson(e.to_string()))?;
    let obj = value
        .as_object()
        .ok_or_else(|| WasmError::InvalidJson("expected object".into()))?;
    let payload_b64 = obj
        .get("payload")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WasmError::MissingField("payload".into()))?;
    let issuer_fingerprint = obj
        .get("issuer_pubkey_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WasmError::MissingField("issuer_pubkey_fingerprint".into()))?;
    let issuer_kid = obj
        .get("issuer_kid")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let issued_at = obj.get("issued_at").and_then(|v| v.as_u64()).unwrap_or(0);
    let registry_id = obj
        .get("registry_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::STANDARD
        .decode(payload_b64)
        .map_err(|e| WasmError::Base64Error(e.to_string()))?;
    let payload_json =
        String::from_utf8(payload_bytes).map_err(|e| WasmError::Utf8Error(e.to_string()))?;
    Ok(ParsedScittReceipt {
        payload_json,
        issuer_pubkey_fingerprint_hex: issuer_fingerprint.to_string(),
        issuer_kid,
        issued_at,
        registry_id,
    })
}

// ============================================================================
// WASM bindings (thin shims around the pure logic)
// ============================================================================

// ============================================================================
// Watermark detection (Kirchenbauer z-test, byte-level)
// ============================================================================
//
// SDK-level detector for the Kirchenbauer et al. (2023) text watermark.
// The full algorithm lives in `tl-watermark` (which depends on c2patool,
// AudioSeal, etc.); pulling those into WASM would blow the bundle size
// budget. Instead we ship a self-contained z-test here that operates
// on UTF-8 bytes as token ids with vocab_size = 256.
//
// The statistical test is identical: green_count ~ Binom(n, gamma) under
// the null hypothesis, z = (observed - expected) / std_dev, threshold 4.0.
//
// `text` is the UTF-8 encoded string. `gamma` defaults to 0.25. The
// 32-byte `key` is hashed with `blake3` per position to derive the
// green list (deterministic; shared secret between producer and detector).

/// Default green-list fraction (Kirchenbauer et al. 2023: gamma=0.25).
pub(crate) const DEFAULT_GAMMA: f32 = 0.25;
/// Default z-score threshold (one-sided p < 0.00003).
pub(crate) const DEFAULT_THRESHOLD: f64 = 4.0;
/// Vocab size for byte-level detection: 256 (one byte = one "token").
pub(crate) const BYTE_VOCAB_SIZE: u32 = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WatermarkDetection {
    /// True iff z_score > threshold.
    pub detected: bool,
    /// Signed z-score under null hypothesis of no watermark.
    pub z_score: f64,
    /// Number of bytes that fell in the green list.
    pub green_count: u32,
    /// Total bytes analysed.
    pub total_count: u32,
    /// Green-list fraction used.
    pub gamma: f32,
    /// Z-score threshold used.
    pub threshold: f64,
}

/// Pure logic: byte-level Kirchenbauer z-test.
///
/// `text` is interpreted as a UTF-8 string; each byte is one token id.
/// The 32-byte `key` seeds the per-position green list via BLAKE3.
pub(crate) fn detect_watermark_pure(
    text: &str,
    key: &[u8; 32],
    gamma: f32,
    threshold: f64,
) -> Result<WatermarkDetection, WasmError> {
    if gamma <= 0.0 || gamma >= 1.0 {
        return Err(WasmError::InvalidJson(format!(
            "gamma must be in (0,1): got {}",
            gamma
        )));
    }
    if threshold <= 0.0 {
        return Err(WasmError::InvalidJson(format!(
            "threshold must be > 0: got {}",
            threshold
        )));
    }

    let bytes = text.as_bytes();
    let n = bytes.len();
    if n == 0 {
        return Ok(WatermarkDetection {
            detected: false,
            z_score: 0.0,
            green_count: 0,
            total_count: 0,
            gamma,
            threshold,
        });
    }

    let green_size = ((gamma * BYTE_VOCAB_SIZE as f32) as u32).max(1);
    let mut green_count: u32 = 0;

    for (i, &tok) in bytes.iter().enumerate() {
        let mut prng_seed = key.to_vec();
        prng_seed.extend_from_slice(&(i as u32).to_le_bytes());
        let hash = blake3::hash(&prng_seed);
        let seed = u32::from_le_bytes([
            hash.as_bytes()[0],
            hash.as_bytes()[1],
            hash.as_bytes()[2],
            hash.as_bytes()[3],
        ]);
        // Check if `tok` is in the green list for this position.
        for j in 0..green_size {
            let candidate = seed.wrapping_add(j.wrapping_mul(0x9E3779B1)) % BYTE_VOCAB_SIZE;
            if candidate == tok as u32 {
                green_count += 1;
                break;
            }
        }
    }

    let n_f = n as f64;
    let gamma_f = gamma as f64;
    let expected = n_f * gamma_f;
    let variance = n_f * gamma_f * (1.0 - gamma_f);
    let std_dev = variance.sqrt();
    let z = if std_dev > 0.0 {
        (green_count as f64 - expected) / std_dev
    } else {
        0.0
    };
    let detected = z > threshold;

    Ok(WatermarkDetection {
        detected,
        z_score: z,
        green_count,
        total_count: n as u32,
        gamma,
        threshold,
    })
}

/// Native API: detect watermark in text (byte-level z-test).
pub fn detect_watermark_native(text: &str) -> Result<WatermarkDetection, WasmError> {
    // Default key (matches the Go SDK's DefaultWatermarkConfig).
    let mut key = [0u8; 32];
    for i in 0..32 {
        key[i] = (i + 1) as u8;
    }
    detect_watermark_pure(text, &key, DEFAULT_GAMMA, DEFAULT_THRESHOLD)
}

#[cfg(target_arch = "wasm32")]
mod wasm_bindings {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Verify that a bundle's `row_hash` matches the BLAKE3 hash of its
    /// canonical JSON.
    #[wasm_bindgen]
    pub fn verify_bundle_hash(bundle_json: &str) -> Result<bool, JsError> {
        verify_bundle_hash_pure(bundle_json).map_err(JsError::from)
    }

    /// Compute the BLAKE3 hash of a JSON value (canonical form).
    #[wasm_bindgen]
    pub fn compute_canonical_hash(json_str: &str) -> Result<String, JsError> {
        compute_canonical_hash_pure(json_str).map_err(JsError::from)
    }

    /// Validate an org_id string matches DNS-safe rules.
    #[wasm_bindgen]
    pub fn validate_org_id(org_id: &str) -> Result<String, JsError> {
        validate_org_id_pure(org_id).map_err(JsError::from)
    }

    /// Parse a SCITT receipt JSON envelope and extract displayable fields.
    #[wasm_bindgen]
    pub fn parse_scitt_receipt(receipt_json: &str) -> Result<JsValue, JsError> {
        let parsed = parse_scitt_receipt_pure(receipt_json)?;
        serde_wasm_bindgen::to_value(&parsed).map_err(JsError::from)
    }

    /// Get the WASM SDK version (semver).
    #[wasm_bindgen]
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// Run the byte-level Kirchenbauer z-test on the input text.
    ///
    /// Uses a fixed default key (1, 2, 3, ..., 32) and gamma=0.25,
    /// threshold=4.0. Returns a JS object with `detected`, `z_score`,
    /// `green_count`, `total_count`, `gamma`, `threshold`.
    #[wasm_bindgen]
    pub fn detect_watermark(text: &str) -> Result<JsValue, JsError> {
        let out = detect_watermark_native(text)?;
        serde_wasm_bindgen::to_value(&out).map_err(JsError::from)
    }
}

#[cfg(target_arch = "wasm32")]
pub use wasm_bindings::*;

// ============================================================================
// Native-target API (for testing + for HTTP-only TypeScript/Python SDKs
// that want the same pure logic without WASM)
// ============================================================================

/// Native API: verify bundle hash (same logic as wasm `verify_bundle_hash`).
pub fn verify_bundle_hash_native(bundle_json: &str) -> Result<bool, WasmError> {
    verify_bundle_hash_pure(bundle_json)
}

/// Native API: compute canonical hash.
pub fn compute_canonical_hash_native(json_str: &str) -> Result<String, WasmError> {
    compute_canonical_hash_pure(json_str)
}

/// Native API: validate org_id.
pub fn validate_org_id_native(org_id: &str) -> Result<String, WasmError> {
    validate_org_id_pure(org_id)
}

/// Native API: parse SCITT receipt.
pub fn parse_scitt_receipt_native(receipt_json: &str) -> Result<ParsedScittReceipt, WasmError> {
    parse_scitt_receipt_pure(receipt_json)
}

/// Get the crate version (works on both native and wasm).
pub fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_keys() {
        let v: serde_json::Value = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        let c = canonicalize_json(&v);
        assert_eq!(c.to_string(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonicalize_recurses() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"z":1,"nested":{"y":2,"x":3}}"#).unwrap();
        let c = canonicalize_json(&v);
        assert_eq!(c.to_string(), r#"{"nested":{"x":3,"y":2},"z":1}"#);
    }

    #[test]
    fn canonicalize_arrays_preserve_order() {
        let v: serde_json::Value = serde_json::from_str(r#"[3,1,2]"#).unwrap();
        let c = canonicalize_json(&v);
        assert_eq!(c.to_string(), "[3,1,2]");
    }

    #[test]
    fn blake3_hash_is_deterministic() {
        let a = blake3_hex(b"hello");
        let b = blake3_hex(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn verify_bundle_hash_matches_when_correct() {
        let bundle_str = r#"{"bundle_id":"b1","disclosures":[],"signatures":{}}"#;
        let value: serde_json::Value = serde_json::from_str(bundle_str).unwrap();
        let mut obj = value.as_object().unwrap().clone();
        let canonical_bytes =
            serde_json::to_vec(&canonicalize_json(&serde_json::Value::Object(obj.clone())))
                .unwrap();
        obj.insert(
            "row_hash".into(),
            serde_json::Value::String(blake3_hex(&canonical_bytes)),
        );
        let bundle_with_hash = serde_json::to_string(&obj).unwrap();
        let result = verify_bundle_hash_native(&bundle_with_hash).unwrap();
        assert!(result, "hash should match");
    }

    #[test]
    fn verify_bundle_hash_detects_tampering() {
        let bundle_str = r#"{"bundle_id":"b1","disclosures":[],"signatures":{}}"#;
        let value: serde_json::Value = serde_json::from_str(bundle_str).unwrap();
        let mut obj = value.as_object().unwrap().clone();
        let canonical_bytes =
            serde_json::to_vec(&canonicalize_json(&serde_json::Value::Object(obj.clone())))
                .unwrap();
        obj.insert(
            "row_hash".into(),
            serde_json::Value::String(blake3_hex(&canonical_bytes)),
        );
        obj.insert(
            "disclosures".into(),
            serde_json::json!([{"id": "tampered"}]),
        );
        let tampered = serde_json::to_string(&obj).unwrap();
        let result = verify_bundle_hash_native(&tampered).unwrap();
        assert!(!result, "hash should NOT match after tampering");
    }

    #[test]
    fn verify_bundle_hash_rejects_invalid_json() {
        assert!(verify_bundle_hash_native("not json").is_err());
    }

    #[test]
    fn verify_bundle_hash_rejects_non_object() {
        assert!(verify_bundle_hash_native("[1,2,3]").is_err());
    }

    #[test]
    fn verify_bundle_hash_rejects_missing_row_hash() {
        let bundle = r#"{"bundle_id":"b1","disclosures":[]}"#;
        assert!(verify_bundle_hash_native(bundle).is_err());
    }

    #[test]
    fn compute_canonical_hash_is_key_order_independent() {
        let a = compute_canonical_hash_native(r#"{"a":1,"b":2}"#).unwrap();
        let b = compute_canonical_hash_native(r#"{"b":2,"a":1}"#).unwrap();
        assert_eq!(a, b, "canonical hash must be key-order independent");
    }

    #[test]
    fn validate_org_id_accepts_dns_safe() {
        // OrgId rules (per tl-types): a-z, 0-9, `-` only; non-empty;
        // ≤ 64 chars. No underscores, no uppercase.
        assert!(validate_org_id_native("acme").is_ok());
        assert!(validate_org_id_native("acme-corp").is_ok());
        assert!(validate_org_id_native("a1").is_ok());
        assert!(validate_org_id_native("globex-123").is_ok());
        assert_eq!(validate_org_id_native("acme").unwrap(), "acme");
    }

    #[test]
    fn validate_org_id_rejects_invalid() {
        // Empty is rejected.
        assert!(validate_org_id_native("").is_err());
        // Underscore is rejected (DNS-safe doesn't include `_`).
        assert!(validate_org_id_native("acme_corp").is_err());
        // Uppercase is rejected.
        assert!(validate_org_id_native("UPPERCASE").is_err());
        // Spaces are rejected.
        assert!(validate_org_id_native("has spaces").is_err());
        // Path traversal chars are rejected (path-traversal defense).
        assert!(validate_org_id_native("has/slash").is_err());
        assert!(validate_org_id_native("dot.dot").is_err());
        // Unicode is rejected.
        assert!(validate_org_id_native("café").is_err());
        // Too long (> 64 chars).
        assert!(validate_org_id_native(&"a".repeat(65)).is_err());
    }

    #[test]
    fn parse_scitt_receipt_extracts_fields() {
        use base64::Engine;
        let payload = br#"{"disclosure_id":"d1","compliance":"Compliant"}"#;
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let receipt = serde_json::json!({
            "payload": payload_b64,
            "cose_sign1": "ignored-by-parser",
            "issuer_kid": "k1",
            "issuer_pubkey_fingerprint": "ab".repeat(32),
            "inclusion_proof": "None",
            "issued_at": 1719400000u64,
            "registry_id": "apohara-trustlayer-v1",
        });
        let receipt_str = serde_json::to_string(&receipt).unwrap();
        let parsed = parse_scitt_receipt_native(&receipt_str).unwrap();
        assert!(parsed.payload_json.contains("disclosure_id"));
        assert_eq!(parsed.issuer_kid, "k1");
        assert_eq!(parsed.issued_at, 1719400000);
        assert_eq!(parsed.registry_id, "apohara-trustlayer-v1");
        assert_eq!(parsed.issuer_pubkey_fingerprint_hex.len(), 64);
    }

    #[test]
    fn parse_scitt_receipt_rejects_missing_payload() {
        let receipt = serde_json::json!({
            "cose_sign1": "x",
            "issuer_kid": "k1",
            "issuer_pubkey_fingerprint": "ab".repeat(32),
            "issued_at": 1,
            "registry_id": "r1",
        });
        let s = serde_json::to_string(&receipt).unwrap();
        assert!(parse_scitt_receipt_native(&s).is_err());
    }

    #[test]
    fn parse_scitt_receipt_rejects_missing_fingerprint() {
        use base64::Engine;
        let payload = br#"{}"#;
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let receipt = serde_json::json!({
            "payload": payload_b64,
            "cose_sign1": "x",
            "issuer_kid": "k1",
            "issued_at": 1,
            "registry_id": "r1",
        });
        let s = serde_json::to_string(&receipt).unwrap();
        assert!(parse_scitt_receipt_native(&s).is_err());
    }

    #[test]
    fn parse_scitt_receipt_rejects_bad_base64() {
        let receipt = serde_json::json!({
            "payload": "!!!not-base64!!!",
            "cose_sign1": "x",
            "issuer_kid": "k1",
            "issuer_pubkey_fingerprint": "ab".repeat(32),
            "issued_at": 1,
            "registry_id": "r1",
        });
        let s = serde_json::to_string(&receipt).unwrap();
        assert!(parse_scitt_receipt_native(&s).is_err());
    }

    #[test]
    fn sdk_version_is_semver() {
        let v = sdk_version();
        assert!(v.split('.').count() >= 2);
    }

    #[test]
    fn detect_watermark_empty_text_returns_zero() {
        let out = detect_watermark_native("").unwrap();
        assert!(!out.detected);
        assert_eq!(out.total_count, 0);
        assert_eq!(out.green_count, 0);
    }

    #[test]
    fn detect_watermark_long_random_text_is_not_detected() {
        // 5000 ASCII bytes of pseudo-random data; with gamma=0.25 and
        // the fixed default key, the z-score should be well below 4.
        let bytes: Vec<u8> = (0..5000u32)
            .map(|i| (((i as u64).wrapping_mul(1103515245).wrapping_add(12345)) >> 16) as u8 & 0x7F)
            .collect();
        let text = String::from_utf8(bytes).unwrap();
        let out = detect_watermark_native(&text).unwrap();
        assert!(
            !out.detected,
            "z={} green={}/{}",
            out.z_score, out.green_count, out.total_count
        );
        assert_eq!(out.total_count, 5000);
    }

    #[test]
    fn detect_watermark_rejects_bad_gamma() {
        // gamma out of (0, 1) must error.
        let mut key = [0u8; 32];
        key[0] = 1;
        assert!(detect_watermark_pure("hello", &key, 0.0, 4.0).is_err());
        assert!(detect_watermark_pure("hello", &key, 1.0, 4.0).is_err());
    }
}
