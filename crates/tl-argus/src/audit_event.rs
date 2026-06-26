//! EU AI Act Art. 12 audit-event record (16 fields, Level 2 conformance).
//!
//! `AuditEvent` is the canonical record of a single LLM call that
//! produced a decision (verdict, classification, tool invocation).
//!
//! **GDPR-safe by construction**: the cleartext prompt and response
//! are NEVER stored. Only BLAKE3 fingerprints (32 bytes each) are kept.
//!
//! **EU AI Act Art. 12 Level 2** (per `certifieddata/ai-decision-logging-spec`
//! April 2026): `data_class` and `policy_version` are required at
//! compile time. Omitting them is a compile error, not a runtime fallback.
//!
//! The 16 fields (per the apohara-argus v2 schema):
//! 1. `audit_id` 2. `timestamp` 3. `model_id` 4. `prompt_template_version`
//! 5. `prompt_fingerprint` 6. `response_fingerprint` 7. `temperature`
//! 8. `tool_calls` 9. `input_tokens` 10. `output_tokens`
//! 11. `estimated_cost_usd` 12. `data_class` 13. `policy_version`
//! 14. `decision` 15. `prev_hash` 16. `signature`

use chrono::{DateTime, Utc};
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Serde helpers for `[u8; 32]` fields. JSON has no native fixed-size
/// byte array, so we render as lowercase hex. This is the format the
/// audit pipeline + NDJSON exporter + external auditors all expect.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a 32-byte array as a lowercase hex string.
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize a 32-byte array from a lowercase hex string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex string"))
    }
}

/// 64-byte Ed25519 signature, hex-encoded for JSON portability.
pub mod hex_signature {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize a signature as a lowercase hex string.
    pub fn serialize<S: Serializer>(sig: &Signature, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(sig.to_bytes()))
    }

    /// Deserialize a signature from a lowercase hex string.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Signature, D::Error> {
        let s = String::deserialize(de)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 64] = v
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64-byte hex signature"))?;
        Ok(Signature::from_bytes(&bytes))
    }
}

/// A single tool call made during an LLM turn. Inputs/outputs are
/// hashed — the audit log stays GDPR-safe even when the tool touches
/// user data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCallRecord {
    pub tool_name: String,
    #[serde(with = "hex_bytes")]
    pub input_hash: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub output_hash: [u8; 32],
    pub latency_ms: u64,
}

/// The final structured decision an LLM turn produced.
/// `verdict` is a closed enum-ish string: `"allow"` | `"warn"` | `"block"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionArtifact {
    pub verdict: String,
    pub findings_count: u32,
    pub rationale: String,
}

/// Classification of the data the LLM call touched. Drives the
/// retention clock: `SourceCode` = 1y, `Pii`/`Phi` = 1y
/// (GDPR/HIPAA), `Contract` = 7y.
///
/// `Mixed` means the prompt contained more than one class. Callers
/// should err on the side of `Mixed` rather than `None` when in doubt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// No data class assigned yet (metadata only or test).
    None,
    /// Source code (e.g., a PR diff).
    SourceCode,
    /// Personally identifiable information (GDPR Art. 4(1)).
    Pii,
    /// Protected health information (HIPAA-style).
    Phi,
    /// Contract / legal text.
    Contract,
    /// Two or more of the above in a single prompt/response.
    Mixed,
    /// Could not classify at write time.
    Unknown,
}

/// The 16-field EU AI Act Art. 12 audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditEvent {
    /// Unique identifier (UUIDv4) — never reused.
    pub audit_id: Uuid,
    /// ISO 8601 UTC timestamp of when the LLM call completed.
    pub timestamp: DateTime<Utc>,
    /// Provider model id, e.g. `"deepseek-ai/deepseek-v4-flash"`.
    pub model_id: String,
    /// BLAKE3 hex of the prompt template `.md` file.
    pub prompt_template_version: String,
    /// BLAKE3(prompt_text). The cleartext prompt is NEVER stored (GDPR).
    #[serde(with = "hex_bytes")]
    pub prompt_fingerprint: [u8; 32],
    /// BLAKE3(raw_response). Same privacy posture.
    #[serde(with = "hex_bytes")]
    pub response_fingerprint: [u8; 32],
    /// Sampling temperature used.
    pub temperature: f32,
    /// Tool calls the LLM made during this turn.
    pub tool_calls: Vec<ToolCallRecord>,
    /// Estimated input tokens.
    pub input_tokens: u32,
    /// Estimated output tokens.
    pub output_tokens: u32,
    /// Estimated cost in USD.
    pub estimated_cost_usd: f64,
    /// What kind of data the LLM call saw (EU AI Act L2 conformance).
    pub data_class: DataClass,
    /// Semver of the active policy bundle (EU AI Act L2 conformance).
    pub policy_version: String,
    /// The decision this LLM call produced.
    pub decision: DecisionArtifact,
    /// BLAKE3 hash of the previous event in the same session chain.
    #[serde(with = "hex_bytes")]
    pub prev_hash: [u8; 32],
    /// Ed25519 signature over the canonical JSON (with sig field zeroed).
    #[serde(with = "hex_signature")]
    pub signature: Signature,
}

/// Hash the next link in the audit chain. The next event's `prev_hash`
/// is `BLAKE3(prev_hash || canonical_event)`. Tampering with any earlier
/// entry breaks every subsequent link.
pub fn next_prev_hash(prev_hash: [u8; 32], event: &AuditEvent) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&prev_hash);
    let canonical = serde_json::to_vec(event).expect("AuditEvent must serialize");
    hasher.update(&canonical);
    hasher.finalize().into()
}

/// Fingerprint raw bytes with BLAKE3 → 32-byte array.
pub fn blake3_fingerprint(data: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}
