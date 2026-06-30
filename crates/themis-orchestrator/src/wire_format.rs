//! `FlattenedPacketWireFormat` — the public 20+ field JSON shape that
//! `tl-verify`'s `PacketFile` deserializes and the judge / third-party
//! verifier consumes.
//!
//! Extracted from `http.rs::get_packet_json` in P4.4 to replace the
//! 200-line hand-built `serde_json::Map` with a typed struct +
//! `serde::Serialize` derive. The handler now reads ~15 lines:
//!
//! ```ignore
//! let wire = FlattenedPacketWireFormat::from_signed(&packet, sealed.as_deref());
//! let bytes = serde_json::to_vec_pretty(&wire)?;
//! ```
//!
//! Wire format field reference (matches `fixtures/sample_packet.json`):
//!
//! | field                  | source                                                    |
//! |------------------------|-----------------------------------------------------------|
//! | `case_id`              | `"{tenant}:{invoice}"`                                     |
//! | `tenant_id`            | `EvidencePacket::tenant_id`                               |
//! | `decision_id`          | `EvidencePacket::packet_id` (UUID as string)               |
//! | `input_data`           | `EvidencePacket::invoice_id`                              |
//! | `start_time`           | `generated_at_ms - 90s` (AC2's per-PR window)             |
//! | `end_time`             | `generated_at_ms` (RFC3339)                               |
//! | `policy_version`       | constant `"apohara-vouch-1"`                                |
//! | `reference_database`   | constant `"stanford-invoicenet-50"`                       |
//! | `natural_person_id`    | `VOUCH_OPERATOR_EMAIL` env var (omitted when unset)       |
//! | `hash_chain_prev`      | genesis 64-zero (single-packet chain)                     |
//! | `hash_chain_link`      | null (single-packet chain)                                |
//! | `agent_outputs`        | `Vec<AgentOutputWire>` mapped from `Vec<AgentDecision>`    |
//! | `hash`                 | `SignedPacket::blake3_hash_hex` (tl-verify's field name)   |
//! | `signature_hex`        | `SignedPacket::signature_hex`                             |
//! | `public_key_hex`       | `SignedPacket::public_key_hex`                            |
//! | `signed_payload_b64`   | base64(EvidencePacket::to_canonical_json())              |
//! | `rfc3161_ts_der_hex`   | always null (DER not preserved past seal-time, C-09)      |
//! | `rfc3161_tsa_url`      | `SealedPacket::timestamp.tsa_url` (omitted when unset)   |
//! | `c2pa_manifest`        | always null                                               |
//! | `rekor_entry`          | `SignedPacket::rekor_entry` (omitted when unset)          |

use base64::Engine;
use serde::Serialize;

use crate::packet::{EvidencePacket, SignedPacket};
use themis_agents::decision::AgentDecision;

/// Per-agent output in the wire format (`tl-verify` AgentOutput shape).
#[derive(Debug, Serialize)]
pub(crate) struct AgentOutputWire {
    pub agent_id: String,
    /// Either `"approve"` or `"halt"` (mirrors BAAAR outcome).
    pub verdict: &'static str,
    pub summary: String,
    /// Per-agent confidence (0.0..=1.0). `f32` to match
    /// `AgentDecision::confidence`'s declared type.
    pub risk_score: Option<f32>,
}

/// Public flattened wire format served by `GET /packets/:id/json`.
/// P4.4: previously hand-built as a `serde_json::Map<String, Value>`
/// with 200+ lines of `flat.insert(...)` calls. Now a typed struct
/// derived via `Serialize` — the field set is fixed, the wire
/// shape is auditable in one place, and missing/optional fields
/// are explicit (`Option` + `skip_serializing_if`).
#[derive(Debug, Serialize)]
pub(crate) struct FlattenedPacketWireFormat {
    // Identity
    pub case_id: String,
    pub tenant_id: String,
    pub decision_id: String,
    pub input_data: String,
    // Time window (RFC3339 strings; null when generated_at_ms is invalid).
    pub start_time: Option<String>,
    pub end_time: Option<String>,
    // Policy + reference data
    pub policy_version: String,
    pub reference_database: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub natural_person_id: Option<String>,
    pub hash_chain_prev: String,
    pub hash_chain_link: Option<()>,
    // Agent outputs (one entry per AgentDecision).
    pub agent_outputs: Vec<AgentOutputWire>,
    // Crypto fields
    pub hash: String,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub signed_payload_b64: String,
    // Optional / always-null fields
    pub rfc3161_ts_der_hex: Option<()>,
    pub rfc3161_tsa_url: Option<String>,
    pub c2pa_manifest: Option<()>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rekor_entry: Option<serde_json::Value>,
}

impl FlattenedPacketWireFormat {
    /// Build the wire format from a `SignedPacket` (the orchestrator's
    /// stored packet) + an optional `SealedPacket` (for the TSA URL).
    /// The `SealedPacket` is passed by reference because the handler
    /// only has a `DashMap::get` reference.
    pub(crate) fn from_signed(
        packet: &SignedPacket,
        sealed: Option<&themis_evidence::packet::SealedPacket>,
    ) -> Self {
        let p: &EvidencePacket = packet.packet();
        let end_ms = p.generated_at_ms;
        let start_ms = end_ms - 90_000;

        let verdict_str = match &p.bbaaar_outcome {
            themis_agents::baaar::Outcome::Approve => "approve",
            themis_agents::baaar::Outcome::Halt(_) => "halt",
        };

        let natural_person_id = std::env::var("VOUCH_OPERATOR_EMAIL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let signed_payload_b64 = p
            .to_canonical_json()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(&bytes))
            .unwrap_or_default();

        Self {
            case_id: format!("{}:{}", p.tenant_id, p.invoice_id),
            tenant_id: p.tenant_id.clone(),
            decision_id: p.packet_id.to_string(),
            input_data: p.invoice_id.clone(),
            start_time: to_iso(start_ms),
            end_time: to_iso(end_ms),
            policy_version: "apohara-vouch-1".to_string(),
            reference_database: "stanford-invoicenet-50".to_string(),
            natural_person_id,
            hash_chain_prev: "0".repeat(64),
            hash_chain_link: None,
            agent_outputs: map_agent_outputs(&p.agent_decisions, verdict_str),
            hash: packet.blake3_hash_hex().to_string(),
            signature_hex: packet.signature_hex().to_string(),
            public_key_hex: packet.public_key_hex().to_string(),
            signed_payload_b64,
            rfc3161_ts_der_hex: None,
            rfc3161_tsa_url: sealed
                .map(|s| s.timestamp.tsa_url.clone())
                .filter(|u| !u.is_empty()),
            c2pa_manifest: None,
            rekor_entry: packet
                .rekor_entry()
                .and_then(|e| serde_json::to_value(e).ok()),
        }
    }
}

/// Map `Vec<AgentDecision>` → `Vec<AgentOutputWire>` (one wire entry
/// per agent). The `verdict` is the pipeline-level BAAAR outcome
/// (`approve` | `halt`); the `risk_score` is the per-agent
/// confidence (None when not present).
fn map_agent_outputs(
    decisions: &[AgentDecision],
    verdict_str: &'static str,
) -> Vec<AgentOutputWire> {
    decisions
        .iter()
        .map(|d| AgentOutputWire {
            agent_id: d.agent_id.clone(),
            verdict: verdict_str,
            summary: d.reasoning.clone(),
            risk_score: Some(d.confidence),
        })
        .collect()
}

/// Convert a Unix-millisecond timestamp to RFC3339 (seconds precision,
/// Zulu). Returns `None` when the timestamp is invalid (`chrono`
/// clamps out-of-range values).
fn to_iso(ms: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}
