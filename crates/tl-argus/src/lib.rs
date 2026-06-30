//! tl-argus — absorbed from apohara-argus (Plan v3.0 W3.1)
//!
//! This crate ports three concerns from the ARGUS collective into
//! TrustLayer, without pulling in any of the argus-* crates:
//!
//! - [`specialists`] — the 4 specialist module interfaces
//!   (`aegis-slop`, `aegis-security`, `aegis-arch`, `aegis-verdict`).
//!   Ported trait surface + report types. The LLM runtime lives in
//!   the consumer; here we only ship the contracts.
//! - [`cordon`] — the **CordonEnforcer pattern** (the moat): the
//!   runtime guard that ensures the verdict synthesizer NEVER sees
//!   raw code. Only the structured outputs of the other 3 specialists.
//! - [`audit_event`] — the 16-field EU AI Act Art. 12 audit record
//!   (Level 2 conformance per `certifieddata/ai-decision-logging-spec`
//!   April 2026). BLAKE3 fingerprints only — GDPR-safe by construction.

#![warn(missing_docs)]

pub mod audit_event;
pub mod cordon;
pub mod specialists;

#[cfg(test)]
mod tests;

pub use audit_event::{
    blake3_fingerprint, hex_bytes, hex_signature, next_prev_hash, AuditEvent, DataClass,
    DecisionArtifact, ToolCallRecord,
};
pub use cordon::{Constraint, ContextRequirement, CordonEnforcer, CordonError};
pub use specialists::{
    extract_json, ArchConcern, ArchReport, ArchitectureFit, RiskScore, SecurityFinding,
    SecurityReport, SecurityReview, SecuritySeverity, SlopDetector, SlopError, SlopExample,
    SlopReport, Specialist, SynthesizerInput, Verdict, VerdictStatus, VerdictSynthesizer,
};
