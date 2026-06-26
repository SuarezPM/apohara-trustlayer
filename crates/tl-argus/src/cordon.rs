//! CordonEnforcer — the runtime guard for the **Cordon Principle**.
//!
//! The Cordon Principle (from the academic literature on
//! multi-agent LLM systems) says: a synthesis agent (the verdict
//! synthesizer) must NEVER receive raw code. It only receives the
//! structured outputs of the other specialists.
//!
//! Without this guard, the verdict synthesizer can be tricked by a
//! malicious diff into echoing attacker-controlled code, or can leak
//! proprietary source into its own context. The Cordon is the **moat**
//! of the ARGUS collective — the thing that makes "verdict from 3
//! specialists" trustworthy.
//!
//! Two enforcement modes:
//! 1. **Static** (`verify_safe_to_synthesize`) — rejects any
//!    `ContextRequirement` that is not `OtherAgentsOutputs`.
//! 2. **Dynamic** (`verify_no_raw_code_in_json`) — scans a JSON value
//!    for raw diff lines (heuristic: `+ ` / `- ` prefixes) and for
//!    `raw_code` / `raw_diff` field names.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Cordon Principle violation. Surface as a typed error so the
/// orchestrator can pick the right response (block + log vs. halt).
#[derive(Error, Debug, PartialEq, Eq)]
pub enum CordonError {
    /// A synthesis agent would have had access to raw code. Blocked.
    #[error(
        "Cordon Principle violation: a synthesis agent would have access to raw code. Blocked."
    )]
    RawCodeLeak,
    /// The agent spec is invalid (e.g. Cordon-enforced agent first
    /// in the routing plan).
    #[error("Agent spec is invalid: {0}")]
    InvalidSpec(String),
}

/// What context an agent needs to do its job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContextRequirement {
    /// Just the PR diff. Nothing else. (aegis-slop, aegis-security)
    DiffOnly,
    /// The diff + a sample of the existing repo. (aegis-arch)
    DiffPlusRepoSample,
    /// The structured outputs of other agents. **No raw code.**
    /// (aegis-verdict — the synthesizer)
    OtherAgentsOutputs,
}

/// A constraint on an agent's behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Constraint {
    /// The agent must never see raw natural-language code.
    /// Set on `aegis-verdict` to enforce the Cordon Principle.
    NoRawCode,
    /// The agent's temperature must be <= this value (for deterministic
    /// output).
    MaxTemperature(f32),
    /// The agent must produce output matching this JSON schema name.
    MustProduceJson(String),
    /// The agent must NOT make final merge decisions.
    NoMergeDecisions,
}

/// Enforces the Cordon Principle at runtime.
#[derive(Debug, Default)]
pub struct CordonEnforcer;

impl CordonEnforcer {
    /// Construct a new enforcer.
    pub fn new() -> Self {
        Self
    }

    /// Verify that the context about to be sent to a synthesizer
    /// agent is safe. **Only `OtherAgentsOutputs` is allowed.**
    pub fn verify_safe_to_synthesize(
        &self,
        context_type: &ContextRequirement,
    ) -> Result<(), CordonError> {
        match context_type {
            ContextRequirement::OtherAgentsOutputs => Ok(()),
            ContextRequirement::DiffOnly | ContextRequirement::DiffPlusRepoSample => {
                Err(CordonError::RawCodeLeak)
            }
        }
    }

    /// Scan a JSON value for raw code (heuristic: lines starting with
    /// `+ ` or `- `) and for `raw_code` / `raw_diff` field names.
    pub fn verify_no_raw_code_in_json(
        &self,
        value: &serde_json::Value,
    ) -> Result<(), CordonError> {
        Self::scan_for_raw_code(value)
    }

    fn scan_for_raw_code(value: &serde_json::Value) -> Result<(), CordonError> {
        match value {
            serde_json::Value::String(s) => {
                // Diff lines: "+ foo" / "- foo". We require both the
                // marker AND a newline so we don't false-positive on
                // a sentence like "use + for concatenation".
                if s.lines().any(|l| l.starts_with("+ ") || l.starts_with("- "))
                    && s.contains('\n')
                {
                    return Err(CordonError::RawCodeLeak);
                }
                Ok(())
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    Self::scan_for_raw_code(v)?;
                }
                Ok(())
            }
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let kl = k.to_lowercase();
                    if (kl.contains("raw") && kl.contains("code")) || kl == "raw_diff" {
                        return Err(CordonError::RawCodeLeak);
                    }
                    Self::scan_for_raw_code(v)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl Constraint {
    /// Returns `true` if this is the `NoRawCode` constraint.
    pub fn is_no_raw_code(&self) -> bool {
        matches!(self, Constraint::NoRawCode)
    }
}
