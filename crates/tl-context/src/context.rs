//! [`InvocationContext`] - "what the agent had when it made a decision".
//!
//! Absorbed from `Apohara_Context_Forge`'s `JCRSafetyGate` input domain
//! (Plan v3.0 W3.2). The struct captures every input the gate observed
//! for a single agent invocation: role, candidate set, KV-cache reuse
//! rate, layout-shuffled flag, and the dense-prefill decision. Together
//! with [`ContextBudget`] (the resource ceiling for the invocation),
//! these are the canonical inputs the INV-15 proof quantifies over.

use blake3::Hash;
use serde::{Deserialize, Serialize};

/// Roles considered "judge-type" by INV-15. Per the paper
/// (arXiv:2601.08343), J = `{critic, judge}`: both get dense prefill
/// when risky. Mirrors `JUDGE_ROLES` in `Apohara_Context_Forge.safety.jcr_gate`.
pub const JUDGE_ROLES: &[&str] = &["critic", "judge"];

/// Default JCR risk threshold above which dense prefill is mandated.
/// Mirrors `DEFAULT_JCR_THRESHOLD = 0.7` in `jcr_gate.py`.
pub const DEFAULT_JCR_THRESHOLD: f32 = 0.7;

/// The JCR risk score for an upcoming agent step. Returned by
/// [`InvocationContext::compute_jcr_risk`]. Higher means KV reuse is
/// more likely to corrupt the judge's verdict. Range: `[0.0, 1.0]`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct JcrRiskScore(pub f32);

impl JcrRiskScore {
    /// True iff the score exceeds the JCR threshold (mandates dense prefill
    /// for judge-class roles).
    pub fn exceeds(&self, threshold: f32) -> bool {
        self.0 > threshold
    }
}

/// The full snapshot of what the agent had when it made a decision.
///
/// This is the canonical input for INV-15: when serialized and
/// hashed (BLAKE3 via [`InvocationContext::content_hash`]), the result
/// can be included in an evidence packet so auditors can re-verify the
/// dense-prefill decision post-hoc.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationContext {
    /// Agent role (e.g. `"critic"`, `"judge"`, `"retriever"`). Lowercased
    /// at construction time; the verifier is case-insensitive.
    pub agent_role: String,

    /// Number of candidates the agent jointly compared (Critic: the
    /// candidate set; Judge: the verdict options). Must be `>= 0`.
    pub candidate_count: u32,

    /// Fraction of the KV cache reused from a prior round, in `[0.0, 1.0]`.
    /// A high reuse rate on a judge-type agent is the failure mode INV-15
    /// protects against.
    pub reuse_rate: f32,

    /// Whether the candidate order was shuffled since the last round.
    /// Triggers the `_RISK_LAYOUT_SHUFFLED = 0.20` weight in the gate.
    pub layout_shuffled: bool,

    /// The dense-prefill decision observed for this invocation.
    /// INV-15 mandates `true` for judge-class roles whenever the risk
    /// score exceeds the threshold (strict `>`).
    pub use_dense: bool,

    /// The JCR threshold used for this invocation (defaults to
    /// [`DEFAULT_JCR_THRESHOLD`] = 0.7). Stamped into the context so
    /// threshold changes don't invalidate historical evidence.
    pub jcr_threshold: f32,

    /// The resource budget for this invocation. See [`ContextBudget`].
    pub budget: ContextBudget,
}

impl InvocationContext {
    /// Construct a new context with default [`ContextBudget`] and the
    /// default JCR threshold (0.7). Validates inputs; returns
    /// [`ContextError`] on out-of-domain values.
    pub fn new(
        agent_role: impl Into<String>,
        candidate_count: u32,
        reuse_rate: f32,
        layout_shuffled: bool,
        use_dense: bool,
    ) -> Result<Self, ContextError> {
        Self::with_budget(
            agent_role,
            candidate_count,
            reuse_rate,
            layout_shuffled,
            use_dense,
            DEFAULT_JCR_THRESHOLD,
            ContextBudget::default(),
        )
    }

    /// Construct with a custom JCR threshold and budget.
    #[allow(clippy::too_many_arguments)]
    pub fn with_budget(
        agent_role: impl Into<String>,
        candidate_count: u32,
        reuse_rate: f32,
        layout_shuffled: bool,
        use_dense: bool,
        jcr_threshold: f32,
        budget: ContextBudget,
    ) -> Result<Self, ContextError> {
        let agent_role = agent_role.into().to_lowercase();
        if !(0.0..=1.0).contains(&reuse_rate) {
            return Err(ContextError::ReuseRateOutOfRange { got: reuse_rate });
        }
        if !(0.0..=1.0).contains(&jcr_threshold) {
            return Err(ContextError::ThresholdOutOfRange { got: jcr_threshold });
        }
        Ok(Self {
            agent_role,
            candidate_count,
            reuse_rate,
            layout_shuffled,
            use_dense,
            jcr_threshold,
            budget,
        })
    }

    /// Compute the JCR risk score for this context. Mirrors
    /// `JCRSafetyGate.compute_jcr_risk` in `Apohara_Context_Forge`:
    ///
    /// - base = 0.6 if judge-class else 0.1
    /// - +0.10 per candidate beyond 2
    /// - +0.20 if `layout_shuffled`
    /// - +0.15 if `reuse_rate > 0.8`
    /// - clamp to `[0.0, 1.0]`
    pub fn compute_jcr_risk(&self) -> JcrRiskScore {
        let base = if JUDGE_ROLES.contains(&self.agent_role.as_str()) {
            0.6
        } else {
            0.1
        };
        let extra_candidates = if self.candidate_count > 2 {
            0.10 * (self.candidate_count as f32 - 2.0)
        } else {
            0.0
        };
        let shuffled = if self.layout_shuffled { 0.20 } else { 0.0 };
        let high_reuse = if self.reuse_rate > 0.8 { 0.15 } else { 0.0 };
        let risk = base + extra_candidates + shuffled + high_reuse;
        JcrRiskScore(risk.clamp(0.0, 1.0))
    }

    /// Check whether the observed `use_dense` decision matches what INV-15
    /// mandates for this context. Mirrors `inv15_certifier.certify_decision`
    /// in ContextForge: UNSAT (matches) iff the judge-class risk exceeds
    /// the threshold.
    pub fn satisfies_inv15(&self) -> bool {
        let risk = self.compute_jcr_risk();
        let is_judge = JUDGE_ROLES.contains(&self.agent_role.as_str());
        let mandated = is_judge && risk.exceeds(self.jcr_threshold);
        mandated == self.use_dense
    }

    /// BLAKE3 hash of the canonical-JSON serialization. Used to bind the
    /// invocation snapshot into an evidence packet so the dense-prefill
    /// decision can be audited post-hoc.
    pub fn content_hash(&self) -> Hash {
        let canonical = serde_json::to_vec(self).expect("InvocationContext is serializable");
        blake3::hash(&canonical)
    }
}

/// Resource budget for a single agent invocation. INV-15 is silent on
/// these (it operates over `agent_role`, `candidate_count`, `reuse_rate`,
/// `layout_shuffled`), but TrustLayer needs to record them so the
/// context snapshot is complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextBudget {
    /// Max input tokens the agent may consume. `None` = unlimited.
    pub max_input_tokens: Option<u32>,
    /// Max output tokens the agent may produce. `None` = unlimited.
    pub max_output_tokens: Option<u32>,
    /// Wall-clock budget in milliseconds. `None` = unlimited.
    pub wall_clock_ms: Option<u32>,
    /// KV-cache blocks reserved for this invocation. `None` = best-effort.
    pub kv_blocks: Option<u32>,
}

impl Default for ContextBudget {
    fn default() -> Self {
        Self {
            max_input_tokens: Some(8192),
            max_output_tokens: Some(1024),
            wall_clock_ms: Some(30_000),
            kv_blocks: None,
        }
    }
}

/// Errors emitted by [`InvocationContext`] construction.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ContextError {
    /// `reuse_rate` must be in `[0.0, 1.0]`.
    #[error("reuse_rate must be in [0.0, 1.0]; got {got}")]
    ReuseRateOutOfRange {
        /// The out-of-range value the caller passed.
        got: f32,
    },
    /// `jcr_threshold` must be in `[0.0, 1.0]`.
    #[error("jcr_threshold must be in [0.0, 1.0]; got {got}")]
    ThresholdOutOfRange {
        /// The out-of-range value the caller passed.
        got: f32,
    },
}
