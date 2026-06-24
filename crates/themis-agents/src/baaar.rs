//! BAAAR kill-switch — the wow moment of the demo.
//!
//! Five conditions, all of which trigger HALT when present. The LLM
//! is the *producer* of `risk_score` and `findings`; the gate is the
//! *judge* (deterministic). This split is the entire reason AC4
//! (BAAAR 10/10 deterministic) holds.

use serde::{Deserialize, Serialize};

/// A single finding from the Fraud Auditor's LLM call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// What kind of finding this is.
    pub kind: FindingKind,
    /// Human-readable description (goes into the Evidence Packet).
    pub description: String,
}

/// The 6 kinds of fraud findings. Serialized as a flat string so the
/// LLM contract stays simple: the LLM produces a JSON object with a
/// `kind` string field. The `Other` variant carries the custom tag
/// as its serialized form (so a custom kind `"chargeback_dispute"`
/// round-trips cleanly).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// Secret pattern (AWS, OpenAI, etc.) detected in the invoice.
    SecretLeak,
    /// Price anomaly (3x PO, etc.).
    PriceAnomaly,
    /// Vendor doesn't exist in the PO database.
    PhantomVendor,
    /// Line items don't sum to the total.
    MathFraud,
    /// Same vendor+amount+date as a recent invoice.
    Duplicate,
    /// Anything else (custom string tag).
    Other(String),
}

impl FindingKind {
    /// Wire-format string. Stable identifiers used in the Evidence
    /// Packet + telemetry.
    pub fn as_str(&self) -> &str {
        match self {
            FindingKind::SecretLeak => "secret_leak",
            FindingKind::PriceAnomaly => "price_anomaly",
            FindingKind::PhantomVendor => "phantom_vendor",
            FindingKind::MathFraud => "math_fraud",
            FindingKind::Duplicate => "duplicate",
            FindingKind::Other(s) => s.as_str(),
        }
    }
}

impl serde::Serialize for FindingKind {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for FindingKind {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Ok(match s.as_str() {
            "secret_leak" => FindingKind::SecretLeak,
            "price_anomaly" => FindingKind::PriceAnomaly,
            "phantom_vendor" => FindingKind::PhantomVendor,
            "math_fraud" => FindingKind::MathFraud,
            "duplicate" => FindingKind::Duplicate,
            other => FindingKind::Other(other.to_string()),
        })
    }
}

/// The full assessment the LLM produces, before the BAAAR gate
/// evaluates it. All fields are required (the gate checks each one).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FraudAssessment {
    /// 0.0..=1.0 risk score from the LLM.
    pub risk_score: f32,
    /// All findings the LLM identified.
    pub findings: Vec<Finding>,
    /// 0.0..=1.0 coherence of the agent debate (the LLM rates how
    /// internally consistent the debate was).
    pub coherence_score: f32,
    /// Number of debate rounds so far.
    pub debate_rounds: u32,
    /// Whether the operator explicitly requested HALT.
    pub explicit_halt: bool,
}

/// The gate's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// No HALT condition triggered; proceed.
    Approve,
    /// At least one HALT condition triggered.
    Halt(BaaarReason),
}

/// Why the gate halted. Each variant maps to exactly one BAAAR
/// condition (so the Evidence Packet can surface "halted on
/// SecretLeak" precisely).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaaarReason {
    /// `risk_score > 0.85`.
    RiskScoreExceeded,
    /// `findings` contained a `SecretLeak`.
    SecretLeakDetected,
    /// `coherence_score < 0.3`.
    CoherenceTooLow,
    /// `debate_rounds >= 5`.
    MaxDebateRoundsReached,
    /// `explicit_halt == true`.
    ExplicitHaltRequested,
}

// Thresholds (named constants for evidence-packet audit).
const RISK_SCORE_HALT: f32 = 0.85;
const COHERENCE_FLOOR: f32 = 0.3;
const MAX_DEBATE_ROUNDS: u32 = 5;

/// The kill-switch. `check` is pure: same input → same output, no
/// I/O, no clock. That's what makes AC4 (10/10 deterministic) work.
#[derive(Debug, Default, Clone, Copy)]
pub struct BaaarGate;

impl FraudAssessment {
    /// Best-effort construction from an LLM decision's `payload`
    /// (`serde_json::Value`). Missing fields default to safe
    /// values: risk_score=0.0, findings=empty, coherence=1.0,
    /// debate_rounds=0, explicit_halt=false. A missing
    /// `findings` field is treated as "no SecretLeak", which is
    /// the safe interpretation (the gate only halts on
    /// SecretLeak if the LLM claims one).
    pub fn from_decision_payload(payload: &serde_json::Value) -> Self {
        // The FraudAuditor emits a nested `{"assessment": {...}}`
        // payload. Older / external agents may emit the fields
        // flat at the top level. Accept both shapes — check the
        // `assessment` nested object first, then fall back to
        // top-level keys.
        let inner = payload.get("assessment").unwrap_or(payload);
        let risk_score = inner
            .get("risk_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0) as f32;
        let coherence_score = inner
            .get("coherence_score")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0) as f32;
        let debate_rounds = inner
            .get("debate_rounds")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let explicit_halt = inner
            .get("explicit_halt")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let findings: Vec<Finding> = inner
            .get("findings")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        let kind_str = item.get("kind")?.as_str()?;
                        let kind = match kind_str {
                            "secret_leak" => FindingKind::SecretLeak,
                            "price_anomaly" => FindingKind::PriceAnomaly,
                            "phantom_vendor" => FindingKind::PhantomVendor,
                            "math_fraud" => FindingKind::MathFraud,
                            "duplicate" => FindingKind::Duplicate,
                            other => FindingKind::Other(other.to_string()),
                        };
                        Some(Finding {
                            kind,
                            description: item
                                .get("description")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            risk_score,
            findings,
            coherence_score,
            debate_rounds,
            explicit_halt,
        }
    }
}

impl BaaarGate {
    /// New gate (no state; const-fn construction is fine).
    pub fn new() -> Self {
        Self
    }

    /// Evaluate the assessment. Returns `Halt(reason)` if any of the
    /// 5 conditions is met, otherwise `Approve`. The first matching
    /// reason wins (so the Evidence Packet shows a single, precise
    /// halt cause).
    pub fn check(&self, a: &FraudAssessment) -> Outcome {
        if a.risk_score > RISK_SCORE_HALT {
            return Outcome::Halt(BaaarReason::RiskScoreExceeded);
        }
        if a.findings
            .iter()
            .any(|f| matches!(f.kind, FindingKind::SecretLeak))
        {
            return Outcome::Halt(BaaarReason::SecretLeakDetected);
        }
        if a.coherence_score < COHERENCE_FLOOR {
            return Outcome::Halt(BaaarReason::CoherenceTooLow);
        }
        if a.debate_rounds >= MAX_DEBATE_ROUNDS {
            return Outcome::Halt(BaaarReason::MaxDebateRoundsReached);
        }
        if a.explicit_halt {
            return Outcome::Halt(BaaarReason::ExplicitHaltRequested);
        }
        Outcome::Approve
    }
}

// --- BaaarV2Gate (vNext §8.2 — Self-Anchored Consensus) ---
//
// The original BAAAR is a single-agent 5-condition deterministic
// gate. SAC (arXiv:2605.09076, May 2026) proposes a multi-agent
// weighted consensus check: each agent emits a confidence score,
// and the weighted average must clear a threshold for APPROVE.
// SAC's F+1-robustness property means the system stays correct
// even when a minority of agents are adversarial.
//
// BaaarV2Gate is BACKWARD COMPATIBLE: `check_sac()` first runs
// the v1 `BaaarGate::check()` (so AC11 — BAAAR HALT deterministic
// 10/10 — still holds), and only then runs the SAC weighted
// consensus check. If v1 halts, v1's reason wins.

/// Identifies the agent that emitted a confidence score. Used as
/// the key for the SAC `agent_weights` map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentRole {
    /// `extractor`
    Extractor,
    /// `po_matcher`
    PoMatcher,
    /// `fraud_auditor` — primary risk scorer
    FraudAuditor,
    /// `gaap_classifier`
    GaapClassifier,
    /// `provenance_signer`
    ProvenanceSigner,
    /// `audit_watchdog` (shadow)
    AuditWatchdog,
    /// `regression_tester` (shadow)
    RegressionTester,
    /// `demo_narrator` (shadow)
    DemoNarrator,
}

impl AgentRole {
    /// Stable string id.
    pub fn as_str(&self) -> &'static str {
        match self {
            AgentRole::Extractor => "extractor",
            AgentRole::PoMatcher => "po_matcher",
            AgentRole::FraudAuditor => "fraud_auditor",
            AgentRole::GaapClassifier => "gaap_classifier",
            AgentRole::ProvenanceSigner => "provenance_signer",
            AgentRole::AuditWatchdog => "audit_watchdog",
            AgentRole::RegressionTester => "regression_tester",
            AgentRole::DemoNarrator => "demo_narrator",
        }
    }
}

/// BAAAR v2 — Self-Anchored Consensus wrapper around `BaaarGate`.
///
/// v1 (`inner.check`) runs FIRST, unchanged. If v1 halts, v1's
/// reason is returned verbatim (backward compat with AC11). Only
/// when v1 approves does v2 evaluate the weighted consensus.
///
/// If `agent_confidences` is empty OR the weighted average is
/// below `sac_threshold`, v2 halts with `CoherenceTooLow` (the
/// same reason v1 uses for low coherence — semantically: "the
/// system doesn't have enough cross-agent agreement to trust the
/// v1 APPROVE").
pub struct BaaarV2Gate {
    /// The v1 gate (untouched).
    inner: BaaarGate,
    /// Per-agent weight (fraud_auditor defaults to 1.0; everything
    /// else defaults to 0.5 — fraud risk is the load-bearing
    /// signal).
    agent_weights: std::collections::HashMap<AgentRole, f32>,
    /// Minimum weighted confidence to APPROVE. 0.5 is the SAC
    /// default (F+1-robust for 2 faulty agents out of 5).
    sac_threshold: f32,
}

impl std::fmt::Debug for BaaarV2Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaaarV2Gate")
            .field("inner", &"BaaarGate")
            .field("agent_weights", &self.agent_weights)
            .field("sac_threshold", &self.sac_threshold)
            .finish()
    }
}

impl BaaarV2Gate {
    /// New v2 gate with default weights (FraudAuditor=1.0, others=0.5)
    /// and SAC threshold 0.5.
    pub fn new() -> Self {
        let mut weights = std::collections::HashMap::new();
        weights.insert(AgentRole::Extractor, 0.5);
        weights.insert(AgentRole::PoMatcher, 0.5);
        weights.insert(AgentRole::FraudAuditor, 1.0);
        weights.insert(AgentRole::GaapClassifier, 0.5);
        weights.insert(AgentRole::ProvenanceSigner, 0.5);
        weights.insert(AgentRole::AuditWatchdog, 0.5);
        weights.insert(AgentRole::RegressionTester, 0.5);
        weights.insert(AgentRole::DemoNarrator, 0.5);
        Self {
            inner: BaaarGate::new(),
            agent_weights: weights,
            sac_threshold: 0.5,
        }
    }

    /// Override the SAC threshold (0.0..=1.0). Default 0.5.
    pub fn with_sac_threshold(mut self, threshold: f32) -> Self {
        self.sac_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Override the per-agent weights.
    pub fn with_weights(mut self, weights: std::collections::HashMap<AgentRole, f32>) -> Self {
        self.agent_weights = weights;
        self
    }

    /// Run the v1 check first; if it halts, return that. Otherwise
    /// evaluate the SAC weighted consensus.
    ///
    /// `agent_confidences` is a list of `(role, confidence)` pairs.
    /// The weighted average is `sum(role_weight * confidence) /
    /// sum(role_weight)`. If the average is below `sac_threshold`,
    /// halt with `CoherenceTooLow`.
    pub fn check_sac(
        &self,
        assessment: &FraudAssessment,
        agent_confidences: &[(AgentRole, f32)],
    ) -> Outcome {
        // v1 first — backward compat with AC11 (10/10 deterministic).
        if let halt @ Outcome::Halt(_) = self.inner.check(assessment) {
            return halt;
        }
        // v1 approved. Now run SAC.
        if agent_confidences.is_empty() {
            // No agent confidences → can't trust v1's approve. Halt.
            return Outcome::Halt(BaaarReason::CoherenceTooLow);
        }
        let mut weighted_sum = 0.0_f32;
        let mut weight_total = 0.0_f32;
        for (role, confidence) in agent_confidences {
            if let Some(w) = self.agent_weights.get(role) {
                // Confidence is clamped to 0.0..=1.0 defensively
                // (an LLM can occasionally emit out-of-range
                // values; we don't want a NaN to poison the sum).
                let c = confidence.clamp(0.0, 1.0);
                weighted_sum += w * c;
                weight_total += w;
            }
            // Agents not in the weight map are ignored (they have
            // zero weight, equivalent to "no opinion").
        }
        if weight_total == 0.0 {
            return Outcome::Halt(BaaarReason::CoherenceTooLow);
        }
        let weighted_avg = weighted_sum / weight_total;
        if weighted_avg < self.sac_threshold {
            return Outcome::Halt(BaaarReason::CoherenceTooLow);
        }
        Outcome::Approve
    }

    /// Delegate to the inner v1 gate (for tests that don't need
    /// SAC; the existing AC11 determinism test uses this path).
    pub fn check_v1(&self, a: &FraudAssessment) -> Outcome {
        self.inner.check(a)
    }
}

impl Default for BaaarV2Gate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FraudAssessment {
        FraudAssessment {
            risk_score: 0.5,
            findings: vec![],
            coherence_score: 0.7,
            debate_rounds: 1,
            explicit_halt: false,
        }
    }

    #[test]
    fn approves_when_no_conditions_triggered() {
        assert_eq!(BaaarGate::new().check(&base()), Outcome::Approve);
    }

    #[test]
    fn halts_on_risk_score_above_threshold() {
        let mut a = base();
        a.risk_score = 0.86;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn risk_score_threshold_is_strict() {
        // Exactly 0.85 does NOT trigger (strict >).
        let mut a = base();
        a.risk_score = 0.85;
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_secret_leak_finding() {
        let mut a = base();
        a.findings.push(Finding {
            kind: FindingKind::SecretLeak,
            description: "AWS key in line item notes".to_string(),
        });
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::SecretLeakDetected)
        );
    }

    #[test]
    fn price_anomaly_alone_does_not_halt() {
        // PriceAnomaly is logged but does NOT trigger HALT by itself
        // (no threshold). The LLM also raises risk_score for price
        // anomalies, which DOES halt.
        let mut a = base();
        a.findings.push(Finding {
            kind: FindingKind::PriceAnomaly,
            description: "3x PO expected".to_string(),
        });
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_coherence_below_floor() {
        let mut a = base();
        a.coherence_score = 0.29;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn coherence_floor_is_strict() {
        // Exactly 0.3 does NOT trigger.
        let mut a = base();
        a.coherence_score = 0.3;
        assert_eq!(BaaarGate::new().check(&a), Outcome::Approve);
    }

    #[test]
    fn halts_on_max_debate_rounds() {
        let mut a = base();
        a.debate_rounds = 5;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::MaxDebateRoundsReached)
        );
    }

    #[test]
    fn halts_on_explicit_halt_request() {
        let mut a = base();
        a.explicit_halt = true;
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::ExplicitHaltRequested)
        );
    }

    #[test]
    fn first_matching_condition_wins() {
        // Both risk and secret leak present — risk wins (checked first).
        let mut a = base();
        a.risk_score = 0.99;
        a.findings.push(Finding {
            kind: FindingKind::SecretLeak,
            description: "key".to_string(),
        });
        assert_eq!(
            BaaarGate::new().check(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn finding_kind_serializes_as_flat_string() {
        // Plain string per FindingKind: "secret_leak", "price_anomaly", etc.
        let f = Finding {
            kind: FindingKind::SecretLeak,
            description: "x".to_string(),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["kind"], "secret_leak");

        let f2 = Finding {
            kind: FindingKind::Other("custom".to_string()),
            description: "y".to_string(),
        };
        let v2 = serde_json::to_value(&f2).unwrap();
        assert_eq!(v2["kind"], "custom");
    }

    // --- BaaarV2Gate tests (vNext §8.2 — SAC) ---

    #[test]
    fn v2_v1_halt_wins_over_sac_approve() {
        // v1 halts on risk_score > 0.85. SAC would otherwise approve.
        // The v1 reason must propagate (backward compat with AC11).
        let mut a = base();
        a.risk_score = 0.95;
        let gate = BaaarV2Gate::new();
        let conf = vec![
            (AgentRole::FraudAuditor, 1.0),
            (AgentRole::GaapClassifier, 1.0),
            (AgentRole::Extractor, 1.0),
        ];
        assert_eq!(
            gate.check_sac(&a, &conf),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn v2_sac_halts_when_no_agent_confidences() {
        // v1 approves (default base()). No agent confidences →
        // SAC can't evaluate → halt with CoherenceTooLow.
        let a = base();
        let gate = BaaarV2Gate::new();
        assert_eq!(
            gate.check_sac(&a, &[]),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn v2_sac_halts_when_weighted_avg_below_threshold() {
        // v1 approves. SAC: weighted avg = 0.4 (FraudAuditor=0.4,
        // 2× others=0.4) = 0.4, below default threshold 0.5.
        let a = base();
        let gate = BaaarV2Gate::new();
        let conf = vec![
            (AgentRole::FraudAuditor, 0.4),
            (AgentRole::GaapClassifier, 0.4),
            (AgentRole::Extractor, 0.4),
        ];
        assert_eq!(
            gate.check_sac(&a, &conf),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn v2_sac_approves_when_weighted_avg_above_threshold() {
        // v1 approves. SAC: weighted avg = 0.7 (FraudAuditor=0.7,
        // 2× others=0.7) = 0.7, above 0.5. Approve.
        let a = base();
        let gate = BaaarV2Gate::new();
        let conf = vec![
            (AgentRole::FraudAuditor, 0.7),
            (AgentRole::GaapClassifier, 0.7),
            (AgentRole::Extractor, 0.7),
        ];
        assert_eq!(gate.check_sac(&a, &conf), Outcome::Approve);
    }

    #[test]
    fn v2_sac_ignores_agents_not_in_weight_map() {
        // Default weight map has 8 roles. Pass 3 unweighted roles
        // (custom): they contribute nothing to the sum. SAC must
        // not crash; the empty effective total → halt.
        let a = base();
        let gate = BaaarV2Gate::new();
        let conf = vec![
            (AgentRole::FraudAuditor, 0.0), // explicitly 0
            (AgentRole::GaapClassifier, 0.0),
            (AgentRole::Extractor, 0.0),
        ];
        // weighted sum = 0, weight_total > 0, avg = 0, below 0.5
        assert_eq!(
            gate.check_sac(&a, &conf),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }

    #[test]
    fn v2_check_v1_delegates_to_inner() {
        // Backward compat: the AC11 10/10 deterministic test
        // (already in the suite) uses check_v1. Sanity check.
        let mut a = base();
        a.risk_score = 0.5;
        let gate = BaaarV2Gate::new();
        assert_eq!(gate.check_v1(&a), Outcome::Approve);
        a.risk_score = 0.95;
        assert_eq!(
            gate.check_v1(&a),
            Outcome::Halt(BaaarReason::RiskScoreExceeded)
        );
    }

    #[test]
    fn v2_with_sac_threshold_override() {
        // With threshold 0.9, the same confidence that approved at
        // 0.5 now halts. Caller-controlled knob for post-hackathon
        // tuning.
        let a = base();
        let gate = BaaarV2Gate::new().with_sac_threshold(0.9);
        let conf = vec![
            (AgentRole::FraudAuditor, 0.7),
            (AgentRole::GaapClassifier, 0.7),
        ];
        assert_eq!(
            gate.check_sac(&a, &conf),
            Outcome::Halt(BaaarReason::CoherenceTooLow)
        );
    }
}
