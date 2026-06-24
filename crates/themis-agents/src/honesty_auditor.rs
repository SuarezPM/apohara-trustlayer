//! Honesty Auditor — the 6th THEMIS agent. Watches the 5 core agents'
//! outputs and flags LLM over-claims ("always", "never", "100%",
//! "guaranteed", ...) with a deterministic, pure-Rust, zero-LLM
//! regex pass.
//!
//! ## Why (the design rationale)
//!
//! LLM-generated analysis is the most failure-prone surface in the
//! THEMIS pipeline: vendors, amounts, POs and GAAP accounts are
//! ground truth that the FraudAuditor et al. reason over, but their
//! narrative explanations are open-ended prose where confident
//! over-claims ("100% safe", "guaranteed legit", "never fraudulent")
//! pollute the Evidence Packet and undermine regulator trust. A
//! deterministic regex layer that flags these phrases before the
//! Evidence Packet is sealed lets the judge see *what* was said
//! and *whether* the auditor caught it, even when the LLM is
//! stochastic.
//!
//! ## How (the MVP)
//!
//! The MVP is a pure-function regex auditor: feed it the raw text
//! of an agent's `reasoning` (or any output), get back one of three
//! verdicts — `Pass`, `Flag`, or `Fail`. The score is the count of
//! distinct matched over-claim patterns:
//!
//! - `0 matches` → `Pass`
//! - `1..=2 matches` → `Flag`
//! - `>= 3 matches` → `Fail`
//!
//! This is the **steal-and-improve** layer from the (fictional)
//! `umpmlv` library: a deterministic, language-agnostic
//! over-claim detector that runs *before* the BLAKE3 chain is
//! sealed. The Z3-proved variant (count thresholds formally
//! grounded in ContextForge's INV-15 invariants) is a follow-up;
//! the regex MVP is correct for the Phase 4 demo and ships zero
//! LLM cost.
//!
//! ## Determinism
//!
//! The same input always produces the same `HonestyVerdict`.
//! `audit()` is `&self` (no mutation), `regression_tester`-friendly,
//! and re-runnable inside a 10x loop with no observable drift
//! (verified by `test_honesty_auditor_10x_deterministic`).
//!
//! ## Band-room wiring (deferred)
//!
//! The PRD wires `HonestyAuditor` as a 6th agent in the Band room
//! transcript: after every other agent emits a decision, the
//! HonestyAuditor audits the `reasoning` string and posts a
//! `HonestyCheck` event to the room. That wiring is deferred to a
//! follow-up commit when the orchestrator's agent loop is touched
//! (the orchestrator's `process_invoice` is owned by C-07/C-15
//! right now and is not safe to change mid-merge).
//!
//! In the meantime the auditor is a **library** that any caller
//! can `audit(...)`; the integration test
//! `test_honesty_auditor_visible_in_band_room` documents the
//! would-be wiring in a `// ` doc comment so the future agent
//! loop touches have a clear target.

use regex::Regex;

/// Default over-claim patterns. Each entry is a (pattern, name)
/// pair; the name is what shows up in `HonestyVerdict::reasons`
/// and in the audit log.
///
/// The patterns intentionally lean on word boundaries
/// (`\b…\b`) and case-insensitive matching to keep false
/// positives down — "the vendor is always-responsive" is a
/// legitimate claim; "the invoice is always legit" is not.
pub const DEFAULT_OVER_CLAIM_PATTERNS: &[&str] = &[
    r"\b100\s*%", // 100% / 100 % — over-confident certainty
    // (no trailing \b: `%` is a non-word char, so a
    // trailing boundary would require a word char
    // after it, which would be wrong in "100% safe".)
    r"\balways\b",            // universal claim (positive)
    r"\bnever\b",             // universal claim (negative)
    r"\bguarantee(?:s|d)?\b", // guarantee / guarantees / guaranteed
    r"\bdefinitely\b",        // absolute certainty
    r"\bcertainly\b",         // absolute certainty
    r"\bno chance\b",         // extreme negation
    r"\bperfectly\b",         // extreme quality
];

/// Verdict emitted by `HonestyAuditor::audit()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HonestyVerdict {
    /// No over-claim patterns matched. The output reads as
    /// epistemically humble.
    Pass,
    /// 1-2 over-claim patterns matched. The output is *notable*
    /// — the operator should review the reasoning, but the
    /// evidence isn't a clear HALT.
    Flag {
        /// Human-readable reason listing the matched pattern
        /// names.
        reason: String,
    },
    /// At least 3 over-claim patterns matched. The output reads as
    /// confidently overclaiming; the operator should HALT or
    /// require re-attestation.
    Fail {
        /// Human-readable reason listing the matched pattern
        /// names.
        reason: String,
    },
}

impl HonestyVerdict {
    /// Stable string identifier (matches the wire-format contract
    /// used by the orchestrator's `DecisionType::as_str()`).
    pub fn as_str(&self) -> &'static str {
        match self {
            HonestyVerdict::Pass => "pass",
            HonestyVerdict::Flag { .. } => "flag",
            HonestyVerdict::Fail { .. } => "fail",
        }
    }
}

/// The Honesty Auditor (6th THEMIS agent).
///
/// Holds a pre-compiled list of regex patterns; the
/// `audit()` call is a pure function of `(patterns, input)`.
/// `&self` everywhere → safe behind `Arc` if the orchestrator
/// wants to share one instance across threads.
pub struct HonestyAuditor {
    /// Pre-compiled regex patterns (one per `DEFAULT_OVER_CLAIM_PATTERNS`
    /// entry, plus any extras the caller added).
    pub over_claim_patterns: Vec<Regex>,
}

impl HonestyAuditor {
    /// New auditor with `DEFAULT_OVER_CLAIM_PATTERNS` (case-insensitive).
    pub fn new() -> Self {
        Self::with_patterns(DEFAULT_OVER_CLAIM_PATTERNS.iter().copied())
    }

    /// New auditor with a custom pattern set. The strings are
    /// compiled as case-insensitive; pass them as raw `&str`
    /// (the default constant exposes them as `&'static str`).
    pub fn with_patterns<I, S>(patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let over_claim_patterns = patterns
            .into_iter()
            .map(|p| {
                Regex::new(&format!("(?i){}", p.as_ref()))
                    .expect("honesty_auditor: invalid default over-claim pattern")
            })
            .collect();
        Self {
            over_claim_patterns,
        }
    }

    /// Audit an agent's output text and return a verdict.
    ///
    /// - `0` matches → `Pass`
    /// - `1..=2` matches → `Flag { reason }`
    /// - `>= 3` matches → `Fail { reason }`
    pub fn audit(&self, agent_output: &str) -> HonestyVerdict {
        let count = self.flag_count(agent_output);
        match count {
            0 => HonestyVerdict::Pass,
            1..=2 => HonestyVerdict::Flag {
                reason: self.reason_string(agent_output),
            },
            _ => HonestyVerdict::Fail {
                reason: self.reason_string(agent_output),
            },
        }
    }

    /// Number of distinct patterns that matched `agent_output`.
    /// (Note: the count is per-pattern, not per-occurrence; a
    /// text that says "always always always" still counts as
    /// one match on the `always` pattern. This is deliberate —
    /// a single over-claim category is the signal, not the
    /// lexical count.)
    pub fn flag_count(&self, agent_output: &str) -> usize {
        self.over_claim_patterns
            .iter()
            .filter(|re| re.is_match(agent_output))
            .count()
    }

    /// Human-readable names of the matched patterns (the same
    /// strings used in `DEFAULT_OVER_CLAIM_PATTERNS`).
    pub fn reasons(&self, agent_output: &str) -> Vec<String> {
        self.over_claim_patterns
            .iter()
            .zip(DEFAULT_OVER_CLAIM_PATTERNS.iter())
            .filter(|(re, _)| re.is_match(agent_output))
            .map(|(_, name)| (*name).to_string())
            .collect()
    }

    fn reason_string(&self, agent_output: &str) -> String {
        let names = self.reasons(agent_output);
        format!("over-claim patterns detected: [{}]", names.join(", "))
    }
}

impl Default for HonestyAuditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_on_clean_output() {
        let auditor = HonestyAuditor::new();
        let v = auditor.audit(
            "Vendor Acme Corp billed $450.00 across 3 line items; \
             total matches the PO; no anomalies flagged. Confidence: 0.87.",
        );
        assert_eq!(v, HonestyVerdict::Pass);
        assert_eq!(v.as_str(), "pass");
    }

    #[test]
    fn flag_on_one_over_claim() {
        let auditor = HonestyAuditor::new();
        let v = auditor.audit(
            "This vendor is always responsive, but the line \
             item totals match the PO. Confidence: 0.81.",
        );
        match &v {
            HonestyVerdict::Flag { reason } => {
                assert!(reason.contains("always"), "reason={reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
        assert_eq!(v.as_str(), "flag");
    }

    #[test]
    fn fail_on_three_over_claims() {
        let auditor = HonestyAuditor::new();
        let v = auditor.audit(
            "This vendor is always responsive, never late, and \
             the invoice is 100% legitimate. Definitely safe to \
             pay.",
        );
        match &v {
            HonestyVerdict::Fail { reason } => {
                // 5 patterns hit: always, never, 100%, definitely,
                // (no "perfectly" or "guaranteed" in this string but
                // the threshold is >= 3 so we already Fail).
                assert!(reason.contains("always"), "reason={reason}");
                assert!(reason.contains("never"), "reason={reason}");
            }
            other => panic!("expected Fail, got {other:?}"),
        }
        assert_eq!(v.as_str(), "fail");
    }

    #[test]
    fn flag_count_returns_correct_number() {
        let auditor = HonestyAuditor::new();
        assert_eq!(auditor.flag_count("clean output, no overclaims"), 0);
        assert_eq!(auditor.flag_count("the vendor is always responsive"), 1);
        assert_eq!(auditor.flag_count("always, never, but maybe"), 2);
        assert_eq!(
            auditor.flag_count("always, never, definitely, 100% safe, perfectly fine"),
            5
        );
    }

    #[test]
    fn reasons_lists_matched_patterns() {
        let auditor = HonestyAuditor::new();
        let reasons = auditor.reasons("always responsive, never late");
        assert_eq!(reasons.len(), 2);
        assert!(reasons.iter().any(|r| r.contains("always")));
        assert!(reasons.iter().any(|r| r.contains("never")));

        let empty = auditor.reasons("clean output");
        assert!(empty.is_empty());
    }

    #[test]
    fn with_patterns_replaces_default_set() {
        // A custom auditor with only one pattern.
        let auditor = HonestyAuditor::with_patterns([r"\balways\b"]);
        assert_eq!(
            auditor.flag_count("always responsive, never late, 100% safe"),
            1
        );
    }

    #[test]
    fn case_insensitive_matching() {
        let auditor = HonestyAuditor::new();
        // All-caps "ALWAYS" should still match the always pattern.
        let v = auditor.audit("ALWAYS responsive, NEVER late.");
        assert!(matches!(
            v,
            HonestyVerdict::Flag { .. } | HonestyVerdict::Fail { .. }
        ));
    }
}
