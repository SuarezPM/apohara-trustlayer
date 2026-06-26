//! `tl-context` - TrustLayer INV-15 verifier + Z3 proof wrapper.
//!
//! Absorbed from `Apohara_Context_Forge` per Plan v3.0 W3.2 + W3.5 (roadmap v3).
//! The original ContextForge project ships a Python-only INV-15 verifier
//! (regex sweep) and a Z3 SMT formal proof (UNSAT in 10.08 ms). This crate
//! re-homes those capabilities as native Rust, so TrustLayer can verify
//! prompt-injection attempts and certify INV-15 compliance without a
//! Python dependency.
//!
//! ## Modules
//!
//! - [`inv15`] (W3.2) - the 5-category prompt-injection regex verifier
//!   (GoalOverride / SystemOverride / RoleImpersonation /
//!   SecretExtraction / Jailbreak) with 0.8 Block / 0.5 Warn thresholds.
//! - [`context`] (W3.2) - the [`context::InvocationContext`] struct +
//!   [`context::ContextBudget`], i.e. "what the agent had when it made a
//!   decision" (KV-cache state, candidate set, layout flags).
//! - [`proof`] (W3.2) - the Z3 SMT proof wrapper. Embeds the UNSAT result
//!   (`elapsed_ms = 10.08`, `z3_version = 4.16.0`) for the canonical
//!   antecedent and exposes a runtime API for re-proving if the
//!   `z3_inv15_proof.py` script is available on disk.
//! - [`z3_inv15`] (W3.5) - the Rust port of the Z3 risk model + the
//!   `prove_inv15()` function. Mirrors the Python decision logic 1:1.

pub mod context;
pub mod inv15;
pub mod proof;
pub mod z3_inv15;

pub use z3_inv15::{
    compute_risk_score as compute_inv15_risk_score,
    compute_use_dense_prefill as compute_inv15_use_dense_prefill,
    find_counterexample_relaxed as find_inv15_counterexample_relaxed,
    inv15_antecedent, prove_inv15 as prove_inv15_z3,
    Counterexample as Inv15Counterexample, Z3Inv15Result as Inv15Z3Result,
};

#[cfg(test)]
mod tests;

/// Crate version + name.
pub fn version() -> &'static str {
    "tl-context"
}

/// The Z3 version (4.16.0) used to generate the canonical proof.
/// Hardcoded so dependents can pin against it without calling Z3.
pub const Z3_VERSION: &str = "4.16.0";

/// The elapsed_ms of the canonical Z3 proof (UNSAT in 10.08 ms,
/// mean over 10 runs per the v6.0 paper). Embedded so downstream
/// auditors can verify the proven invariant without re-running Z3.
pub const Z3_PROOF_ELAPSED_MS: f64 = 10.08;

/// The INV-15 theorem string, used as the `theorem` field in
/// [`proof::Z3ProofResult`].
pub const INV15_THEOREM: &str = "INV-15-DENSE-PREFILL";

#[cfg(test)]
mod lib_tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "tl-context");
    }

    #[test]
    fn constants_match_v6_paper() {
        // Regression guard against accidental edits to the embedded proof metadata.
        assert_eq!(Z3_VERSION, "4.16.0");
        assert!((Z3_PROOF_ELAPSED_MS - 10.08).abs() < f64::EPSILON);
        assert_eq!(INV15_THEOREM, "INV-15-DENSE-PREFILL");
    }
}
