//! `tl-context` - TrustLayer INV-15 verifier + Z3 proof wrapper.
//!
//! Absorbed from `Apohara_Context_Forge` per Plan v3.0 W3.2 (roadmap v3).
//! The original ContextForge project ships a Python-only INV-15 verifier
//! (regex sweep) and a Z3 SMT formal proof (UNSAT in 10.08 ms). This crate
//! re-homes those capabilities as native Rust, so TrustLayer can verify
//! prompt-injection attempts and certify INV-15 compliance without a
//! Python dependency.

pub mod z3_inv15;

pub use z3_inv15::{
    compute_risk_score as compute_inv15_risk_score,
    compute_use_dense_prefill as compute_inv15_use_dense_prefill,
    find_counterexample_relaxed as find_inv15_counterexample_relaxed,
    inv15_antecedent, prove_inv15 as prove_inv15_z3, Counterexample as Inv15Counterexample,
    Z3Inv15Result as Inv15Z3Result,
};
