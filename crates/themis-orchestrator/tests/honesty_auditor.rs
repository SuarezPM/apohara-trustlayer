//! Integration tests for Story C-14 — Honesty Auditor (6th agent,
//! deterministic LLM over-claim detection).
//!
//! The HonestyAuditor is a pure-Rust, zero-LLM regex pass over
//! agent outputs. The MVP sits *next* to the 5 core agents
//! (Extractor, PO Matcher, Fraud Auditor, GAAP Classifier,
//! Provenance Signer) and the 3 shadow agents (Audit Watchdog,
//! Regression Tester, Demo Narrator). It does **not** call an
//! LLM, so the test suite ships no API keys and runs in <1s.
//!
//! Determinism guarantee: `HonestyAuditor::audit()` is `&self` and
//! a pure function of the input. `test_honesty_auditor_10x_deterministic`
//! runs the same input 10 times and asserts identical verdicts
//! every time.

use themis_agents::honesty_auditor::{HonestyAuditor, HonestyVerdict, DEFAULT_OVER_CLAIM_PATTERNS};

fn auditor() -> HonestyAuditor {
    HonestyAuditor::new()
}

#[test]
fn test_honesty_auditor_full_flow() {
    // Five sample agent outputs (one per core agent), each with a
    // known over-claim footprint. The verdicts follow the
    // documented thresholds (0/1-2/3+).
    let a = auditor();

    // Extractor: clean output → Pass.
    let extractor_output = "\
        Vendor Acme Corp, amount $450.00 across 3 line items, \
        date 2026-06-01, PO-12345 matched. Confidence: 0.87.";
    assert_eq!(a.audit(extractor_output), HonestyVerdict::Pass);

    // PO Matcher: 1 over-claim ("always") → Flag.
    let po_matcher_output = "\
        PO-12345 found in registry; the vendor is always \
        responsive on the SEPA channel.";
    assert!(matches!(
        a.audit(po_matcher_output),
        HonestyVerdict::Flag { .. }
    ));

    // Fraud Auditor: 2 over-claims ("never", "100%") → Flag.
    let fraud_auditor_output = "\
        The invoice is 100% within historical price bands and the \
        vendor has never failed a compliance check. Risk: 0.4.";
    assert!(matches!(
        a.audit(fraud_auditor_output),
        HonestyVerdict::Flag { .. }
    ));

    // GAAP Classifier: 3 over-claims ("always", "definitely", "guaranteed")
    // → Fail.
    let gaap_output = "\
        Line items always map to Office Expense; the choice is \
        definitely correct, and the categorization is guaranteed \
        to satisfy ASC 230.";
    assert!(matches!(a.audit(gaap_output), HonestyVerdict::Fail { .. }));

    // Provenance Signer: 4 over-claims ("never", "always", "perfectly",
    // "no chance") → Fail.
    let provenance_output = "\
        The evidence chain is never compromised, always valid, \
        perfectly reconstructable, and there is no chance of \
        tampering. BLAKE3 hash pinned.";
    assert!(matches!(
        a.audit(provenance_output),
        HonestyVerdict::Fail { .. }
    ));
}

#[test]
fn test_honesty_auditor_10x_deterministic() {
    // The same input must produce the same verdict across 10
    // independent calls. This is the determinism guarantee the
    // PRD calls out: judges can re-run the same audit twice and
    // see the same result.
    let a = auditor();
    let input = "\
        The vendor is always responsive, never late, and the \
        invoice is 100% within historical price bands. Definitely \
        safe to pay.";

    let first = a.audit(input);
    for i in 0..10 {
        let v = a.audit(input);
        assert_eq!(
            v, first,
            "determinism violation on iteration {i}: got {v:?}, expected {first:?}"
        );
    }
}

#[test]
fn test_honesty_auditor_legit_invoice_analysis() {
    // A real-ish, well-written invoice analysis with no over-claims.
    // The honesty auditor should Pass — no over-claim patterns match.
    let a = auditor();
    let analysis = "\
        Invoice INV-2026-0042 from Stark Industries, $4,500.00, \
        dated 2026-06-01. Three line items, each with unit price \
        and quantity. PO-12345 matched: vendor, amount, and line \
        items are consistent with the PO. The vendor appears in \
        the EU transparency registry (EU-AI-ACT-2026-THEMIS-MOCK). \
        GAAP classification: Office Expense, 6420-100. Risk score: \
        0.18 (low). Confidence: 0.91. The Evidence Packet is \
        signed with the tenant's Ed25519 key (Wayne Enterprises) \
        and the BLAKE3 chain is intact across 7 links.";

    assert_eq!(a.audit(analysis), HonestyVerdict::Pass);
    assert_eq!(a.flag_count(analysis), 0);
    assert!(a.reasons(analysis).is_empty());
}

#[test]
fn test_honesty_auditor_flagged_invoice_analysis() {
    // An invoice analysis with 1-2 over-claims. The auditor should
    // Flag (not Fail, not Pass) and surface the matched pattern
    // names so the operator can review the reasoning.
    let a = auditor();
    let analysis = "\
        The vendor is always responsive and the invoice is within \
        historical price bands. Risk score: 0.22 (low).";

    match a.audit(analysis) {
        HonestyVerdict::Flag { reason } => {
            assert!(
                reason.contains("always"),
                "reason missing 'always': {reason}"
            );
        }
        other => panic!("expected Flag, got {other:?}"),
    }
    assert_eq!(a.flag_count(analysis), 1);
}

#[test]
fn test_honesty_auditor_failed_invoice_analysis() {
    // An invoice analysis with 3+ over-claims. The auditor should
    // Fail and the operator should HALT or require re-attestation.
    let a = auditor();
    let analysis = "\
        This vendor is always responsive, never late, and the \
        invoice is 100% legitimate. Definitely safe to pay. \
        Guaranteed to pass the audit.";

    match a.audit(analysis) {
        HonestyVerdict::Fail { reason } => {
            // The reason string is "over-claim patterns detected: [p1, p2, ...]"
            // where each `p` is the literal regex from `DEFAULT_OVER_CLAIM_PATTERNS`.
            // We assert on the *anchoring token* of each pattern, not the full
            // pattern body (which contains regex metachars like `\b`, `(?:`).
            assert!(
                reason.contains("always"),
                "reason missing 'always': {reason}"
            );
            assert!(reason.contains("never"), "reason missing 'never': {reason}");
            assert!(reason.contains("100"), "reason missing '100%': {reason}");
            assert!(
                reason.contains("definitely"),
                "reason missing 'definitely': {reason}"
            );
            assert!(
                reason.contains("guarantee"),
                "reason missing 'guarantee': {reason}"
            );
        }
        other => panic!("expected Fail, got {other:?}"),
    }
    // always + never + 100% + definitely + guarantee = 5 matches.
    assert_eq!(a.flag_count(analysis), 5);
}

#[test]
fn test_honesty_auditor_visible_in_band_room() {
    // DOC-ONLY TEST — documents how `HonestyAuditor` would be
    // wired into the Band room transcript as the 6th agent.
    //
    // The full wiring is deferred to a follow-up commit (see the
    // module doc in `crates/themis-agents/src/honesty_auditor.rs`
    // and the PRD for C-14). The intended shape is:
    //
    //   ┌─────────────────────────────────────────────────────┐
    //   │  Band room transcript (THEMIS 3.0, 6 agents)         │
    //   │                                                     │
    //   │  [12:00:01] @extractor     → @po_matcher            │
    //   │  [12:00:02] @po_matcher    → @fraud_auditor         │
    //   │  [12:00:03] @fraud_auditor → @gaap_classifier       │
    //   │  [12:00:04] @gaap_classifier → @provenance_signer   │
    //   │  [12:00:05] @provenance_signer → (sealed)           │
    //   │  ─── NEW in C-14: 6th agent ──────────────────────── │
    //   │  [12:00:06] @honesty_auditor → @provenance_signer   │
    //   │    event: HonestyCheck {                             │
    //   │      target_agent: "fraud_auditor",                 │
    //   │      verdict: Flag { reason: "over-claim ..." },   │
    //   │      match_count: 1,                                │
    //   │    }                                                │
    //   │  [12:00:06] @honesty_auditor → @po_matcher          │
    //   │    event: HonestyCheck { target_agent: "po_matcher",│
    //   │      verdict: Pass, match_count: 0 }               │
    //   │  ...                                                │
    //   └─────────────────────────────────────────────────────┘
    //
    // The audit itself is the deterministic regex pass exercised
    // by the other tests in this file; what this test asserts is
    // the API surface the orchestrator's `process_invoice` loop
    // will consume once the integration lands.
    //
    // The HonestyAuditor is *not* an LLM agent — it is a library.
    // The orchestrator calls `auditor.audit(&decision.reasoning)`
    // and posts the resulting `HonestyVerdict` as a `HonestyCheck`
    // event on the room's `EventBus`. No `LlmBackend` is needed.

    // Sanity check: the API surface is what the orchestrator will
    // consume (audit + flag_count + reasons + as_str).
    let a = auditor();
    let _verdict: HonestyVerdict = a.audit("clean output");
    let _count: usize = a.flag_count("clean output");
    let _reasons: Vec<String> = a.reasons("clean output");
    let _stable: &str = HonestyVerdict::Pass.as_str();

    // Sanity check: the default pattern set is non-empty and
    // contains the over-claim categories the PRD names.
    assert!(!DEFAULT_OVER_CLAIM_PATTERNS.is_empty());
    assert!(DEFAULT_OVER_CLAIM_PATTERNS
        .iter()
        .any(|p| p.contains("100")));
    assert!(DEFAULT_OVER_CLAIM_PATTERNS
        .iter()
        .any(|p| p.contains("always")));
    assert!(DEFAULT_OVER_CLAIM_PATTERNS
        .iter()
        .any(|p| p.contains("never")));
    assert!(DEFAULT_OVER_CLAIM_PATTERNS
        .iter()
        .any(|p| p.contains("guarantee")));
}
