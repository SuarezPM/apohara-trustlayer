//! Integration tests for tl-argus. Cover:
//! 1. CordonEnforcer isolation (the moat)
//! 2. Specialist dispatch (4 names + prompt names)
//! 3. AuditEvent BLAKE3 chain (3-event tamper-evidence)
//! 4. AuditEvent GDPR posture (cleartext NEVER appears in JSON)
//! 5. AuditEvent JSON has all 16 fields
//! 6. Slop/Security/Arch serde round-trip
//! 7. SynthesizerInput honors the Cordon contract

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde_json::json;
use uuid::Uuid;

use crate::audit_event::{
    blake3_fingerprint, next_prev_hash, AuditEvent, DataClass, DecisionArtifact, ToolCallRecord,
};
use crate::cordon::{Constraint, ContextRequirement, CordonEnforcer, CordonError};
use crate::specialists::{
    extract_json, ArchitectureFit, SecurityReview, SecuritySeverity, SlopDetector, SlopError,
    Specialist, SynthesizerInput, VerdictStatus, VerdictSynthesizer,
};

// =====================================================================
// 1. CordonEnforcer isolation (the moat)
// =====================================================================

#[test]
fn cordon_blocks_diff_context_for_synthesizer() {
    // The verdict synthesizer (aegis-verdict) must NEVER receive raw
    // diff. The static guard rejects DiffOnly and DiffPlusRepoSample.
    let e = CordonEnforcer::new();
    assert_eq!(
        e.verify_safe_to_synthesize(&ContextRequirement::DiffOnly),
        Err(CordonError::RawCodeLeak),
    );
    assert_eq!(
        e.verify_safe_to_synthesize(&ContextRequirement::DiffPlusRepoSample),
        Err(CordonError::RawCodeLeak),
    );
    assert_eq!(
        e.verify_safe_to_synthesize(&ContextRequirement::OtherAgentsOutputs),
        Ok(()),
    );
}

#[test]
fn cordon_scans_json_for_raw_diff_lines() {
    let e = CordonEnforcer::new();

    // A multi-line string with diff markers is blocked.
    let bad = json!({
        "slop_report": {"notes": "+ added foo\n- removed bar"}
    });
    assert_eq!(
        e.verify_no_raw_code_in_json(&bad),
        Err(CordonError::RawCodeLeak),
    );

    // A structured verdict with no diff markers is fine.
    let good = json!({
        "verdict": "HALTED",
        "risk_score": 0.9,
        "findings": [],
    });
    assert!(e.verify_no_raw_code_in_json(&good).is_ok());

    // Field named `raw_code` or `raw_diff` is blocked even when empty.
    let bad_field = json!({ "raw_diff": "" });
    assert!(e.verify_no_raw_code_in_json(&bad_field).is_err());
    let bad_field2 = json!({ "raw_code": "x" });
    assert!(e.verify_no_raw_code_in_json(&bad_field2).is_err());
}

#[test]
fn constraint_no_raw_code_marker_is_recognized() {
    assert!(Constraint::NoRawCode.is_no_raw_code());
    assert!(!Constraint::MaxTemperature(0.0).is_no_raw_code());
    assert!(!Constraint::MustProduceJson("x".into()).is_no_raw_code());
    assert!(!Constraint::NoMergeDecisions.is_no_raw_code());
}

// =====================================================================
// 2. Specialist dispatch (4 specialists + names + prompt names)
// =====================================================================

#[test]
fn four_specialists_have_stable_names_and_prompts() {
    // The 4 specialist names are load-bearing: the prompt library
    // looks them up by these exact strings. A typo breaks everything.
    assert_eq!(SlopDetector::new().name(), "aegis-slop");
    assert_eq!(SlopDetector::new().prompt_name(), "slop-detector");
    assert_eq!(SecurityReview::new().name(), "aegis-security");
    assert_eq!(SecurityReview::new().prompt_name(), "redteam-security");
    assert_eq!(ArchitectureFit::new().name(), "aegis-arch");
    assert_eq!(ArchitectureFit::new().prompt_name(), "architecture-fit");
    assert_eq!(VerdictSynthesizer::new().name(), "aegis-verdict");
    assert_eq!(VerdictSynthesizer::new().prompt_name(), "verdict-synthesizer");
}

#[test]
fn extract_json_handles_fenced_and_bare() {
    assert_eq!(extract_json(r#"{"a":1}"#), r#"{"a":1}"#);
    assert_eq!(extract_json("```json\n{\"a\":1}\n```"), "{\"a\":1}");
    assert_eq!(extract_json("```\n{\"a\":1}\n```"), "{\"a\":1}");
}

#[test]
fn slop_parse_invalid_returns_parse_error() {
    let err = SlopDetector::new().parse_response("not json").unwrap_err();
    assert!(matches!(err, SlopError::Parse(_)));
}

#[test]
fn security_severity_ordering_for_verdict_escalation() {
    // Verdict synthesizer escalates to HALTED on Critical | High.
    // This ordering must hold.
    assert!(SecuritySeverity::None < SecuritySeverity::Info);
    assert!(SecuritySeverity::Info < SecuritySeverity::Low);
    assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
    assert!(SecuritySeverity::Medium < SecuritySeverity::High);
    assert!(SecuritySeverity::High < SecuritySeverity::Critical);
}

#[test]
fn synthesizer_input_honors_cordon_contract() {
    // The CordonEnforcer guarantees the diff field is already
    // secret-redacted. Round-trip the shape to ensure serde doesn't
    // break the contract.
    let input = SynthesizerInput {
        pr_ref: "pr/123".into(),
        pr_diff: "<redacted-by-cordon>".into(),
        slop_report: json!({ "slop_score": 0.5 }),
        security_report: json!({ "highest_severity": "low" }),
        architecture_report: json!({ "fit_score": 0.7 }),
    };
    let s = serde_json::to_string(&input).unwrap();
    let back: SynthesizerInput = serde_json::from_str(&s).unwrap();
    assert_eq!(back.pr_ref, "pr/123");
    assert_eq!(back.pr_diff, "<redacted-by-cordon>");
    // The Cordon scan must accept this input — no raw diff markers.
    let v: serde_json::Value = serde_json::to_value(&back).unwrap();
    assert!(CordonEnforcer::new().verify_no_raw_code_in_json(&v).is_ok());
}

#[test]
fn verdict_synthesizer_maps_unknown_string_to_review_required() {
    // Defensive default: anything that isn't APPROVED or HALTED
    // becomes REVIEW_REQUIRED (safer than APPROVED).
    let raw = r#"{"verdict":"WAT","risk_score":0.5,"summary":"","key_findings":[],"action_items":[],"reasoning":""}"#;
    let v = VerdictSynthesizer::new().parse_response(raw).unwrap();
    assert_eq!(v.status, VerdictStatus::ReviewRequired);
}

// =====================================================================
// 3. AuditEvent BLAKE3 chain (3-event tamper-evidence)
// =====================================================================

fn test_signing_key() -> SigningKey {
    // Deterministic 32-byte seed — no `rand` dep needed.
    SigningKey::from_bytes(&[7u8; 32])
}

fn sample_decision() -> DecisionArtifact {
    DecisionArtifact {
        verdict: "warn".into(),
        findings_count: 2,
        rationale: "Two minor slop patterns".into(),
    }
}

fn build_event(prev_hash: [u8; 32], prompt: &str, response: &str) -> AuditEvent {
    let key = test_signing_key();
    let mut event = AuditEvent {
        audit_id: Uuid::new_v4(),
        timestamp: DateTime::parse_from_rfc3339("2026-06-26T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        model_id: "test-model".into(),
        prompt_template_version: "v1".into(),
        prompt_fingerprint: blake3_fingerprint(prompt.as_bytes()),
        response_fingerprint: blake3_fingerprint(response.as_bytes()),
        temperature: 0.7,
        tool_calls: vec![],
        input_tokens: prompt.len() as u32 / 4,
        output_tokens: response.len() as u32 / 4,
        estimated_cost_usd: 0.0,
        data_class: DataClass::SourceCode,
        policy_version: "policy-v1".into(),
        decision: sample_decision(),
        prev_hash,
        signature: Signature::from_bytes(&[0u8; 64]),
    };
    // Sign the canonical JSON with the signature field zeroed.
    let canonical = serde_json::to_vec(&event).expect("serialize");
    event.signature = key.sign(&canonical);
    event
}

#[test]
fn audit_event_blake3_chain_3_events_tamper_evident() {
    let prev0 = [0u8; 32];
    let e1 = build_event(prev0, "p1", "r1");
    let prev1 = next_prev_hash(prev0, &e1);
    let e2 = build_event(prev1, "p2", "r2");
    let prev2 = next_prev_hash(prev1, &e2);
    let e3 = build_event(prev2, "p3", "r3");
    let prev3 = next_prev_hash(prev2, &e3);

    // Each event's prev_hash matches the chain.
    assert_eq!(e1.prev_hash, prev0);
    assert_eq!(e2.prev_hash, prev1);
    assert_eq!(e3.prev_hash, prev2);

    // Tampering with e2 must change the link from e2 to e3.
    let mut e2_tampered = e2.clone();
    e2_tampered.input_tokens = 9999;
    let prev3_after_tamper = next_prev_hash(prev1, &e2_tampered);
    assert_ne!(prev3_after_tamper, prev2);
    // And e3's stored prev_hash no longer matches.
    assert_ne!(e3.prev_hash, prev3_after_tamper);

    // The final hash is non-zero and reproducible.
    assert_ne!(prev3, [0u8; 32]);
    assert_eq!(next_prev_hash(prev2, &e3), prev3);
}

#[test]
fn audit_event_json_has_all_16_fields_and_no_cleartext() {
    let secret = "patient: alice, ssn: 123-45-6789 - DO NOT LOG";
    let event = build_event([0u8; 32], secret, "response");

    let v: serde_json::Value = serde_json::to_value(&event).unwrap();
    let obj = v.as_object().unwrap();

    // 16 fields per Art. 12 Level 2 schema (14 original + data_class + policy_version).
    assert_eq!(obj.len(), 16);

    // GDPR: the cleartext prompt (and any PII inside it) is gone.
    let s = serde_json::to_string(&event).unwrap();
    assert!(!s.contains(secret), "cleartext prompt must not appear in JSON");
    assert!(!s.contains("123-45-6789"), "PII must not leak into JSON");

    // Fingerprint must be hex-encoded, exactly 64 chars (32 bytes).
    let fp = obj["prompt_fingerprint"].as_str().expect("hex string");
    assert_eq!(fp.len(), 64);
    assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn audit_event_json_roundtrip_preserves_all_16_fields() {
    let event = build_event([0u8; 32], "prompt", "response");
    let s = serde_json::to_string(&event).unwrap();
    let back: AuditEvent = serde_json::from_str(&s).unwrap();
    assert_eq!(back.audit_id, event.audit_id);
    assert_eq!(back.model_id, event.model_id);
    assert_eq!(back.prompt_fingerprint, event.prompt_fingerprint);
    assert_eq!(back.response_fingerprint, event.response_fingerprint);
    assert_eq!(back.temperature, event.temperature);
    assert_eq!(back.input_tokens, event.input_tokens);
    assert_eq!(back.output_tokens, event.output_tokens);
    assert_eq!(back.estimated_cost_usd, event.estimated_cost_usd);
    assert_eq!(back.data_class, event.data_class);
    assert_eq!(back.policy_version, event.policy_version);
    assert_eq!(back.decision, event.decision);
    assert_eq!(back.prev_hash, event.prev_hash);
    assert_eq!(back.signature.to_bytes(), event.signature.to_bytes());

    // All 16 keys present.
    let v: serde_json::Value = serde_json::to_string(&event).unwrap().parse().unwrap();
    assert_eq!(v.as_object().unwrap().len(), 16);
}

#[test]
fn tool_call_record_roundtrips_with_hex_hashes() {
    let tc = ToolCallRecord {
        tool_name: "read_file".into(),
        input_hash: [7u8; 32],
        output_hash: [9u8; 32],
        latency_ms: 42,
    };
    let s = serde_json::to_string(&tc).unwrap();
    let back: ToolCallRecord = serde_json::from_str(&s).unwrap();
    assert_eq!(back, tc);
    // The hash fields must serialize as 64-char hex, not 32 raw bytes.
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["input_hash"].as_str().unwrap().len(), 64);
}
