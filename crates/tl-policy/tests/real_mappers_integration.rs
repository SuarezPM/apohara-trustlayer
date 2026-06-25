//! Integration tests verifying the v1.2 real mappers are wired into
//! the ComplianceStrategy dispatcher (no more stubs).

use tl_policy::iso_42001::{AimsEvidence, Iso42001Mapper};
use tl_policy::nist_ai_rmf::NistAiRmfMapper;
use tl_policy::{ComplianceStrategy, DORAContext, Framework, Status};

fn sample_packet() -> AimsEvidence {
    AimsEvidence {
        disclosure_id: "disc-001".to_string(),
        tenant_id: "acme".to_string(),
        compliance_rollup: "Partial".to_string(),
        compliance_policy_version: "apohara-v1.0".to_string(),
        deployment_status: "production".to_string(),
        lifecycle_stage: "production".to_string(),
    }
}

fn sample_ctx() -> DORAContext {
    DORAContext {
        disclosure_id: "disc-001".to_string(),
        has_valid_chain: true,
        has_recent_key_rotation: true,
        has_policy_decision: true,
        retention_until_iso: Some("2031-06-25T00:00:00Z".to_string()),
    }
}

#[test]
fn test_dispatcher_reports_iso_42001_as_covered_with_real_mapper() {
    // Per locked user decision + Plan v1.2 Block 4 v1.2-US-2:
    // the dispatcher must wire the REAL ISO 42001 mapper (not the
    // v1.1.x stub). The Status::Covered assertion is the auditable
    // proof.
    let dispatcher = ComplianceStrategy::new();
    let reports = dispatcher.evaluate_all(
        &tl_policy::DORAEvidenceStrategy::new(),
        &sample_ctx(),
    );
    let iso = reports
        .get(&Framework::Iso42001)
        .expect("ISO 42001 must be in dispatcher");
    assert_eq!(
        iso.status,
        Status::Covered,
        "ISO 42001 must be Covered (v1.2: real mapper, not stub)"
    );
    // The reason must reference the real mapper, not a stub.
    assert!(
        iso.reason.contains("v1.2 US-2"),
        "ISO 42001 reason must mention v1.2 US-2, got: {}",
        iso.reason
    );
    assert!(
        iso.reason.contains("§4-§10"),
        "ISO 42001 reason must mention §4-§10 (the 7 main clauses), got: {}",
        iso.reason
    );
}

#[test]
fn test_dispatcher_reports_nist_ai_rmf_as_covered_with_real_mapper() {
    let dispatcher = ComplianceStrategy::new();
    let reports = dispatcher.evaluate_all(
        &tl_policy::DORAEvidenceStrategy::new(),
        &sample_ctx(),
    );
    let nist = reports
        .get(&Framework::NistAiRmf)
        .expect("NIST AI RMF must be in dispatcher");
    assert_eq!(
        nist.status,
        Status::Covered,
        "NIST AI RMF must be Covered (v1.2: real mapper, not stub)"
    );
    assert!(
        nist.reason.contains("v1.2 US-2"),
        "NIST AI RMF reason must mention v1.2 US-2, got: {}",
        nist.reason
    );
    assert!(
        nist.reason.contains("NIST AI 100-1"),
        "NIST AI RMF reason must mention NIST AI 100-1, got: {}",
        nist.reason
    );
}

#[test]
fn test_iso_42001_real_mapper_produces_7_clauses() {
    // Verify the real mapper (not just the dispatcher wrapper).
    let m = Iso42001Mapper.map(&sample_packet());
    assert_eq!(m.populated, 7);
    assert!(m.all_clauses_covered);
    assert_eq!(m.notes.len(), 2);
    assert!(m.notes[1].contains("AIMS ready"));
}

#[test]
fn test_nist_ai_rmf_real_mapper_produces_4_functions_19_categories() {
    let m = NistAiRmfMapper.map(&sample_packet());
    assert_eq!(m.populated, 4);
    assert!(m.all_functions_covered);

    // Count total categories enumerated (should be 19 = 6+5+4+4)
    let mut total_categories = 0;
    for (_, value) in &m.fields {
        if let Some(obj) = value.as_object() {
            total_categories += obj.len();
        }
    }
    assert_eq!(
        total_categories, 19,
        "all 19 NIST AI RMF categories must be enumerated"
    );
}

#[test]
fn test_v1_2_status_matrix_has_iso_and_nist_as_covered() {
    // v1.2 ships the real mappers, so both are now Covered
    // (not the v1.1.x "NotImplemented" stubs).
    let dispatcher = ComplianceStrategy::new();
    let reports = dispatcher.evaluate_all(
        &tl_policy::DORAEvidenceStrategy::new(),
        &sample_ctx(),
    );
    assert_eq!(reports[&Framework::Iso42001].status, Status::Covered);
    assert_eq!(reports[&Framework::NistAiRmf].status, Status::Covered);
}
