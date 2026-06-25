//! Integration tests for the v1.2 ISO 42001:2023 AIMS real mapper.

use tl_policy::iso_42001::{AimsEvidence, Iso42001Mapper};

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

#[test]
fn test_all_7_main_clauses_populated() {
    // Per ISO 42001:2023 §4-§10, there are 7 main clauses. The
    // mapper produces 7 umbrella fields (one per main clause), each
    // containing the sub-clauses as a JSON object.
    let m = Iso42001Mapper.map(&sample_packet());
    assert_eq!(m.total, 7);
    assert_eq!(m.populated, 7);
    assert!(m.all_clauses_covered);
    assert_eq!(m.fields.len(), 7);
}

#[test]
fn test_clause_4_context_present_with_subclauses() {
    let m = Iso42001Mapper.map(&sample_packet());
    let (name, value) = m
        .fields
        .iter()
        .find(|(n, _)| n == "clause_4_context")
        .expect("clause_4_context must be present");
    assert_eq!(name, "clause_4_context");
    let v = value.as_object().expect("must be object");
    // Sub-clauses
    assert!(v.contains_key("4_1_organization_context"));
    assert!(v.contains_key("4_2_interested_parties"));
    assert!(v.contains_key("4_3_aims_scope"));
    assert!(v.contains_key("4_4_establish_aims"));
    // 4.1 includes tenant_id
    let sub = v
        .get("4_1_organization_context")
        .and_then(|x| x.as_object())
        .unwrap();
    assert_eq!(
        sub.get("tenant_id").and_then(|x| x.as_str()),
        Some("acme")
    );
}

#[test]
fn test_clause_6_1_baaar_mechanism() {
    let m = Iso42001Mapper.map(&sample_packet());
    let (_, value) = m
        .fields
        .iter()
        .find(|(n, _)| n == "clause_6_planning")
        .expect("clause_6_planning must be present");
    let v = value.as_object().expect("must be object");
    let sub_6_1 = v
        .get("6_1_risk_assessment")
        .and_then(|x| x.as_object())
        .expect("6_1 must be present");
    let mech = sub_6_1
        .get("mechanism")
        .and_then(|x| x.as_str())
        .unwrap();
    assert!(
        mech.contains("BAAAR"),
        "mechanism must reference BAAAR, got: {mech}"
    );
}

#[test]
fn test_clause_8_4_third_party_lists_sectigo() {
    let m = Iso42001Mapper.map(&sample_packet());
    let (_, value) = m
        .fields
        .iter()
        .find(|(n, _)| n == "clause_8_operation")
        .expect("clause_8_operation must be present");
    let v = value.as_object().expect("must be object");
    let sub_8_4 = v
        .get("8_4_third_party_relationships")
        .and_then(|x| x.as_object())
        .expect("8_4 must be present");
    let tsps = sub_8_4
        .get("tsps")
        .and_then(|x| x.as_array())
        .unwrap();
    let tsps_strs: Vec<&str> = tsps.iter().filter_map(|x| x.as_str()).collect();
    assert!(
        tsps_strs.contains(&"Sectigo (primary)"),
        "must list Sectigo as primary"
    );
    assert!(
        tsps_strs.contains(&"DigiCert (fallback)"),
        "must list DigiCert as fallback"
    );
}

#[test]
fn test_notes_reference_tenant() {
    let m = Iso42001Mapper.map(&sample_packet());
    let joined = m.notes.join(" | ");
    assert!(joined.contains("acme"), "notes must reference tenant: {joined}");
}

#[test]
fn test_aims_ready_note_when_all_covered() {
    let m = Iso42001Mapper.map(&sample_packet());
    assert!(
        m.notes.iter().any(|n| n.contains("AIMS ready")),
        "all 10 covered → 'AIMS ready' note must be present"
    );
}

#[test]
fn test_all_10_clause_names_present() {
    // Sanity check: every clause 4-10 has a corresponding field.
    let m = Iso42001Mapper.map(&sample_packet());
    let expected = [
        "clause_4_context",
        "clause_5_leadership",
        "clause_6_planning",
        "clause_7_support",
        "clause_8_operation",
        "clause_9_performance_evaluation",
        "clause_10_improvement",
    ];
    for name in &expected {
        assert!(
            m.fields.iter().any(|(n, _)| n == name),
            "{name} must be present in the 10-clause map"
        );
    }
}
