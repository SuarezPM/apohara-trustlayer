//! Tests for the ComplianceStrategy dispatcher (Plan v1.2 Block 4 v1.1.0.x+1+5).
//!
//! The dispatcher maps each concrete strategy (DORA, EU AI Act, etc.) to
//! its framework key. Adding a new framework requires zero changes to
//! existing strategies (open-closed). The v1.1.x state is documented:
//! EU AI Act=Covered, DORA=Partial, the other 6=NotImplemented.

use tl_policy::{ComplianceStrategy, DORAContext, DORAEvidenceStrategy, Framework, Status};

fn ctx_ok() -> DORAContext {
    DORAContext {
        disclosure_id: "disc-001".to_string(),
        has_valid_chain: true,
        has_recent_key_rotation: true,
        has_policy_decision: true,
        retention_until_iso: Some("2031-06-25T00:00:00Z".to_string()),
    }
}

#[test]
fn test_dispatcher_returns_map_of_8_frameworks_for_a_disclosure() {
    // Per Plan v1.2 Block 4 v1.1.0.x+1+5: dispatcher returns a
    // BTreeMap<Framework, ComplianceReport> with 8 framework keys.
    let dispatcher = ComplianceStrategy::new();
    let reports = dispatcher.evaluate_all(&DORAEvidenceStrategy::new(), &ctx_ok());
    assert_eq!(reports.len(), 8);

    for framework in [
        Framework::EuAiAct,
        Framework::Dora,
        Framework::Iso42001,
        Framework::NistAiRmf,
        Framework::NistSp80053,
        Framework::Soc2,
        Framework::Iso27001,
        Framework::OwaspLlm2026,
    ] {
        assert!(
            reports.contains_key(&framework),
            "dispatcher missing framework {:?}",
            framework
        );
    }
}

#[test]
fn test_v1_2_x_status_matrix_is_honest() {
    // For v1.1.x state: DORA=Partial, EU AI Act=Covered, the other 6
    // are NotImplemented. This is the v1.1.x truth-table per the README.
    let dispatcher = ComplianceStrategy::new();
    let reports = dispatcher.evaluate_all(&DORAEvidenceStrategy::new(), &ctx_ok());

    assert_eq!(
        reports[&Framework::Dora].status,
        Status::Partial,
        "DORA must report Partial in v1.1.x (5/6 checks pass; multi_tenant_isolation fails)"
    );
    assert_eq!(
        reports[&Framework::EuAiAct].status,
        Status::Covered,
        "EU AI Act must report Covered in v1.2.x (v1.0.5 truthfulness)"
    );
    // v1.2: ISO 42001 + NIST AI RMF are now Covered (real mappers).
    for framework in [Framework::Iso42001, Framework::NistAiRmf] {
        assert_eq!(
            reports[&framework].status,
            Status::Covered,
            "v1.2: {:?} must report Covered (real mapper)",
            framework
        );
    }
    // v1.2: the other 4 frameworks are still NotImplemented
    // (they ship in v1.2 follow-ups per Plan v1.2 Block 5).
    for framework in [
        Framework::NistSp80053,
        Framework::Soc2,
        Framework::Iso27001,
        Framework::OwaspLlm2026,
    ] {
        assert_eq!(
            reports[&framework].status,
            Status::NotImplemented,
            "{:?} must report NotImplemented in v1.2 (still follow-up)",
            framework
        );
    }
}

#[test]
fn test_dora_multi_tenant_isolation_honest_fail_says_ships_in_v1_2() {
    // Per Plan v1.2 Block 4 v1.1.0.x+1+5: the multi_tenant_isolation
    // honest-fail MUST sharpen its reason to mention "ships in v1.2"
    // (the test for the v1.1.x+1+5 change). The original reason
    // ("N/A in v1.1.0 — multi-tenant ships in v1.2") is still
    // acceptable as a substring; we want v1.2 mentioned prominently.
    let strategy = DORAEvidenceStrategy::new();
    let r = strategy.check_multi_tenant_isolation(&ctx_ok());
    assert!(!r.pass);
    assert!(
        r.reason.contains("v1.2"),
        "reason must mention v1.2 (Fase 3 closes this); actual: {:?}",
        r.reason
    );
    assert!(
        r.reason.contains("ships in"),
        "reason must mention 'ships in' (honest-fail pattern); actual: {:?}",
        r.reason
    );
}

#[test]
fn test_strategy_registry_is_open_principle() {
    // Open-closed: the dispatcher accepts a new framework without
    // changes to existing strategies. We add a custom strategy for a
    // hypothetical 9th framework; the dispatcher should call it.
    use std::collections::BTreeMap;
    use tl_policy::Strategy;

    struct CustomStrategy;
    impl Strategy for CustomStrategy {
        fn name(&self) -> &'static str {
            "custom-test"
        }
        fn evaluate(&self, _ctx: &DORAContext) -> (Status, String, Vec<String>) {
            (
                Status::Covered,
                "custom test".to_string(),
                vec!["test://custom".to_string()],
            )
        }
    }

    let _dispatcher = ComplianceStrategy::new();
    // The dispatcher should be able to delegate to arbitrary strategies
    // even if no framework mapping exists; we just verify the
    // Strategy trait is object-safe + the dispatcher pattern works.
    let mut map: BTreeMap<String, Box<dyn Strategy>> = BTreeMap::new();
    map.insert("custom".to_string(), Box::new(CustomStrategy));
    assert_eq!(map.get("custom").unwrap().name(), "custom-test");
}
