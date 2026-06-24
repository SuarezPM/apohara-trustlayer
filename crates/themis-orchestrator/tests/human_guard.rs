//! Integration tests for Story C-06 — Alert-fatigue detector +
//! rogue-agent quarantine (ASI09 + ASI10 / G22 + G23).
//!
//! Verifies the two defense-in-depth layers that protect the
//! orchestrator from a compromised human rubber-stamping HALT
//! overrides (alert-fatigue) and from misbehaving agents spamming
//! the room without ever `@mention`-ing another agent (rogue
//! monitor).

use themis_orchestrator::human_guard::{
    AlertFatigueDetector, AlertFatigueError, AlertFatigueStatus,
};
use themis_orchestrator::rogue_monitor::{RogueMonitor, RogueStatus};

#[test]
fn test_alert_fatigue_full_flow() {
    let detector = AlertFatigueDetector::new();

    // First 5 approvals are within budget (Ok 1..=5).
    for i in 1..=5 {
        let s = detector.record_approval();
        assert!(
            matches!(s, AlertFatigueStatus::Ok { count } if count == i),
            "approval #{i} should be Ok(count={i}), got {s:?}"
        );
    }

    // 6th approval triggers suspension.
    let s = detector.record_approval();
    assert!(
        matches!(s, AlertFatigueStatus::Suspended { count: 6, .. }),
        "6th approval should be Suspended(6), got {s:?}"
    );

    // Authorization is denied while suspended.
    match detector.check_authorization() {
        Err(AlertFatigueError::RequiresReauth) => {}
        other => panic!("expected RequiresReauth, got {other:?}"),
    }

    // Re-auth clears the queue and resumes HITL.
    detector.reset_after_reauth();
    assert!(detector.check_authorization().is_ok());
    assert_eq!(detector.current_count(), 0);

    // Next approval starts fresh at Ok(1).
    let s = detector.record_approval();
    assert_eq!(s, AlertFatigueStatus::Ok { count: 1 });
}

#[test]
fn test_rogue_monitor_full_flow() {
    let monitor = RogueMonitor::new();

    // 10 unmentioned messages from agent_x → quarantine.
    let mut last = None;
    for _ in 0..10 {
        last = Some(monitor.record_message("agent_x".to_string(), false));
    }
    assert_eq!(last, Some(RogueStatus::Quarantined { count: 10 }));
    assert!(monitor.is_quarantined(&"agent_x".to_string()));

    // A different agent's @mention does NOT clear agent_x's
    // quarantine — only the offending agent's own @mention does.
    let _ = monitor.record_message("agent_y".to_string(), true);
    assert!(
        monitor.is_quarantined(&"agent_x".to_string()),
        "agent_x must remain quarantined; only agent_x's own @mention should reset it"
    );

    // agent_x itself sends a message mentioning another agent —
    // quarantine lifts and counter resets.
    let s = monitor.record_message("agent_x".to_string(), true);
    assert_eq!(s, RogueStatus::Active { count: 0 });
    assert!(!monitor.is_quarantined(&"agent_x".to_string()));

    // Sanity: explicit unquarantine also restores Active (and
    // preserves the counter, but it starts at 0 after the reset).
    for _ in 0..10 {
        let _ = monitor.record_message("agent_x".to_string(), false);
    }
    assert!(monitor.is_quarantined(&"agent_x".to_string()));
    monitor.unquarantine(&"agent_x".to_string());
    assert!(!monitor.is_quarantined(&"agent_x".to_string()));
}
