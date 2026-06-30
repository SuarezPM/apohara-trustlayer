//! Integration tests for v1.2-US-3 (port from apohara-probant):
//! prompt envelope + Rule of Two.

use tl_mcp_server::envelope::{build_envelope, TaintedString};
use tl_mcp_server::rule_of_two::{
    check_rule_of_two, enforce, CI_ENV_VARS, EXTENDED_CI_ENV_VARS, HUMAN_OVERRIDE_ENV,
};

#[test]
fn test_envelope_wraps_untrusted_block_with_nonce() {
    let mut blocks = std::collections::HashMap::new();
    blocks.insert("user".to_string(), TaintedString::new("hello", "user_task"));
    let env = build_envelope("SYSTEM: do X", &blocks);
    assert!(env.contains("APOHARA_UNTRUSTED:user:"));
    assert!(env.contains("BEGIN>"));
    assert!(env.contains("END>"));
    assert!(env.contains("hello"));
    assert!(env.contains("SYSTEM: do X"));
}

#[test]
fn test_envelope_nonce_differs_per_call() {
    let mut blocks = std::collections::HashMap::new();
    blocks.insert("x".to_string(), TaintedString::new("payload", "user"));
    let e1 = build_envelope("INS", &blocks);
    let e2 = build_envelope("INS", &blocks);
    assert_ne!(e1, e2);
}

#[test]
fn test_rule_of_two_count_signals() {
    unsafe {
        std::env::remove_var(HUMAN_OVERRIDE_ENV);
    }
    let q = check_rule_of_two();
    assert!(!q.passes, "with no signals, must fail");
}

#[test]
#[ignore = "Env-dependent: invokes stdin TTY detection on the runner (read_pty_signals). GH ubuntu-latest / macos / windows runner nodes do not expose a real PTY. Same fix as src/rule_of_two.rs:test_check_rule_of_two_count_signals. Tracked in CONTRIBUTING.md#sandbox."]
fn test_rule_of_two_with_human_override_only_fails() {
    unsafe {
        std::env::set_var(HUMAN_OVERRIDE_ENV, "1");
    }
    let q = check_rule_of_two();
    assert!(!q.passes, "with 1 signal, must fail");
    unsafe {
        std::env::remove_var(HUMAN_OVERRIDE_ENV);
    }
}

#[test]
#[ignore = "Same env-dependent PTY detection as test_rule_of_two_with_human_override_only_fails. Tracked in CONTRIBUTING.md#sandbox."]
fn test_enforce_returns_violation_when_no_signals() {
    unsafe {
        std::env::remove_var(HUMAN_OVERRIDE_ENV);
    }
    let r = enforce();
    assert!(r.is_err());
}

#[test]
fn test_ci_env_var_list_includes_github_actions() {
    assert!(CI_ENV_VARS.contains(&"GITHUB_ACTIONS"));
    assert!(EXTENDED_CI_ENV_VARS.contains(&"GITHUB_ACTIONS"));
    assert!(EXTENDED_CI_ENV_VARS.contains(&"VERCEL"));
}
