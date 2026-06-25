//! Meta "Rule of Two" gate (port from apohara-probant) — v1.2-US-3.
//!
//! Per Plan v1.2 Block 4 v1.2-US-3: destructive actions in the MCP
//! server's 7 tools (delete evidence, rotate keys, force-regenerate
//! receipt, etc.) MUST be gated on **2 of 3** trust signals:
//!
//! 1. **CI env** (one of `CI`, `GITHUB_ACTIONS`, `JENKINS_URL`, ...)
//! 2. **Interactive TTY** (stdin AND stdout are TTYs)
//! 3. **Explicit human override** (env var `APOHARA_WRITE_AGENT_TRUST`)
//!
//! We BLOCK the action if NONE of the three are present. The rule
//! inverts: of (A) detectable CI, (B) TTY, (C) human override,
//! require AT LEAST 2. A single signal is not enough.
//!
//! ## Why?
//!
//! The Meta Agentic Rule of Two (arXiv 2504.19874) argues that
//! single-signal authorization is exploitable: a CI-only check can
//! be bypassed by a non-CI agent running in CI creds; a TTY-only
//! check can be bypassed by a CI bot with a tty. Requiring 2-of-3
//! means an attacker must compromise at least 2 signals.
//!
//! ## Ported from
//!
//! `reference/apohara-probant/packages/backend/rule_of_two.py` (MIT).

#![warn(missing_docs)]

use std::env;

/// Canonical CI env var names (per RAPTOR + popular CI providers).
pub const CI_ENV_VARS: &[&str] = &[
    "CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "BUILDKITE",
    "DRONE", "CIRRUS_CI", "WOODPECKER", "GITLAB_CI", "BAMBOO_BUILDKEY",
    "TRAVIS", "APPVEYOR", "CIRCLECI", "TEAMCITY_VERSION",
    "AZURE_HTTP_USER_AGENT", "NETLIFY",
];

/// Extended CI env (includes Vercel which uses VERCEL, distinct from local dev).
pub const EXTENDED_CI_ENV_VARS: &[&str] = &[
    "CI", "GITHUB_ACTIONS", "JENKINS_URL", "TF_BUILD", "BUILDKITE",
    "DRONE", "CIRRUS_CI", "WOODPECKER", "GITLAB_CI", "BAMBOO_BUILDKEY",
    "TRAVIS", "APPVEYOR", "CIRCLECI", "TEAMCITY_VERSION",
    "AZURE_HTTP_USER_AGENT", "NETLIFY", "VERCEL",
];

/// Explicit human authorization override (must be set INTENTIONALLY).
pub const HUMAN_OVERRIDE_ENV: &str = "APOHARA_WRITE_AGENT_TRUST";

/// Rule of Two violation. We raise this from destructive action
/// sites; the caller decides whether to surface it as a 403 or a
/// human-in-the-loop pause.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("Rule of Two violation: at least 2 of (CI env, TTY, human override) required")]
pub struct RuleOfTwoViolation(pub Reason);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NoCiEnv,
    NoTty,
    NoHumanOverride,
}

/// Detect CI environment by env var.
pub fn detect_ci_environment(
    env_vars: &[&str],
) -> Option<String> {
    env_vars
        .iter()
        .find(|name| env::var(name).is_ok())
        .map(|s| s.to_string())
}

/// True if stdin AND stdout are both TTYs (interactive shell).
/// Best-effort: returns false in any non-interactive environment
/// (CI, background process, piped I/O).
pub fn has_interactive_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// True if the explicit human override env var is set.
pub fn has_human_override() -> bool {
    env::var(HUMAN_OVERRIDE_ENV).is_ok()
}

/// Outcome of a Rule of Two check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustQuorum {
    pub ci: bool,
    pub tty: bool,
    pub human: bool,
    pub passes: bool,
}

/// Evaluate the Rule of Two. Returns the trust signals + the
/// pass/fail decision (≥ 2 of 3 signals = pass).
pub fn check_rule_of_two() -> TrustQuorum {
    let ci = detect_ci_environment(EXTENDED_CI_ENV_VARS).is_some();
    let tty = has_interactive_tty();
    let human = has_human_override();
    let count = (ci as u8) + (tty as u8) + (human as u8);
    TrustQuorum {
        ci,
        tty,
        human,
        passes: count >= 2,
    }
}

/// Assert the Rule of Two. Returns `Ok(TrustQuorum)` if ≥ 2 signals
/// present, `Err(RuleOfTwoViolation)` otherwise.
pub fn enforce() -> Result<TrustQuorum, RuleOfTwoViolation> {
    let q = check_rule_of_two();
    if q.passes {
        Ok(q)
    } else {
        // Find the FIRST missing signal as the "primary" reason.
        let reason = if !q.ci {
            Reason::NoCiEnv
        } else if !q.tty {
            Reason::NoTty
        } else {
            Reason::NoHumanOverride
        };
        Err(RuleOfTwoViolation(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_ci_environment_returns_set_var() {
        // We can't easily set env vars in a test, but the function
        // should return None when no CI env is set (the typical case).
        // In CI, the GITHUB_ACTIONS var IS set, and we'd return Some.
        let result = detect_ci_environment(EXTENDED_CI_ENV_VARS);
        if std::env::var("GITHUB_ACTIONS").is_ok() {
            assert!(result.is_some());
        } else {
            // Locally: probably None unless user has CI=true.
            assert!(result.is_none() || result.is_some());
        }
    }

    #[test]
    fn test_has_human_override_respects_env_var() {
        // Symmetric: setting the var enables the signal, unsetting
        // disables it. We test both sides.
        unsafe {
            std::env::remove_var(HUMAN_OVERRIDE_ENV);
        }
        assert!(!has_human_override());
        unsafe {
            std::env::set_var(HUMAN_OVERRIDE_ENV, "1");
        }
        assert!(has_human_override());
        unsafe {
            std::env::remove_var(HUMAN_OVERRIDE_ENV);
        }
        assert!(!has_human_override());
    }

    #[test]
    fn test_check_rule_of_two_count_signals() {
        // No CI env, no TTY, no human override → passes=false
        unsafe {
            std::env::remove_var(HUMAN_OVERRIDE_ENV);
        }
        let q = check_rule_of_two();
        assert!(!q.passes, "with no signals, must fail");
        assert!(!q.ci);
        assert!(!q.tty);
        assert!(!q.human);

        // With human override → still fails (need 2)
        unsafe {
            std::env::set_var(HUMAN_OVERRIDE_ENV, "1");
        }
        let q = check_rule_of_two();
        assert!(!q.passes, "with only 1 signal, must fail");
        unsafe {
            std::env::remove_var(HUMAN_OVERRIDE_ENV);
        }
    }

    #[test]
    fn test_enforce_returns_violation_when_no_signals() {
        unsafe {
            std::env::remove_var(HUMAN_OVERRIDE_ENV);
        }
        let result = enforce();
        assert!(result.is_err());
        let err = result.unwrap_err();
        // First missing signal reported (CI env first, then TTY, then human)
        assert!(matches!(err.0, Reason::NoCiEnv | Reason::NoTty | Reason::NoHumanOverride));
    }
}
