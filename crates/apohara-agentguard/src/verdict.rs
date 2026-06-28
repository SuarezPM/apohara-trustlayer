//! Core verdict types: the shared spine for gate, hook, and firewall.
//!
//! A [`Verdict`] is the single decision shape every component returns. Its
//! [`Tier`] is derived from a numeric severity via [`severity_to_tier`], with
//! the cutoffs supplied by [`Thresholds`]. Defaults:
//! `sev >= 8` BLOCK, `5..=7` REVIEW/Warn, else Allow.

use serde::{Deserialize, Serialize};

/// Decision tier for a single evaluation.
///
/// Precedence (most-severe wins, used by [`crate::hook::max_verdict`]):
/// `Block > Ask > Warn > Allow`. A default-deny request for human
/// confirmation (`Ask`) outranks `Warn` (so it is never silently
/// downgraded to a caution) and is outranked by `Block` (a hard refusal
/// still wins). `Allow` is the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Permit the action.
    Allow,
    /// Permit but surface a caution to the user/agent.
    Warn,
    /// Escalate to the human: a one-way ask surfaced as a UI prompt by
    /// the harness (`permissionDecision: "ask"`, exit 0). The human's
    /// response is the harness's concern, not agentguard's hook path —
    /// the verdict is "ask", nothing more.
    Ask,
    /// Refuse the action.
    Block,
}

impl Tier {
    /// Precedence rank for max-verdict / ordering comparisons.
    /// `Block > Ask > Warn > Allow`. The v0.3 test matrix in this
    /// module is the canonical reference; any change here is a
    /// semantic change that must update the matrix.
    pub fn rank(self) -> u8 {
        match self {
            Tier::Allow => 0,
            Tier::Warn => 1,
            Tier::Ask => 2,
            Tier::Block => 3,
        }
    }
}

/// A safety decision plus its rationale and optional agent-facing feedback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// The decision tier.
    pub tier: Tier,
    /// Human-readable reason for the decision.
    pub reason: String,
    /// Optional extra guidance surfaced back to the agent.
    pub feedback: Option<String>,
    /// Stable rule id (e.g. `"P-FIREWALL-001"`) when the verdict was
    /// produced by a known rule. `None` for ad-hoc reasons. P4.5/F6:
    /// set at construction via `with_rule_id`; legacy verdicts
    /// still derive one via the `parse_rule_label` fallback in
    /// `crate::hook`.
    pub rule_id: Option<String>,
    /// Category bucket (`"firewall"`, `"gate"`, `"policy"`). Same
    /// construction story as `rule_id`.
    pub category: Option<String>,
}

impl Verdict {
    /// An allow verdict with an empty reason and no feedback.
    pub fn allow() -> Self {
        Self {
            tier: Tier::Allow,
            reason: String::new(),
            feedback: None,
            rule_id: None,
            category: None,
        }
    }

    /// A warn verdict carrying the given reason.
    pub fn warn(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Warn,
            reason: reason.into(),
            feedback: None,
            rule_id: None,
            category: None,
        }
    }

    /// A block verdict carrying the given reason.
    pub fn block(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Block,
            reason: reason.into(),
            feedback: None,
            rule_id: None,
            category: None,
        }
    }

    /// An ask verdict carrying the given reason. The hook output
    /// `permissionDecision: "ask"` (exit 0) is produced downstream by
    /// [`crate::hook::contract::HookOutput::ask`] + [`crate::hook::contract::emit`].
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            tier: Tier::Ask,
            reason: reason.into(),
            feedback: None,
            rule_id: None,
            category: None,
        }
    }

    /// Attach (or replace) the optional agent-facing feedback. Builder style.
    pub fn with_feedback(mut self, feedback: impl Into<String>) -> Self {
        self.feedback = Some(feedback.into());
        self
    }

    /// Attach a stable rule id (and optional category) at construction
    /// time. The hook path still derives these from `reason` via the
    /// `parse_rule_label` fallback for legacy verdicts.
    pub fn with_rule_id(
        mut self,
        rule_id: impl Into<String>,
        category: Option<impl Into<String>>,
    ) -> Self {
        self.rule_id = Some(rule_id.into());
        self.category = category.map(Into::into);
        self
    }
}

/// Severity cutoffs that map a numeric severity to a [`Tier`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Severities `>= block_at` map to [`Tier::Block`].
    pub block_at: u8,
    /// Severities `>= warn_at` (but below `block_at`) map to [`Tier::Warn`].
    pub warn_at: u8,
}

impl Default for Thresholds {
    fn default() -> Self {
        // Severity cutoffs: sev >= 8 BLOCK, 5..=7 Warn, else Allow.
        Self {
            block_at: 8,
            warn_at: 5,
        }
    }
}

/// Map a numeric severity to a [`Tier`] using the given [`Thresholds`].
///
/// **Invariant:** this function NEVER returns [`Tier::Ask`] — `Ask` is a
/// POLICY decision (budget exhaustion), not a severity-tier mapping. Callers
/// that match on the result include a `Tier::Ask` arm only to satisfy
/// exhaustiveness; it degrades to `Verdict::allow()` if the invariant ever
/// breaks (defensive, never panics).
pub fn severity_to_tier(sev: u8, t: &Thresholds) -> Tier {
    if sev >= t.block_at {
        Tier::Block
    } else if sev >= t.warn_at {
        Tier::Warn
    } else {
        Tier::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_to_tier_default_thresholds() {
        let t = Thresholds::default();
        assert_eq!(severity_to_tier(9, &t), Tier::Block);
        assert_eq!(severity_to_tier(8, &t), Tier::Block);
        assert_eq!(severity_to_tier(7, &t), Tier::Warn);
        assert_eq!(severity_to_tier(5, &t), Tier::Warn);
        assert_eq!(severity_to_tier(4, &t), Tier::Allow);
        assert_eq!(severity_to_tier(0, &t), Tier::Allow);
    }

    #[test]
    fn severity_to_tier_custom_thresholds() {
        let t = Thresholds {
            block_at: 10,
            warn_at: 3,
        };
        assert_eq!(severity_to_tier(9, &t), Tier::Warn);
        assert_eq!(severity_to_tier(3, &t), Tier::Warn);
        assert_eq!(severity_to_tier(2, &t), Tier::Allow);
    }

    #[test]
    fn verdict_constructors() {
        assert_eq!(Verdict::allow().tier, Tier::Allow);
        assert_eq!(Verdict::warn("careful").tier, Tier::Warn);
        assert_eq!(Verdict::block("nope").tier, Tier::Block);
        assert_eq!(Verdict::ask("human?").tier, Tier::Ask);

        let v = Verdict::block("nope").with_feedback("try X instead");
        assert_eq!(v.feedback.as_deref(), Some("try X instead"));
    }

    #[test]
    fn ask_tier_rank_above_warn_below_block() {
        // v0.3 precedence: Block > Ask > Warn > Allow. This test is the
        // canonical reference for the new rank order; any disagreement
        // between `Tier::rank()` and this matrix is a bug, not a
        // stylistic change. (F8 from the ralplan Critic findings — the
        // matrix is the single source of truth.)
        assert!(Tier::Block.rank() > Tier::Ask.rank());
        assert!(Tier::Ask.rank() > Tier::Warn.rank());
        assert!(Tier::Warn.rank() > Tier::Allow.rank());
        // The 4 ranks are distinct (no two tiers share a rank).
        let ranks = [
            Tier::Allow.rank(),
            Tier::Warn.rank(),
            Tier::Ask.rank(),
            Tier::Block.rank(),
        ];
        for i in 0..ranks.len() {
            for j in (i + 1)..ranks.len() {
                assert_ne!(ranks[i], ranks[j], "ranks must be unique");
            }
        }
    }
}
