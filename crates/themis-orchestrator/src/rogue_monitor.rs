//! Rogue-agent monitor — ASI10 (Rogue Agents) defense.
//!
//! OWASP Agentic 2026 / ASI10: an agent that misbehaves
//! (prompt-injection-driven loop, spam, resource exhaustion)
//! will eventually broadcast many messages without ever
//! `@mention`-ing another agent — that's the visible signature of
//! a stuck/spinning agent that isn't participating in the
//! protocol.
//!
//! Policy:
//!
//! * Per-agent counter for messages without an `@mention`.
//! * When the counter reaches `threshold`, the agent is added to
//!   `quarantined` and stays there until `unquarantine` is called.
//! * When the agent does send a message that mentions another
//!   agent, its counter resets.
//!
//! Used by the orchestrator's agent loop (Story C-06 / G23 /
//! AC6) when an `AgentDecision` arrives on the event bus. Wiring
//! lands in a follow-up when the per-agent emit path is touched.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Default rogue threshold (messages without an `@mention` before
/// quarantine).
pub const DEFAULT_THRESHOLD: u32 = 10;

/// Identifier of a single agent in the orchestrator's registry.
/// `String` matches the orchestrator's existing `AgentId` newtype
/// pattern without coupling this module to the full registry.
pub type AgentId = String;

/// Status returned by `record_message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RogueStatus {
    /// Agent is below the threshold and not quarantined.
    Active {
        /// Current consecutive unmentioned-message count.
        count: u32,
    },
    /// Agent crossed the threshold and is quarantined.
    Quarantined {
        /// Count at the moment of quarantine.
        count: u32,
    },
}

/// Per-orchestrator rogue monitor.
pub struct RogueMonitor {
    /// Max consecutive unmentioned messages before quarantine.
    pub threshold: u32,
    /// Per-agent consecutive unmentioned-message counters.
    pub per_agent_counts: Mutex<HashMap<AgentId, u32>>,
    /// Set of quarantined agent IDs.
    pub quarantined: Mutex<HashSet<AgentId>>,
}

impl Default for RogueMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl RogueMonitor {
    /// Construct a monitor with the default threshold (10).
    pub fn new() -> Self {
        Self::with_threshold(DEFAULT_THRESHOLD)
    }

    /// Construct a monitor with a custom threshold.
    pub fn with_threshold(threshold: u32) -> Self {
        assert!(threshold > 0, "threshold must be > 0");
        Self {
            threshold,
            per_agent_counts: Mutex::new(HashMap::new()),
            quarantined: Mutex::new(HashSet::new()),
        }
    }

    /// Record a message from `agent`. If `mentioned_another`, the
    /// agent's counter resets. Otherwise the counter increments;
    /// crossing the threshold quarantines the agent.
    pub fn record_message(&self, agent: AgentId, mentioned_another: bool) -> RogueStatus {
        if mentioned_another {
            // Legitimate protocol participation — reset and clear
            // quarantine if the agent had been flagged earlier.
            self.lock_counts().remove(&agent);
            self.lock_quarantined().remove(&agent);
            return RogueStatus::Active { count: 0 };
        }

        let count = {
            let mut counts = self.lock_counts();
            let c = counts.entry(agent.clone()).or_insert(0);
            *c += 1;
            *c
        };

        let already_quarantined = self.lock_quarantined().contains(&agent);
        if count >= self.threshold {
            // Threshold crossed (or still over). If we haven't
            // flagged the agent yet, flip the flag; either way
            // the agent is quarantined.
            self.lock_quarantined().insert(agent);
            if already_quarantined {
                // Re-entry: surface as Active so callers know
                // the gate is lifted by an explicit unquarantine.
                RogueStatus::Active { count }
            } else {
                RogueStatus::Quarantined { count }
            }
        } else {
            RogueStatus::Active { count }
        }
    }

    /// Returns true if the agent is currently quarantined.
    pub fn is_quarantined(&self, agent: &AgentId) -> bool {
        self.lock_quarantined().contains(agent)
    }

    /// Lift the quarantine on an agent and reset its counter.
    /// The agent returns to Active; any subsequent unmentioned
    /// message starts a fresh count from 0. (Use sparingly —
    /// typically only after a human review.)
    pub fn unquarantine(&self, agent: &AgentId) {
        self.lock_quarantined().remove(agent);
        self.lock_counts().remove(agent);
    }

    /// Snapshot of all quarantined agents.
    pub fn quarantined_agents(&self) -> Vec<AgentId> {
        let g = self.lock_quarantined();
        let mut v: Vec<AgentId> = g.iter().cloned().collect();
        v.sort();
        v
    }

    fn lock_counts(&self) -> std::sync::MutexGuard<'_, HashMap<AgentId, u32>> {
        match self.per_agent_counts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn lock_quarantined(&self) -> std::sync::MutexGuard<'_, HashSet<AgentId>> {
        match self.quarantined.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_under_threshold() {
        let m = RogueMonitor::new();
        for i in 1..10 {
            let s = m.record_message("agent_a".to_string(), false);
            assert!(
                matches!(s, RogueStatus::Active { count } if count == i),
                "msg #{i} should be Active(count={i}), got {s:?}"
            );
        }
        assert!(!m.is_quarantined(&"agent_a".to_string()));
    }

    #[test]
    fn quarantined_at_10_unmentioned_messages() {
        let m = RogueMonitor::new();
        let mut last = None;
        for _ in 0..10 {
            last = Some(m.record_message("agent_x".to_string(), false));
        }
        assert!(
            matches!(last, Some(RogueStatus::Quarantined { count: 10 })),
            "10th message should quarantine, got {last:?}"
        );
        assert!(m.is_quarantined(&"agent_x".to_string()));
    }

    #[test]
    fn mention_resets_count() {
        let m = RogueMonitor::new();
        for _ in 0..5 {
            let _ = m.record_message("agent_y".to_string(), false);
        }
        // Mentioning another agent clears the count and returns
        // to Active(0).
        let s = m.record_message("agent_y".to_string(), true);
        assert_eq!(s, RogueStatus::Active { count: 0 });
        // 9 more unmentioned messages must NOT trigger quarantine
        // (the counter started from 0).
        for _ in 0..9 {
            let s = m.record_message("agent_y".to_string(), false);
            assert!(matches!(s, RogueStatus::Active { .. }));
        }
        assert!(!m.is_quarantined(&"agent_y".to_string()));
    }

    #[test]
    fn unquarantine_restores_active() {
        let m = RogueMonitor::new();
        for _ in 0..10 {
            let _ = m.record_message("agent_z".to_string(), false);
        }
        assert!(m.is_quarantined(&"agent_z".to_string()));
        m.unquarantine(&"agent_z".to_string());
        assert!(!m.is_quarantined(&"agent_z".to_string()));
        // Counter is also reset — next unmentioned message
        // starts fresh at Active(1).
        let s = m.record_message("agent_z".to_string(), false);
        assert_eq!(s, RogueStatus::Active { count: 1 });
    }

    #[test]
    fn per_agent_counts_independent() {
        let m = RogueMonitor::new();
        // Drive agent_a to 9 unmentioned messages (just under).
        for _ in 0..9 {
            let _ = m.record_message("agent_a".to_string(), false);
        }
        // Drive agent_b to 10 unmentioned messages (quarantined).
        for _ in 0..10 {
            let _ = m.record_message("agent_b".to_string(), false);
        }
        // agent_a is still under the threshold.
        assert!(!m.is_quarantined(&"agent_a".to_string()));
        let s = m.record_message("agent_a".to_string(), false);
        assert!(matches!(s, RogueStatus::Quarantined { count: 10 }));
        // agent_b remains quarantined.
        assert!(m.is_quarantined(&"agent_b".to_string()));
        // Snapshot exposes both.
        let mut g = m.quarantined_agents();
        g.sort();
        assert_eq!(g, vec!["agent_a".to_string(), "agent_b".to_string()]);
    }
}
