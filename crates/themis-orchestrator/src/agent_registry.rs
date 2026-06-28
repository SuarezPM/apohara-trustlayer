//! `AgentRegistry` — owns the orchestrator's agent dispatch table.
//!
//! Extracted from `Orchestrator` in P4.2 to reduce the god-object's
//! responsibilities. The registry is a thin wrapper over the agent
//! `HashMap` that hides the iteration order and provides typed
//! lookup. The orchestrator routes agent calls through
//! `AgentRegistry::get(name)` instead of indexing the map directly.

use std::collections::HashMap;
use std::sync::Arc;

use themis_agents::traits::Agent;

/// Agent dispatch table for the orchestrator.
///
/// Owns the 8 named agents (`fraud_auditor`, `gaap_classifier`, etc.)
/// and provides typed lookup. Constructed once at orchestrator
/// startup; shared across `process_invoice` runs via `Arc<dyn Agent>`
/// entries.
pub(crate) struct AgentRegistry {
    agents: HashMap<String, Arc<dyn Agent>>,
}

impl AgentRegistry {
    /// Build a new registry from the agent map (moved; the
    /// orchestrator caller usually owns the map already).
    pub(crate) fn new(agents: HashMap<String, Arc<dyn Agent>>) -> Self {
        Self { agents }
    }

    /// Look up an agent by its pipeline name (e.g. `"fraud_auditor"`).
    pub(crate) fn get(&self, name: &str) -> Option<&Arc<dyn Agent>> {
        self.agents.get(name)
    }

    /// Names of all registered agents in arbitrary order. Used by
    /// `Debug` and by health-check endpoints.
    pub(crate) fn names(&self) -> Vec<&str> {
        self.agents.keys().map(String::as_str).collect()
    }

    /// Number of registered agents. Reserved for health-check
    /// endpoints + future `metrics` integration; not used in the
    /// hot path today (`#[allow(dead_code)]` keeps the API surface
    /// stable while avoiding the warning).
    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.agents.len()
    }

    /// True if no agents are registered. Same rationale as `len`.
    #[allow(dead_code)]
    pub(crate) fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }
}
