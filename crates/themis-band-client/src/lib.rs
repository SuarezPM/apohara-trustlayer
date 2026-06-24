//! themis-band-client — Band client wrapper for THEMIS.
//!
//! Two integration surfaces:
//!
//! 1. **Legacy Python control plane** (`python_bridge.rs`,
//!    `RealBandRoom` in the orchestrator) — JSON-over-stdio for
//!    `create_chatroom` / `send_message` / `get_history`. Used by
//!    the per-invoice orchestrator flow.
//!
//! 2. **Per-agent WebSocket** (`socket.rs`, `fleet.rs`) — one
//!    Python subprocess per agent (`scripts/run_agent.py`) opens a
//!    persistent Phoenix Channels WebSocket at
//!    `wss://app.band.ai/api/v1/socket/websocket`, joins a chatroom,
//!    and streams events to stdout. Used for the public live chat
//!    room (AC Ola-A).

#![warn(missing_docs)]

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-band-client"
}

pub mod client;
pub mod error;
pub mod fleet;
pub mod python_bridge;
pub mod signed_message;
pub mod socket;
pub mod trust_gate;
pub mod types;
pub mod ws;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-band-client");
    }
}
