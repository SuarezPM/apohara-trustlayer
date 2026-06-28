//! apohara-agentguard library crate.
//!
//! Modules are crate-private by default. The real public API is
//! re-exported below — ~10 symbols consumed by the CLI binary,
//! `themis-orchestrator`, integration tests, benches, and fuzz
//! targets. Keeping the module tree `pub(crate)` prevents casual
//! external reach-through to internals (`hook::contract`, `policy::engine`,
//! gate parsers, etc.) and makes the actual contract explicit.

pub mod audit;
pub(crate) mod config;
pub mod firewall;
pub mod gate;
pub mod hook;
pub(crate) mod mcp;
pub(crate) mod policy;
pub mod sandbox;
pub mod verdict;

mod secrets;

// --- Selective re-exports of the real public API -----------------------
//
// External consumers (`themis-orchestrator::sandbox`, integration tests,
// benches, fuzz targets) import the symbols below — no other paths.

// `verdict`: core decision types consumed everywhere.
pub use crate::verdict::{Thresholds, Tier, Verdict};
// `sandbox`: the sandbox request/response/runner surface used by
// themis-orchestrator to invoke the local gate/firewall.
pub use crate::sandbox::{
    PermissionTier, SandboxError, SandboxRequest, SandboxResult, SandboxRunner,
};
// `gate`: the public `evaluate` entry-point and the `compound` /
// `normalize` modules re-exported for the fuzz targets.
pub use crate::gate::{compound, evaluate, normalize};
// `firewall`: `scan_content` is a public-API redaction function used
// by benches and consumers.
pub use crate::firewall::scan_content;
// `config`: `Config` (top-level user-facing config) re-exported for the bin
// and for `themis-orchestrator::sandbox` consumers.
pub use crate::config::{Config, CustomBlock, ToolRule};
// `policy`: `PolicySet` + `PolicyError` consumed by the bin and by
// `themis-orchestrator::sandbox`.
pub use crate::policy::engine::{PolicyError, PolicySet};
// `mcp`: `serve` re-exported for the bin's MCP JSON-RPC entry-point.
pub use crate::mcp::serve;
