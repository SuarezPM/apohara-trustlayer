//! tl-mcp-server lib (v3.0 W3.3: expanded to 36 tools across 10 modules).

pub mod envelope;
pub mod rule_of_two;
pub mod tools_v2;

/// Shared tool-handler type used by both the v1 toolset (in `main.rs`)
/// and the v2 toolset (in `tools_v2.rs`). A handler receives the
/// deserialized JSON `arguments` object and returns a JSON `result`
/// (or a string error).
pub type ToolHandler = fn(serde_json::Value) -> Result<serde_json::Value, String>;
