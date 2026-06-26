//! Integration test for v3.0 W3.3: 36-tool MCP surface (7 v1 + 29 v2).
//!
//! Verifies that all 29 v2 tools are registered in the dispatch
//! table and have proper JSON Schema specs.

use std::collections::HashMap;
use tl_mcp_server::tools_v2::{register_dispatch, tools_list};

#[test]
fn test_register_dispatch_has_29_v2_tools() {
    let mut map: HashMap<&'static str, tl_mcp_server::ToolHandler> = HashMap::new();
    register_dispatch(&mut map);
    assert_eq!(map.len(), 29, "must register exactly 29 v2 tools");
}

#[test]
fn test_tools_list_has_29_specs() {
    let specs = tools_list();
    assert_eq!(specs.len(), 29, "must return exactly 29 v2 tool specs");
    // Every spec must have name + inputSchema
    for spec in &specs {
        assert!(spec.get("name").is_some(), "spec missing name: {spec}");
        assert!(
            spec.get("inputSchema").is_some(),
            "spec missing inputSchema: {spec}"
        );
    }
}

#[test]
fn test_v2_tools_cover_all_9_modules() {
    let mut map: HashMap<&'static str, tl_mcp_server::ToolHandler> = HashMap::new();
    register_dispatch(&mut map);
    let modules: std::collections::HashSet<&str> = map
        .keys()
        .map(|name| name.split('.').next().unwrap_or(""))
        .collect();
    let expected: std::collections::HashSet<&str> = [
        "bundle", "scitt", "watermark", "trustlist", "key", "soa", "nist", "pld", "partner",
    ]
    .iter()
    .copied()
    .collect();
    assert_eq!(
        modules, expected,
        "v2 tool modules must match the 9 planned modules"
    );
}

#[test]
fn test_v2_tool_names_match_dispatch_keys() {
    // Every spec name must be in the dispatch table (and vice versa).
    let mut map: HashMap<&'static str, tl_mcp_server::ToolHandler> = HashMap::new();
    register_dispatch(&mut map);
    let specs = tools_list();
    let spec_names: std::collections::HashSet<&str> = specs
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    let dispatch_names: std::collections::HashSet<&str> = map.keys().copied().collect();
    assert_eq!(
        spec_names, dispatch_names,
        "spec names and dispatch keys must be identical"
    );
}

#[test]
fn test_v2_tools_total_count_with_v1_is_36() {
    // 7 v1 tools (tl_*) + 29 v2 tools = 36 total MCP surface.
    let mut total: HashMap<&'static str, tl_mcp_server::ToolHandler> = HashMap::new();
    // v1 (the 7 existing tl_* tools)
    for name in [
        "tl_generate_disclosure",
        "tl_verify_provenance",
        "tl_sign_artifact",
        "tl_create_evidence_bundle",
        "tl_evaluate_policy",
        "tl_inspect_receipt",
        "tl_check_compliance",
    ] {
        // We don't have a v1 handler accessible here; just count names.
        let _ = total.insert(name, dummy_handler as _);
    }
    // v2 (the 29 new tools)
    register_dispatch(&mut total);
    assert_eq!(total.len(), 36, "v1 (7) + v2 (29) must equal 36 total tools");
}

// Dummy handler for counting purposes only.
fn dummy_handler(_: serde_json::Value) -> Result<serde_json::Value, String> {
    Ok(serde_json::json!({}))
}
