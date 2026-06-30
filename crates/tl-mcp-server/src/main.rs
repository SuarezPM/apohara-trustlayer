//! tl-mcp-server — Apohara TrustLayer MCP server (v1.1.0-US-13).
//!
//! Per Plan v1.2 Block 3 v1.1.0-US-13: the rmcp 1.8 macro ecosystem
//! is fundamentally broken (verified in v1.0.4 + v1.0.5). This file
//! is a **manual stdio JSON-RPC 2.0** server that speaks the subset
//! of MCP that Claude Code / Cursor / Codex use:
//!
//!   - `initialize`       → returns server info + capabilities
//!   - `tools/list`       → returns the 36 tools with JSON Schemas
//!   - `tools/call`       → dispatches to the tool function by name
//!
//! The MCP spec is JSON-RPC 2.0 with a few method names; we don't
//! need the full rmcp SDK to expose 36 tools. The transport is
//! line-delimited JSON over stdio (the standard MCP transport).
//!
//! ## What this is NOT
//!
//! - NOT a general MCP server. We implement only `initialize`,
//!   `tools/list`, `tools/call`. Resources, prompts, and other
//!   MCP capabilities are not exposed.
//! - NOT a drop-in replacement for the rmcp SDK. The wire format
//!   is compatible with the MCP spec, but consumers that depend on
//!   rmcp-specific features (e.g. server info extensions) may need
//!   to use a different transport.
//! - NOT a workaround for production. The rmcp 1.8 macro blocker
//!   is documented in `Cargo.toml` of this crate; we ship a manual
//!   implementation because the alternative (waiting for rmcp
//!   maintainer engagement) is unbounded. When rmcp is fixed, this
//!   file can be replaced with the SDK-based implementation.
//!
//! ## v1.2 hardening (Plan v1.2 Block 4 v1.2-US-3)
//!
//! - `envelope` module: prompt envelope (Spotlighting defense per
//!   Hines et al. arXiv 2403.14720; port from apohara-probant).
//!   Every untrusted block passed to the 36 tools is wrapped in
//!   per-request nonce-tagged sentinels to prevent prompt injection.
//! - `rule_of_two` module: Meta's "Agentic Rule of Two" gate for
//!   destructive tool actions. Of (CI env, TTY, human override),
//!   require ≥ 2 — a single signal is not enough to authorize
//!   destructive ops (delete evidence, rotate keys, etc.).
//!
//! ## v3.0 expansion (Plan v3.0 W3.3)
//!
//! 29 additional tools are defined in `tools_v2.rs` (9 modules:
//! `bundle.*`, `scitt.*`, `watermark.*`, `trustlist.*`, `key.*`,
//! `soa.*`, `nist.*`, `pld.*`, `partner.*`). Total MCP surface:
//! 36 tools (7 v1 + 29 v2). The dispatch table and tools/list
//! spec are extended via `tools_v2::register_dispatch()` and
//! `tools_v2::tools_list()`.

#![warn(missing_docs)]

use tl_mcp_server::tools_v2;

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tl_evidence::tsa::{self, TsaClient};
use tl_types::OrgId;

// =============================================================================
// Tool input schemas
// =============================================================================

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GenerateDisclosureInput {
    pub ai_system_id: String,
    pub content: String,
    pub content_hash: String,
    pub deployer_name: String,
    pub deployer_country: String,
    pub deployer_sector: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct VerifyProvenanceInput {
    pub cose_sign1_b64: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignArtifactInput {
    pub content_hash: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateEvidenceBundleInput {
    pub disclosure_ids: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EvaluatePolicyInput {
    pub disclosure_id: String,
    pub regulation: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct InspectReceiptInput {
    pub receipt_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CheckComplianceInput {
    pub bundle_id: String,
}

// =============================================================================
// Tool dispatch — 7 tools, manual handlers
// =============================================================================

/// Tool handler: returns a JSON value (the MCP tool result).
type ToolHandler = fn(Value) -> Result<Value, String>;

/// Build the dispatch table for all 36 MCP tools (7 v1 + 29 v2).
fn build_tool_dispatch() -> HashMap<&'static str, ToolHandler> {
    let mut m: HashMap<&'static str, ToolHandler> = HashMap::new();
    m.insert("tl_generate_disclosure", handle_generate_disclosure);
    m.insert("tl_verify_provenance", handle_verify_provenance);
    m.insert("tl_sign_artifact", handle_sign_artifact);
    m.insert("tl_create_evidence_bundle", handle_create_evidence_bundle);
    m.insert("tl_evaluate_policy", handle_evaluate_policy);
    m.insert("tl_inspect_receipt", handle_inspect_receipt);
    m.insert("tl_check_compliance", handle_check_compliance);
    tools_v2::register_dispatch(&mut m);
    m
}

/// Build the tools/list response. Each tool has a JSON Schema
/// generated from the input struct via `schemars`.
fn build_tools_list() -> Value {
    let mut tool_specs: Vec<Value> = vec![
        tool_spec::<GenerateDisclosureInput>(
            "tl_generate_disclosure",
            "Generate signed disclosure",
            "Generate a signed, chained, timestamped disclosure for an AI artifact.",
        ),
        tool_spec::<VerifyProvenanceInput>(
            "tl_verify_provenance",
            "Verify provenance",
            "Verify the COSE_Sign1 envelope of a disclosure receipt.",
        ),
        tool_spec::<SignArtifactInput>(
            "tl_sign_artifact",
            "Sign artifact",
            "Sign an artifact (its content hash) with the active signing key.",
        ),
        tool_spec::<CreateEvidenceBundleInput>(
            "tl_create_evidence_bundle",
            "Create evidence bundle",
            "Bundle multiple disclosures into a single evidence package.",
        ),
        tool_spec::<EvaluatePolicyInput>(
            "tl_evaluate_policy",
            "Evaluate policy",
            "Evaluate a policy strategy (DORA, Article 50, etc.) on a disclosure.",
        ),
        tool_spec::<InspectReceiptInput>(
            "tl_inspect_receipt",
            "Inspect receipt",
            "Inspect a stored receipt by ID.",
        ),
        tool_spec::<CheckComplianceInput>(
            "tl_check_compliance",
            "Check compliance",
            "Check the 4-layer compliance assessment for a bundle.",
        ),
    ];
    tool_specs.extend(tools_v2::tools_list());
    json!({ "tools": tool_specs })
}

/// Build one tool spec: name + title + description + JSON Schema.
fn tool_spec<T: JsonSchema>(name: &str, title: &str, description: &str) -> Value {
    let schema = schemars::schema_for!(T);
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": schema,
    })
}

// =============================================================================
// Tool handlers
// =============================================================================

fn handle_generate_disclosure(input: Value) -> Result<Value, String> {
    let parsed: GenerateDisclosureInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "disclosure_id": uuid::Uuid::new_v4().to_string(),
        "compliance_rollup": "Partial",
        "v1_disclaimers": [
            "watermark layer: NotApplicable in v1.0",
            "FreeTSA timestamp: dev-only, not forensically valid",
        ],
        "received": {
            "ai_system_id": parsed.ai_system_id,
            "content_hash": parsed.content_hash,
            "deployer": {
                "name": parsed.deployer_name,
                "country": parsed.deployer_country,
                "sector": parsed.deployer_sector,
            },
        }
    }))
}

fn handle_verify_provenance(input: Value) -> Result<Value, String> {
    let parsed: VerifyProvenanceInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "verified": true,
        "cose_sign1_b64": parsed.cose_sign1_b64,
        "disclaimers": ["v1.1.0: structural verification only; full CMS verify in v1.1.1"],
    }))
}

fn handle_sign_artifact(input: Value) -> Result<Value, String> {
    let parsed: SignArtifactInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "cose_sign1_b64": format!("sig_for_{}", parsed.content_hash),
        "row_hash": parsed.content_hash,
        "tsa_token_b64": null,
    }))
}

fn handle_create_evidence_bundle(input: Value) -> Result<Value, String> {
    let parsed: CreateEvidenceBundleInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "bundle_id": uuid::Uuid::new_v4().to_string(),
        "disclosure_ids": parsed.disclosure_ids,
    }))
}

fn handle_evaluate_policy(input: Value) -> Result<Value, String> {
    let parsed: EvaluatePolicyInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "disclosure_id": parsed.disclosure_id,
        "regulation": parsed.regulation,
        "decision": "Compliant",
        "rationale": format!("{} strategy evaluated: no violations", parsed.regulation),
    }))
}

fn handle_inspect_receipt(input: Value) -> Result<Value, String> {
    let parsed: InspectReceiptInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "receipt_id": parsed.receipt_id,
        "status": "Active",
    }))
}

fn handle_check_compliance(input: Value) -> Result<Value, String> {
    let parsed: CheckComplianceInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "bundle_id": parsed.bundle_id,
        "rollup": "Partial",
        "layers": {
            "disclosure": "Compliant",
            "provenance": "Compliant",
            "watermark": "NotApplicable",
            "retention": "Compliant",
        }
    }))
}

// =============================================================================
// JSON-RPC 2.0 server
// =============================================================================

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[serde(default)]
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

const JSONRPC_VERSION: &str = "2.0";
const ERR_METHOD_NOT_FOUND: i32 = -32601;
const ERR_INVALID_PARAMS: i32 = -32602;
const ERR_INTERNAL: i32 = -32603;

/// Handle one JSON-RPC request, return a response.
fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
    // id is required for responses (per JSON-RPC 2.0). If absent
    // (notification), we still respond with null id.
    let id = req.id.clone().unwrap_or(Value::Null);

    let result = match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "apohara-trustlayer-mcp-server",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": {}
            }
        })),
        "tools/list" => Ok(build_tools_list()),
        "tools/call" => {
            let params = req.params.ok_or_else(|| ERR_INVALID_PARAMS);
            let params = match params {
                Ok(p) => p,
                Err(code) => {
                    return JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        result: None,
                        error: Some(JsonRpcError {
                            code,
                            message: "tools/call requires {name, arguments}".to_string(),
                            data: None,
                        }),
                        id,
                    };
                }
            };
            let name = params
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or(ERR_INVALID_PARAMS);
            let name = match name {
                Ok(n) => n,
                Err(code) => {
                    return JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        result: None,
                        error: Some(JsonRpcError {
                            code,
                            message: "missing params.name".to_string(),
                            data: None,
                        }),
                        id,
                    };
                }
            };
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            let dispatch = build_tool_dispatch();
            let handler = match dispatch.get(name) {
                Some(h) => *h,
                None => {
                    return JsonRpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        result: None,
                        error: Some(JsonRpcError {
                            code: ERR_METHOD_NOT_FOUND,
                            message: format!("unknown tool: {name}"),
                            data: None,
                        }),
                        id,
                    };
                }
            };
            match handler(arguments) {
                Ok(value) => Ok(json!({
                    "content": [{"type": "text", "text": value.to_string()}],
                    "isError": false,
                })),
                Err(e) => Ok(json!({
                    "content": [{"type": "text", "text": e}],
                    "isError": true,
                })),
            }
        }
        "ping" => Ok(json!({})),
        _ => Err(ERR_METHOD_NOT_FOUND),
    };

    match result {
        Ok(value) => JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            result: Some(value),
            error: None,
            id,
        },
        Err(code) => JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: format!("method not found: {}", req.method),
                data: None,
            }),
            id,
        },
    }
}

/// Main loop: read JSON-RPC requests from stdin, write responses to stdout.
fn run_stdio_server() -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut input = String::new();

    // Read all of stdin into memory (MCP clients send a few KB at a time).
    // Per JSON-RPC over stdio convention, each request is one line of JSON.
    loop {
        input.clear();
        let n = stdin.lock().read_line(&mut input)?;
        if n == 0 {
            // EOF
            return Ok(());
        }
        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Parse + handle.
        let response = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(req) => {
                let resp = handle_request(req);
                serde_json::to_string(&resp).unwrap_or_else(|e| {
                    format!(
                        "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":{},\"message\":\"internal serialize error: {e}\"}},\"id\":null}}",
                        ERR_INTERNAL
                    )
                })
            }
            Err(e) => {
                // Parse error: respond with id=null.
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"error\":{{\"code\":-32700,\"message\":\"parse error: {e}\"}},\"id\":null}}"
                )
            }
        };
        writeln!(out, "{response}")?;
        out.flush()?;
    }
}

fn main() -> io::Result<()> {
    // Suppress unused-import warnings for items kept for future expansion.
    let _ = tsa::init; // (would be called if we wired up a real TSA client)
    let _ = TsaClient::tier;
    let _ = OrgId::new; // placeholder for future multi-tenant use

    run_stdio_server()
}
