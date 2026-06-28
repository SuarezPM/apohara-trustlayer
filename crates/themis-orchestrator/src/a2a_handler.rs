//! A2A 1.0 (Google Agent2Agent) JSON-RPC 2.0 endpoint.
//!
//! Story C-01 / G24-G26. Lets external peers:
//!
//! 1. Discover the orchestrator via `GET /.well-known/agent-card.json`
//!    (the `agent_card_json` constant re-exported from
//!    `themis_frontend`).
//! 2. List all 6 agents in the fleet via `GET /agents.json`.
//! 3. Submit a JSON-RPC 2.0 envelope at `POST /a2a`. The supported
//!    methods are:
//!
//!    * `message/send` — kick off `process_invoice` with the
//!      envelope's `params` as the invoice payload. The orchestrator
//!      reuses the same code path as the demo's `POST /invoices`.
//!    * `tasks/get` — look up a previously-submitted task by id.
//!      Story C-01 ships this as a no-op stub (returns 404 for any
//!      unknown id) because THEMIS does not yet persist tasks
//!      out-of-process; C-09+ will add the durable task store.
//!    * `agent/authenticatedExtendedCard` — return the same agent
//!      card served at the well-known URL, but tagged as
//!      "extended" (the live card doesn't carry secrets in C-01;
//!      the extended variant is a placeholder for the C-12 mock
//!      fallback).
//!
//! Auth: Ed25519 bearer in `Authorization: Ed25519Bearer <hex>`. The
//! C-01 contract is a **mock verifier** — any non-empty hex string
//! is accepted with a `tracing::warn!` so the demo's happy path
//! works without a real verifier wired in. C-02 (AgentGuard sandbox)
//! is the right home for the real Ed25519 verification path.
//!
//! Errors follow the JSON-RPC 2.0 spec (see
//! <https://www.jsonrpc.org/specification#error_object>):
//!
//! ```json
//! {"jsonrpc": "2.0", "id": <id>, "error": {"code": -32600, "message": "..."}}
//! ```

//! Errors follow the JSON-RPC 2.0 spec (see
//! <https://www.jsonrpc.org/specification#error_object>):
//!
//! ```json
//! {"jsonrpc": "2.0", "id": <id>, "error": {"code": -32600, "message": "..."}}
//! ```
#![allow(missing_docs)] // The serde-derived structs are self-describing.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use themis_frontend::{AGENTS_JSON, AGENT_CARD_JSON};
use uuid::Uuid;

use crate::events::Event;
use crate::http::AppState;
use crate::packet::PeerVerdict;

/// JSON-RPC 2.0 protocol version string. Every envelope we
/// accept must declare this; every response we emit includes it.
const JSONRPC_VERSION: &str = "2.0";

/// Standard JSON-RPC 2.0 error codes we emit. See
/// <https://www.jsonrpc.org/specification#error_object>.
const ERR_PARSE: i32 = -32700; // Invalid JSON
const ERR_INVALID_REQUEST: i32 = -32600; // Not a valid JSON-RPC envelope
const ERR_METHOD_NOT_FOUND: i32 = -32601; // Method not implemented
const ERR_INVALID_PARAMS: i32 = -32602; // Method params invalid
const ERR_INTERNAL: i32 = -32603; // Internal server error

/// Inbound JSON-RPC 2.0 envelope. The spec allows `id` to be a
/// string, number, or null; we accept any JSON value and echo
/// it back unchanged.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be `"2.0"`. Validated by `parse_envelope` (returning
    /// `ERR_INVALID_REQUEST` if absent or wrong).
    pub jsonrpc: Option<String>,
    /// Caller-defined id; echoed back in the response.
    pub id: Option<Value>,
    /// Method name (e.g. `"message/send"`, `"tasks/get"`).
    pub method: Option<String>,
    /// Method params. Free-form; the per-method parser is
    /// responsible for shape validation.
    #[serde(default)]
    pub params: Value,
}

/// Outbound JSON-RPC 2.0 success response.
#[derive(Debug, Serialize)]
pub struct JsonRpcSuccess {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub result: Value,
}

/// Outbound JSON-RPC 2.0 error response.
#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub jsonrpc: &'static str,
    pub id: Value,
    pub error: JsonRpcErrorBody,
}

/// Body of a JSON-RPC 2.0 error response.
#[derive(Debug, Serialize)]
pub struct JsonRpcErrorBody {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// `POST /a2a` — JSON-RPC 2.0 entrypoint. Public so the router
/// module in `http.rs` can mount it without exposing the
/// internals.
pub async fn post_a2a(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 1. Ed25519 bearer auth (mock for C-01). A real verifier
    //    lands in C-02 (AgentGuard sandbox) — the protocol
    //    here is the contract, the verifier is the impl.
    if let Some(reason) = mock_ed25519_bearer_check(&headers) {
        return jsonrpc_error(
            StatusCode::UNAUTHORIZED,
            Value::Null,
            -32001,
            format!("unauthorized: {reason}"),
            None,
        );
    }

    // 2. Parse the envelope. We accept raw bytes so we can
    //    distinguish "invalid JSON" (ERR_PARSE, 400) from "valid
    //    JSON but not a JSON-RPC envelope" (ERR_INVALID_REQUEST,
    //    400) — the critic amendment requires 400, not 500.
    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                ERR_PARSE,
                format!("parse error: {e}"),
                None,
            );
        }
    };

    // 3. Envelope shape. Spec requires `jsonrpc: "2.0"` and
    //    a non-null `method`. If the caller sent `{"garbage":true}`
    //    we land here — return 400 with ERR_INVALID_REQUEST.
    if req.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
        return jsonrpc_error(
            StatusCode::BAD_REQUEST,
            req.id.unwrap_or(Value::Null),
            ERR_INVALID_REQUEST,
            "jsonrpc field must be \"2.0\"".to_string(),
            None,
        );
    }
    let method = match req.method.as_deref() {
        Some(m) if !m.is_empty() => m.to_string(),
        _ => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                req.id.unwrap_or(Value::Null),
                ERR_INVALID_REQUEST,
                "method is required".to_string(),
                None,
            );
        }
    };

    // 4. Dispatch by method.
    let id = req.id.unwrap_or(Value::Null);
    match method.as_str() {
        "message/send" => handle_message_send(&state, id, req.params).await,
        "tasks/get" => handle_tasks_get(&state, id, req.params).await,
        "peer_verdict/attach" => handle_peer_verdict_attach(id, req.params).await,
        "agent/authenticatedExtendedCard" => handle_extended_card(id).await,
        other => jsonrpc_error(
            StatusCode::NOT_FOUND,
            id,
            ERR_METHOD_NOT_FOUND,
            format!("method not found: {other}"),
            None,
        ),
    }
}

/// `GET /.well-known/agent-card.json` — serve the embedded
/// A2A 1.0 agent card. Public so the router module in
/// `http.rs` can mount it.
pub async fn get_agent_card() -> Response {
    json_response(StatusCode::OK, AGENT_CARD_JSON)
}

/// `GET /agents.json` — serve the machine-readable fleet
/// registry. Public so the router module in `http.rs` can
/// mount it.
pub async fn get_agents_json() -> Response {
    json_response(StatusCode::OK, AGENTS_JSON)
}

// --- Method handlers ---

/// `message/send` — accept an A2A message envelope and dispatch
/// to the orchestrator. The `params` shape is permissive
/// (free-form JSON object) and the handler extracts a minimal
/// `{tenant_id, invoice_id, raw_b64}` triple. This is the
/// C-01 surface; richer param shapes (A2A `parts`, `messages`)
/// land in C-09+ when the orchestrator adopts the A2A
/// "message" data model end-to-end.
async fn handle_message_send(state: &Arc<AppState>, id: Value, params: Value) -> Response {
    let p = match params.as_object() {
        Some(o) => o,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params must be an object".to_string(),
                None,
            );
        }
    };
    let tenant_id = match p.get("tenant_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.tenant_id (string) is required".to_string(),
                None,
            );
        }
    };
    let invoice_id = match p.get("invoice_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.invoice_id (string) is required".to_string(),
                None,
            );
        }
    };
    // raw_b64 is optional. A2A peers that ship a JSON-only
    // "message" (no document) get an empty raw payload — the
    // orchestrator's extractor agent will fail gracefully and
    // the run will halt, which is the right BAAAR behavior.
    let raw_b64 = p
        .get("raw_b64")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let raw = base64::engine::general_purpose::STANDARD
        .decode(raw_b64)
        .unwrap_or_default();

    let run_id = Uuid::new_v4();
    state.event_bus().publish(Event::ProviderActive {
        run_id,
        model_id: state.model_id().to_string(),
    });
    state.event_bus().publish(Event::AgentStarted {
        run_id,
        agent: "extractor".to_string(),
    });

    // Reuse the orchestrator's process_invoice path. We
    // intentionally do NOT use process_invoice_sealed here
    // because (a) the A2A surface is for read-mostly discovery
    // peers, not the live demo, and (b) keeping the
    // non-sealed path means the A2A call has zero dependency
    // on the evidence service being wired.
    let packet = {
        let orch = state.orchestrator().lock().await;
        match orch.process_invoice(&tenant_id, &invoice_id, raw).await {
            Ok(p) => p,
            Err(e) => {
                return jsonrpc_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    id,
                    ERR_INTERNAL,
                    format!("process_invoice failed: {e:?}"),
                    None,
                );
            }
        }
    };

    state.event_bus().publish(Event::EvidenceSealed {
        run_id,
        packet_id: packet.packet().packet_id(),
    });
    state.event_bus().publish(Event::RunFinished { run_id });

    // Build the A2A task object. We use a `task` shape (not a
    // `message` shape) because the orchestrator is a
    // long-running agent that returns a result the peer can
    // later fetch via `tasks/get`.
    let task_id = packet.packet().packet_id();
    a2a_tasks().insert(
        task_id,
        A2ATaskRecord {
            run_id,
            tenant_id: tenant_id.clone(),
            invoice_id: invoice_id.clone(),
            packet_id: task_id,
        },
    );

    let result = json!({
        "task": {
            "id": task_id.to_string(),
            "context_id": run_id.to_string(),
            "status": {
                "state": "completed",
                "message": {
                    "role": "agent",
                    "parts": [{
                        "kind": "data",
                        "data": {
                            "tenant_id": tenant_id,
                            "invoice_id": invoice_id,
                            "run_id": run_id.to_string(),
                            "packet_id": task_id.to_string(),
                            "verdict": format!("{:?}", packet.packet().bbaaar_outcome()),
                        }
                    }]
                }
            }
        }
    });
    jsonrpc_success(StatusCode::OK, id, result)
}

/// `tasks/get` — return a previously-completed task. Stub for
/// C-01: looks up an in-memory map populated by `message/send`.
/// C-09+ replaces this with a durable task store (Postgres or
/// a `themis-tasks` crate).
async fn handle_tasks_get(_state: &Arc<AppState>, id: Value, params: Value) -> Response {
    let p = match params.as_object() {
        Some(o) => o,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params must be an object with `id`".to_string(),
                None,
            );
        }
    };
    let task_id_str = match p.get("id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.id (string) is required".to_string(),
                None,
            );
        }
    };
    let task_id = match Uuid::parse_str(task_id_str) {
        Ok(u) => u,
        Err(_) => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.id must be a UUID".to_string(),
                None,
            );
        }
    };
    match a2a_tasks().get(&task_id) {
        Some(rec) => {
            // Surface any peer verdicts attached to this packet
            // (Story C-12 / G27 / FIX-4). The key is always
            // present so the UI can render a stable "0 of N" state.
            let peer_verdicts: Vec<Value> = a2a_peer_verdicts()
                .get(&task_id)
                .map(|v| v.iter().map(|p| json!(p)).collect())
                .unwrap_or_default();
            let result = json!({
                "task": {
                    "id": rec.packet_id.to_string(),
                    "context_id": rec.run_id.to_string(),
                    "status": {
                        "state": "completed",
                        "message": {
                            "role": "agent",
                            "parts": [{
                                "kind": "data",
                                "data": {
                                    "tenant_id": rec.tenant_id,
                                    "invoice_id": rec.invoice_id,
                                    "run_id": rec.run_id.to_string(),
                                    "packet_id": rec.packet_id.to_string(),
                                    "peer_verdicts": peer_verdicts,
                                }
                            }]
                        }
                    }
                }
            });
            jsonrpc_success(StatusCode::OK, id, result)
        }
        None => jsonrpc_error(
            StatusCode::NOT_FOUND,
            id,
            -32004, // Custom: task not found (outside the standard JSON-RPC range)
            format!("task {task_id} not found"),
            None,
        ),
    }
}

/// `agent/authenticatedExtendedCard` — return the live agent
/// card. In C-01 the card is public (no secrets); this method
/// is here so peers that always call the extended variant
/// (a convention from Google's A2A reference impl) get a
/// 200 with the same payload.
async fn handle_extended_card(id: Value) -> Response {
    let mut card: Value = serde_json::from_str(AGENT_CARD_JSON).unwrap_or_else(|_| json!({}));
    if let Some(obj) = card.as_object_mut() {
        obj.insert("extended".to_string(), json!(true));
    }
    jsonrpc_success(StatusCode::OK, id, json!({"card": card}))
}

/// `peer_verdict/attach` — accept a structured fraud-auditor
/// verdict from an external peer agent (PydanticAI, LangGraph,
/// CrewAI) and stash it on the matching in-flight task. Story
/// C-12 / G27 / FIX-4.
async fn handle_peer_verdict_attach(id: Value, params: Value) -> Response {
    let p = match params.as_object() {
        Some(o) => o,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params must be an object".to_string(),
                None,
            );
        }
    };
    let packet_id_str = match p.get("packet_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.packet_id (string) is required".to_string(),
                None,
            );
        }
    };
    let packet_id = match Uuid::parse_str(packet_id_str) {
        Ok(u) => u,
        Err(_) => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.packet_id must be a UUID".to_string(),
                None,
            );
        }
    };
    if !a2a_tasks().contains_key(&packet_id) {
        return jsonrpc_error(
            StatusCode::NOT_FOUND,
            id,
            -32004,
            format!("task {packet_id} not found"),
            None,
        );
    }
    let verdict_value = match p.get("verdict").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "params.verdict (object) is required".to_string(),
                None,
            );
        }
    };
    let agent = match verdict_value.get("agent").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "verdict.agent (string) is required".to_string(),
                None,
            );
        }
    };
    let risk_score = match verdict_value.get("risk_score").and_then(|v| v.as_f64()) {
        Some(s) => s,
        None => {
            return jsonrpc_error(
                StatusCode::BAD_REQUEST,
                id,
                ERR_INVALID_PARAMS,
                "verdict.risk_score (number) is required".to_string(),
                None,
            );
        }
    };
    let recommendation = verdict_value
        .get("recommendation")
        .and_then(|v| v.as_str())
        .unwrap_or("approve")
        .to_string();
    let findings = verdict_value
        .get("findings")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();
    let timestamp_ms = verdict_value
        .get("timestamp_ms")
        .and_then(|v| v.as_i64())
        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis());

    let verdict = PeerVerdict {
        agent,
        risk_score,
        findings,
        recommendation,
        timestamp_ms,
    };
    a2a_peer_verdicts()
        .entry(packet_id)
        .or_default()
        .push(verdict.clone());

    jsonrpc_success(
        StatusCode::OK,
        id,
        json!({
            "attached": true,
            "packet_id": packet_id.to_string(),
            "agent": verdict.agent,
            "count": a2a_peer_verdicts().get(&packet_id).map(|v| v.len()).unwrap_or(0),
        }),
    )
}

// --- Helpers ---

/// Mock Ed25519 bearer check. The C-01 contract is "accept any
/// non-empty hex signature, log a warning". The C-02 story
/// (AgentGuard sandbox) is the right home for the real
/// verifier; this is the protocol stub.
fn mock_ed25519_bearer_check(headers: &axum::http::HeaderMap) -> Option<&'static str> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if auth.is_empty() {
        return Some("missing Authorization header");
    }
    if !auth.starts_with("Ed25519Bearer ") {
        return Some("expected scheme 'Ed25519Bearer'");
    }
    let sig = &auth["Ed25519Bearer ".len()..];
    if sig.is_empty() {
        return Some("empty signature");
    }
    if sig.len() < 16 {
        return Some("signature too short (need >=16 hex chars)");
    }
    // Hex sanity (cheap pre-check; the real verifier lives in
    // C-02 and is a full ed25519_dalek verify).
    if !sig.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some("signature contains non-hex chars");
    }
    tracing::warn!(
        sig_prefix = &sig[..sig.len().min(16)],
        "mock Ed25519 bearer accepted (C-01 stub); real verification lands in C-02 (AgentGuard)"
    );
    None
}

fn jsonrpc_success(status: StatusCode, id: Value, result: Value) -> Response {
    let body = JsonRpcSuccess {
        jsonrpc: JSONRPC_VERSION,
        id,
        result,
    };
    (status, Json(body)).into_response()
}

fn jsonrpc_error(
    status: StatusCode,
    id: Value,
    code: i32,
    message: String,
    data: Option<Value>,
) -> Response {
    let body = JsonRpcError {
        jsonrpc: JSONRPC_VERSION,
        id,
        error: JsonRpcErrorBody {
            code,
            message,
            data,
        },
    };
    (status, Json(body)).into_response()
}

fn json_response(status: StatusCode, body: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=60")
        .body(axum::body::Body::from(body.to_string()))
        .expect("static JSON response builder")
}

// --- In-memory task store (stub for C-01) ---

/// In-process A2A task store. The map is global because the
/// A2A handler runs as a singleton (one axum router per
/// process); the alternative — thread the map through
/// `AppState` — would couple the A2A surface to the live
/// demo state, which is the wrong blast radius. C-09 replaces
/// this with a durable store.
static A2A_TASKS: std::sync::OnceLock<DashMap<Uuid, A2ATaskRecord>> = std::sync::OnceLock::new();

fn a2a_tasks() -> &'static DashMap<Uuid, A2ATaskRecord> {
    A2A_TASKS.get_or_init(DashMap::new)
}

/// In-process peer-verdict store. Keyed by packet_id; the value
/// is a `Vec<PeerVerdict>` because multiple peer agents (PydanticAI,
/// LangGraph, CrewAI) may attach to the same task.
static A2A_PEER_VERDICTS: std::sync::OnceLock<DashMap<Uuid, Vec<PeerVerdict>>> =
    std::sync::OnceLock::new();

fn a2a_peer_verdicts() -> &'static DashMap<Uuid, Vec<PeerVerdict>> {
    A2A_PEER_VERDICTS.get_or_init(DashMap::new)
}

#[derive(Debug, Clone)]
struct A2ATaskRecord {
    run_id: Uuid,
    tenant_id: String,
    invoice_id: String,
    packet_id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_card_json_parses_and_is_a2a_1_0() {
        let v: Value = serde_json::from_str(AGENT_CARD_JSON).unwrap();
        assert_eq!(v["protocolVersion"], "1.0");
        assert_eq!(v["name"], "THEMIS Orchestrator");
        let skills = v["skills"].as_array().unwrap();
        assert!(!skills.is_empty());
        let skill_ids: Vec<&str> = skills
            .iter()
            .map(|s| s["id"].as_str().unwrap_or(""))
            .collect();
        assert!(skill_ids.contains(&"process_invoice"));
        assert!(skill_ids.contains(&"halt_audit"));
        assert!(skill_ids.contains(&"compliance_report"));
    }

    #[test]
    fn agents_json_has_six_agents() {
        let v: Value = serde_json::from_str(AGENTS_JSON).unwrap();
        let agents = v["agents"].as_array().unwrap();
        // Shipped registry: 7 entries (orchestrator + 6
        // specialists). The "≥6" assertion is forward-compatible
        // with C-12 (cross-framework peers append to the list).
        assert!(
            agents.len() >= 6,
            "expected at least 6 agents, got {}",
            agents.len()
        );
        let ids: Vec<&str> = agents
            .iter()
            .map(|a| a["id"].as_str().unwrap_or(""))
            .collect();
        assert!(ids.contains(&"themis-orchestrator"));
        assert!(ids.contains(&"extractor"));
        assert!(ids.contains(&"honesty-auditor"));
    }

    #[test]
    fn mock_bearer_check_rejects_missing_header() {
        let h = axum::http::HeaderMap::new();
        assert!(mock_ed25519_bearer_check(&h).is_some());
    }

    #[test]
    fn mock_bearer_check_rejects_wrong_scheme() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert!(mock_ed25519_bearer_check(&h).is_some());
    }

    #[test]
    fn mock_bearer_check_accepts_any_hex() {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Ed25519Bearer deadbeefcafebabe1234".parse().unwrap(),
        );
        assert!(mock_ed25519_bearer_check(&h).is_none());
    }

    #[test]
    fn jsonrpc_error_shape_is_spec_compliant() {
        let body = JsonRpcError {
            jsonrpc: JSONRPC_VERSION,
            id: json!(1),
            error: JsonRpcErrorBody {
                code: ERR_INVALID_REQUEST,
                message: "bad".to_string(),
                data: None,
            },
        };
        let s = serde_json::to_string(&body).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 1);
        assert_eq!(v["error"]["code"], -32600);
    }

    /// Seed the global A2A task store with one task and return its
    /// packet id. Test helper.
    fn seed_task() -> Uuid {
        let id = Uuid::new_v4();
        a2a_tasks().insert(
            id,
            A2ATaskRecord {
                run_id: Uuid::new_v4(),
                tenant_id: "stark".to_string(),
                invoice_id: "inv-test".to_string(),
                packet_id: id,
            },
        );
        id
    }

    async fn response_json(resp: axum::response::Response) -> Value {
        let body = resp.into_body();
        let bytes = axum::body::to_bytes(body, 64 * 1024)
            .await
            .map(|b| b.to_vec())
            .unwrap_or_default();
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    #[tokio::test]
    async fn peer_verdict_attach_stores_and_returns_envelope() {
        let packet_id = seed_task();
        let params = json!({
            "packet_id": packet_id.to_string(),
            "verdict": {
                "agent": "peer_pydantic_ai",
                "risk_score": 0.42,
                "findings": ["amount within policy"],
                "recommendation": "approve",
                "timestamp_ms": 1_700_000_000_000_i64,
            }
        });
        let resp = handle_peer_verdict_attach(json!(1), params).await;
        let v = response_json(resp).await;
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["result"]["attached"], true);
        assert_eq!(v["result"]["agent"], "peer_pydantic_ai");
        assert_eq!(v["result"]["count"], 1);
        let stored = a2a_peer_verdicts().get(&packet_id).expect("verdict stored");
        assert_eq!(stored.len(), 1);
        assert!((stored[0].risk_score - 0.42).abs() < 1e-9);
        assert_eq!(stored[0].recommendation, "approve");
    }

    #[tokio::test]
    async fn peer_verdict_attach_rejects_unknown_packet() {
        let params = json!({
            "packet_id": Uuid::new_v4().to_string(),
            "verdict": {"agent": "ghost", "risk_score": 0.5, "recommendation": "approve"}
        });
        let resp = handle_peer_verdict_attach(json!(1), params).await;
        let v = response_json(resp).await;
        assert_eq!(v["error"]["code"], -32004);
    }

    #[tokio::test]
    async fn peer_verdict_attach_validates_required_fields() {
        let packet_id = seed_task();
        let params = json!({
            "packet_id": packet_id.to_string(),
            "verdict": {"agent": "x", "recommendation": "approve"}
        });
        let resp = handle_peer_verdict_attach(json!(1), params).await;
        let v = response_json(resp).await;
        assert_eq!(v["error"]["code"], -32602);
    }
}
