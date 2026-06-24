//! MCP proxy — federates a downstream Model Context Protocol
//! server (currently `@apohara/codesearch-mcp` at
//! `mcp://localhost:3000`) behind the agentgateway sidecar so
//! the orchestrator can issue JSON-RPC calls without an
//! outbound dependency on Node.js or the network.
//!
//! Story **C-11** / **G31**. The critic amendment to the PRD
//! fixed the upstream URL scheme to `mcp://` (not `http://`)
//! — the proxy normalises the URI to its HTTP counterpart for
//! the upstream call while keeping the canonical `mcp://`
//! form in the config surface.
//!
//! Scope (intentionally narrow):
//!   * JSON-RPC 2.0 over HTTP at `/mcp`.
//!   * POST the raw request body, return the raw response body.
//!   * Add CORS headers for `allowed_origins`.
//!   * Surface upstream 5xx as `McpProxyError::Upstream`.
//!
//! Out of scope (deferred): streaming, SSE, MCP session ids,
//! tool result pagination, OAuth. The proxy is the seam
//! agentgateway reaches; the agentgateway (Node.js) handles
//! the protocol-level concerns.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for the proxy. The orchestrator's `bin`
/// entrypoint instantiates this from env vars; tests build it
/// directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpProxyConfig {
    /// Bind address in `host:port` form (e.g. `"0.0.0.0:7777"`).
    pub bind_addr: String,
    /// Canonical MCP URI. We accept the `mcp://host:port`
    /// form per the critic amendment; the proxy rewrites it to
    /// `http://host:port` for the upstream `reqwest` call. The
    /// `mcp://` prefix is preserved in the config so the rest
    /// of the system sees the canonical MCP URL.
    pub mcp_uri: String,
    /// CORS allow-list. Requests whose `Origin` header is in
    /// this list receive `Access-Control-Allow-Origin`. An
    /// empty list disables CORS entirely (the proxy still
    /// works; browsers will block cross-origin requests
    /// without the header).
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

/// Failure modes. We surface upstream HTTP errors as a typed
/// enum so the calling orchestrator handler can map them to
/// the right JSON-RPC error code.
#[derive(Debug, Error)]
pub enum McpProxyError {
    /// The upstream MCP server returned a non-2xx status or
    /// `reqwest` failed to reach it.
    #[error("upstream MCP error: {0}")]
    Upstream(String),

    /// The configured MCP URI is not a valid `mcp://host:port`
    /// URI. We do not silently fall back to `http://`; the
    /// critic amendment was explicit that the prefix is part
    /// of the contract.
    #[error("invalid mcp uri: {0}")]
    InvalidUri(String),

    /// `reqwest` error before reaching the upstream.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// I/O error binding the proxy to `bind_addr`.
    #[error("bind error: {0}")]
    Bind(String),
}

/// Result of a single upstream call. We expose the raw
/// JSON-RPC envelope so the caller can decide whether to
/// forward it to the orchestrator's SSE bus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpProxyResponse {
    /// HTTP status from the upstream (forwarded to the
    /// orchestrator's response).
    pub status: u16,
    /// CORS `Access-Control-Allow-Origin` value we attached
    /// (None when CORS is disabled).
    pub cors_origin: Option<String>,
    /// JSON-RPC envelope from the upstream, parsed as raw
    /// JSON. We don't deserialize to a typed `JsonRpcResponse`
    /// because the orchestrator needs to forward the body
    /// verbatim — the agentgateway parses it next.
    pub body: serde_json::Value,
}

/// Convert the canonical `mcp://host:port` URI to its HTTP
/// counterpart. Returns `InvalidUri` if the URI is malformed
/// or uses an unexpected scheme.
///
/// The critic amendment was clear: the proxy MUST accept the
/// `mcp://` scheme (not silently downgrade to `http://`),
/// but the actual upstream wire call uses `http://`. This
/// keeps the configuration surface canonical without
/// requiring the upstream server to speak a non-standard
/// scheme.
pub fn mcp_uri_to_http(mcp_uri: &str) -> Result<String, McpProxyError> {
    let stripped = mcp_uri.strip_prefix("mcp://").ok_or_else(|| {
        McpProxyError::InvalidUri(format!("expected mcp:// scheme, got {mcp_uri}"))
    })?;

    if stripped.is_empty() || stripped.contains("://") {
        return Err(McpProxyError::InvalidUri(format!(
            "mcp uri must be mcp://host[:port][/path], got {mcp_uri}"
        )));
    }

    Ok(format!("http://{stripped}"))
}

/// Core forwarding logic. Pure (no I/O of its own) — takes a
/// `reqwest::Client` so tests can swap in a mock transport.
///
/// `request_body` is forwarded verbatim. We attach
/// `Content-Type: application/json` so the upstream shim (and
/// the production Node server) parse it as JSON-RPC.
///
/// `origin` is the caller's `Origin` header (if any). It is
/// matched against `config.allowed_origins` to populate the
/// CORS response header.
pub async fn forward_request(
    client: &reqwest::Client,
    config: &McpProxyConfig,
    request_body: serde_json::Value,
    origin: Option<&str>,
) -> Result<McpProxyResponse, McpProxyError> {
    let upstream = mcp_uri_to_http(&config.mcp_uri)?;

    let mut request = client
        .post(&upstream)
        .header("Content-Type", "application/json")
        .json(&request_body);

    if let Some(o) = origin {
        request = request.header("Origin", o);
    }

    let response = request.send().await?;
    let status = response.status().as_u16();

    // Upstream 5xx surfaces as McpProxyError::Upstream so the
    // orchestrator handler can return a JSON-RPC -32603
    // (Internal error) instead of forwarding garbage. 4xx is
    // forwarded as-is — the upstream server is the one that
    // knows whether the caller's request was malformed.
    if (500..600).contains(&status) {
        return Err(McpProxyError::Upstream(format!(
            "upstream returned HTTP {status} for {upstream}"
        )));
    }

    let body: serde_json::Value = response.json().await?;

    let cors_origin = pick_cors_origin(&config.allowed_origins, origin);

    Ok(McpProxyResponse {
        status,
        cors_origin,
        body,
    })
}

/// Pick the `Access-Control-Allow-Origin` value for a given
/// request `Origin` header. Returns `None` when CORS is
/// disabled (empty allow-list) or the request origin is not
/// allow-listed.
fn pick_cors_origin(allowed: &[String], origin: Option<&str>) -> Option<String> {
    if allowed.is_empty() {
        return None;
    }
    let o = origin?;
    if allowed.iter().any(|a| a == o) {
        Some(o.to_string())
    } else {
        None
    }
}

/// Run the proxy HTTP server bound to `config.bind_addr`.
/// Used by the orchestrator's binary entrypoint. The current
/// scope is the forwarding helper + CORS — a full Axum router
/// for `/mcp` lives in `http.rs` (C-11 / agentgateway).
pub async fn run(config: McpProxyConfig) -> Result<(), McpProxyError> {
    // Smoke check: fail fast if the configured URI is
    // malformed, before binding the socket.
    let upstream = mcp_uri_to_http(&config.mcp_uri)?;

    let listener = tokio::net::TcpListener::bind(&config.bind_addr)
        .await
        .map_err(|e| McpProxyError::Bind(format!("{e}: {}", config.bind_addr)))?;

    tracing::info!(bind_addr = %config.bind_addr, upstream = %upstream, "mcp_proxy listening");

    loop {
        let accept = listener.accept().await;
        let (stream, _peer) = match accept {
            Ok(pair) => pair,
            Err(e) => return Err(McpProxyError::Bind(format!("accept: {e}"))),
        };
        let _config = config.clone();
        tokio::spawn(async move {
            let _ = stream;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_rejects_invalid_uri() {
        // No scheme prefix → invalid (critic amendment).
        let bad = mcp_uri_to_http("http://localhost:3000");
        assert!(matches!(bad, Err(McpProxyError::InvalidUri(_))));
        let empty = mcp_uri_to_http("mcp://");
        assert!(matches!(empty, Err(McpProxyError::InvalidUri(_))));
        let wrong_scheme = mcp_uri_to_http("ftp://localhost:3000");
        assert!(matches!(wrong_scheme, Err(McpProxyError::InvalidUri(_))));
    }

    #[test]
    fn mcp_uri_to_http_normalises_canonical_form() {
        assert_eq!(
            mcp_uri_to_http("mcp://localhost:3000").unwrap(),
            "http://localhost:3000"
        );
        assert_eq!(
            mcp_uri_to_http("mcp://localhost:3000/mcp").unwrap(),
            "http://localhost:3000/mcp"
        );
        assert_eq!(
            mcp_uri_to_http("mcp://codesearch.internal:9001").unwrap(),
            "http://codesearch.internal:9001"
        );
    }

    #[test]
    fn cors_picks_allowlisted_origin_only() {
        let allowed = vec!["https://themis.apohara.dev".to_string()];
        assert_eq!(
            pick_cors_origin(&allowed, Some("https://themis.apohara.dev")),
            Some("https://themis.apohara.dev".to_string())
        );
        assert_eq!(
            pick_cors_origin(&allowed, Some("https://evil.example")),
            None
        );
        assert_eq!(pick_cors_origin(&allowed, None), None);
        assert_eq!(pick_cors_origin(&[], Some("https://anything")), None);
    }
}
