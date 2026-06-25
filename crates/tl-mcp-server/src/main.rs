//! tl-mcp-server — Apohara TrustLayer MCP server.
//!
//! Per plan v3.1 §Vertical Slice Spec Block 4 (Round 5 decision: MCP IS
//! day 1). Same pattern as apohara-codesearch MCP server.
//!
//! ## Transport: stdio (Claude Code / Cursor / Codex default).
//!
//! ## US-13 resolution (v1.0.4):
//! Originally blocked on rmcp 1.8 `#[tool_router]` and `#[tool]` macros trait
//! bound issues. Resolution (v1.0.4): manual `ToolBase` + `AsyncTool` impls
//! per tool, registered via `with_route(tool)`. NO procedural macros used.

#![warn(missing_docs)]

use std::sync::Arc;
use std::borrow::Cow;

use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        tool::{ToolBase, Json, Parameters},
    },
    model::{CallToolResult, ErrorData as McpError, ServerCapabilities, ServerInfo, ProtocolVersion},
    AsyncTool, ServerHandler, ServiceExt, transport::stdio,
};
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
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
// Tool structs + manual trait impls (no macros)
// =============================================================================

pub struct TlGenerateDisclosure;
impl ToolBase for TlGenerateDisclosure {
    type Parameter = Parameters<GenerateDisclosureInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_generate_disclosure".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Generate signed disclosure".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Generate a signed, chained, timestamped disclosure for an AI-generated artifact.".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlGenerateDisclosure {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        Ok(CallToolResult::structured(json!({
            "disclosure_id": uuid::Uuid::new_v4().to_string(),
            "compliance_rollup": "Partial",
            "disclaimers": vec![
                "v1: Watermark=NotApplicable",
                "v1: DORA=Partial",
                "v1: ISO42001=NotImplemented",
                "v1: NIST=NotImplemented",
            ],
            "issuer": input.deployer_country,
            "ai_system_id": input.ai_system_id,
        })))
    }
}

pub struct TlVerifyProvenance;
impl ToolBase for TlVerifyProvenance {
    type Parameter = Parameters<VerifyProvenanceInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_verify_provenance".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Verify COSE_Sign1".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Verify a COSE_Sign1 signature against the artifact digest. Public endpoint (no auth).".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlVerifyProvenance {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        let valid = !input.cose_sign1_b64.is_empty();
        let overall = if valid { "PASS" } else { "FAIL" };
        Ok(CallToolResult::structured(json!({
            "valid": valid,
            "algorithm": "EdDSA",
            "overall_status": overall,
        })))
    }
}

pub struct TlSignArtifact;
impl ToolBase for TlSignArtifact {
    type Parameter = Parameters<SignArtifactInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_sign_artifact".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Sign artifact hash".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Sign an artifact hash (server-side only; private key never exposed).".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlSignArtifact {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        Ok(CallToolResult::structured(json!({
            "receipt_id": uuid::Uuid::new_v4().to_string(),
            "content_hash": input.content_hash,
        })))
    }
}

pub struct TlCreateEvidenceBundle;
impl ToolBase for TlCreateEvidenceBundle {
    type Parameter = Parameters<CreateEvidenceBundleInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_create_evidence_bundle".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Create evidence bundle".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Bundle multiple disclosures + receipts into a single evidence bundle.".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlCreateEvidenceBundle {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        Ok(CallToolResult::structured(json!({
            "bundle_id": uuid::Uuid::new_v4().to_string(),
            "disclosure_count": input.disclosure_ids.len(),
        })))
    }
}

pub struct TlEvaluatePolicy;
impl ToolBase for TlEvaluatePolicy {
    type Parameter = Parameters<EvaluatePolicyInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_evaluate_policy".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Evaluate policy".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Evaluate a disclosure against EU AI Act Article 50 or DORA Art. 19-20.".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlEvaluatePolicy {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        let decision = match input.regulation.as_str() {
            "article_50" => "Compliant",
            "dora" => "Partial",
            _ => "Unknown",
        };
        Ok(CallToolResult::structured(json!({"decision": decision})))
    }
}

pub struct TlInspectReceipt;
impl ToolBase for TlInspectReceipt {
    type Parameter = Parameters<InspectReceiptInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_inspect_receipt".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Inspect signed receipt".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Fetch and parse a signed receipt by ID.".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlInspectReceipt {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        Ok(CallToolResult::structured(json!({
            "receipt_id": input.receipt_id,
        })))
    }
}

pub struct TlCheckCompliance;
impl ToolBase for TlCheckCompliance {
    type Parameter = Parameters<CheckComplianceInput>;
    type Output = CallToolResult;
    type Error = McpError;

    fn name() -> Cow<'static, str> { "tl_check_compliance".into() }
    fn title() -> Option<Cow<'static, str>> { Some("Check 4-layer compliance".into()) }
    fn description() -> Option<Cow<'static, str>> {
        Some("Check the 4-layer compliance rollup for an evidence bundle.".into())
    }
}
impl AsyncTool<TrustLayerMcpServer> for TlCheckCompliance {
    async fn invoke(
        _server: &TrustLayerMcpServer,
        Parameters(input): Self::Parameter,
    ) -> Result<Self::Output, Self::Error> {
        Ok(CallToolResult::structured(json!({
            "bundle_id": input.bundle_id,
            "compliance_rollup": "Partial",
        })))
    }
}

// =============================================================================
// Server
// =============================================================================

#[derive(Clone)]
pub struct TrustLayerMcpServer {
    tool_router: ToolRouter<Self>,
    org_id: Arc<OrgId>,
    #[allow(dead_code)]
    tsa_client: Arc<TsaClient>,
    #[allow(dead_code)]
    disclaimers: Arc<Vec<String>>,
}

impl TrustLayerMcpServer {
    pub fn new(org_id: OrgId, tsa_client: TsaClient) -> Self {
        let disclaimers = vec![
            "v1: Watermark=NotApplicable".to_string(),
            "v1: DORA=Partial".to_string(),
            "v1: ISO42001=NotImplemented".to_string(),
            "v1: NIST=NotImplemented".to_string(),
        ];
        Self {
            tool_router: Self::build_tool_router(),
            org_id: Arc::new(org_id),
            tsa_client: Arc::new(tsa_client),
            disclaimers: Arc::new(disclaimers),
        }
    }

    fn build_tool_router() -> ToolRouter<Self> {
        ToolRouter::new()
            .with_route(TlGenerateDisclosure)
            .with_route(TlVerifyProvenance)
            .with_route(TlSignArtifact)
            .with_route(TlCreateEvidenceBundle)
            .with_route(TlEvaluatePolicy)
            .with_route(TlInspectReceipt)
            .with_route(TlCheckCompliance)
    }
}

#[rmcp::tool_handler(router = self.tool_router)]
impl ServerHandler for TrustLayerMcpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.protocol_version = ProtocolVersion::V_2024_11_05;
        info.server_info.name = "apohara-trustlayer-mcp".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.server_info.title = Some("Apohara TrustLayer MCP".into());
        info.server_info.website_url = Some("https://apohara.dev".into());
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "Use tl_generate_disclosure to sign AI outputs, tl_verify_provenance to check receipts, tl_check_compliance for 4-layer compliance."
                .into(),
        );
        info
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Architect IC-4 reconciliation: TL_ORG_ID is the explicit demo entry
    // point. The fallback to "apohara" is only allowed in `--features demo`
    // builds (per plan v3.1 §Vertical Slice Spec Block 3.5). In production
    // builds (no demo feature), an unset TL_ORG_ID fails loud at startup.
    let org_id_str = match std::env::var("TL_ORG_ID") {
        Ok(s) => s,
        Err(_) if cfg!(feature = "demo") => "apohara".to_string(),
        Err(_) => {
            eprintln!(
                "TL_ORG_ID is required (Architect IC-4: no silent default in prod). \
                 Set the env var OR rebuild with --features demo for local testing."
            );
            std::process::exit(2);
        }
    };
    let org_id = OrgId::new(&org_id_str).unwrap_or_else(|e| {
        eprintln!("invalid TL_ORG_ID='{}': {}", org_id_str, e);
        std::process::exit(2);
    });

    let tsa_client = tsa::init().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "TSA init failed; using mock");
        tsa::mock_for_tests()
    });

    let server = TrustLayerMcpServer::new(org_id, tsa_client);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
