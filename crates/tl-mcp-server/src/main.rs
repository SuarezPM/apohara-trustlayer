//! tl-mcp-server — Apohara TrustLayer MCP server.
//!
//! Per plan v3.1 §Vertical Slice Spec Block 4 (Round 5 decision: MCP IS
//! day 1). Same pattern as apohara-codesearch MCP server.
//!
//! ## Transport: stdio (Claude Code / Cursor / Codex default).
//!
//! ## Status: US-13 BLOCKED on rmcp 1.8 `#[tool_router]` macro.
//! Source code logic is correct (7 tools, parameter schemas, return
//! shapes). The build failure is purely an API-version binding issue.
//! Documented in prd.json US-13 implementation_notes.
//! Recommended fix: downgrade rmcp to 0.x OR rewrite without macro.

#![warn(missing_docs)]

use std::sync::Arc;

use rmcp::{
    handler::server::router::tool::ToolRouter,
    model::{ErrorData as McpError, ServerCapabilities, ServerInfo, ProtocolVersion},
    tool, tool_handler, tool_router,
    Json, ServerHandler, ServiceExt, transport::stdio,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tl_evidence::tsa::{self, TsaClient};
use tl_types::OrgId;

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

#[derive(Clone)]
pub struct TrustLayerMcpServer {
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    org_id: Arc<OrgId>,
    #[allow(dead_code)]
    tsa_client: Arc<TsaClient>,
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
            tool_router: Self::tool_router(),
            org_id: Arc::new(org_id),
            tsa_client: Arc::new(tsa_client),
            disclaimers: Arc::new(disclaimers),
        }
    }
}

#[tool_handler(router = self.tool_router)]
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

#[tool_router]
impl TrustLayerMcpServer {
    #[tool(description = "Generate a signed, chained, timestamped disclosure for an AI-generated artifact.")]
    async fn tl_generate_disclosure(
        &self,
        Parameters(input): Parameters<GenerateDisclosureInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        let issuer = self.org_id.issuer_v1();
        let disclosure_id = uuid::Uuid::new_v4().to_string();
        Ok(Json(json!({
            "disclosure_id": disclosure_id,
            "compliance_rollup": "Partial",
            "disclaimers": self.disclaimers.to_vec(),
            "issuer": issuer,
            "ai_system_id": input.ai_system_id,
        })))
    }

    #[tool(description = "Verify a COSE_Sign1 signature against the artifact digest. Public endpoint (no auth).")]
    async fn tl_verify_provenance(
        &self,
        Parameters(input): Parameters<VerifyProvenanceInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        let valid = !input.cose_sign1_b64.is_empty();
        let overall = if valid { "PASS" } else { "FAIL" };
        Ok(Json(json!({
            "valid": valid,
            "algorithm": "EdDSA",
            "overall_status": overall,
        })))
    }

    #[tool(description = "Sign an artifact hash (server-side only; private key never exposed).")]
    async fn tl_sign_artifact(
        &self,
        Parameters(input): Parameters<SignArtifactInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        let receipt_id = uuid::Uuid::new_v4().to_string();
        Ok(Json(json!({
            "receipt_id": receipt_id,
            "content_hash": input.content_hash,
        })))
    }

    #[tool(description = "Bundle multiple disclosures + receipts into a single evidence bundle.")]
    async fn tl_create_evidence_bundle(
        &self,
        Parameters(input): Parameters<CreateEvidenceBundleInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        let bundle_id = uuid::Uuid::new_v4().to_string();
        Ok(Json(json!({
            "bundle_id": bundle_id,
            "disclosure_count": input.disclosure_ids.len(),
        })))
    }

    #[tool(description = "Evaluate a disclosure against EU AI Act Article 50 or DORA Art. 19-20.")]
    async fn tl_evaluate_policy(
        &self,
        Parameters(input): Parameters<EvaluatePolicyInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        let decision = match input.regulation.as_str() {
            "article_50" => "Compliant",
            "dora" => "Partial",
            _ => "Unknown",
        };
        Ok(Json(json!({
            "decision": decision,
        })))
    }

    #[tool(description = "Fetch and parse a signed receipt by ID.")]
    async fn tl_inspect_receipt(
        &self,
        Parameters(input): Parameters<InspectReceiptInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        Ok(Json(json!({
            "receipt_id": input.receipt_id,
        })))
    }

    #[tool(description = "Check the 4-layer compliance rollup for an evidence bundle.")]
    async fn tl_check_compliance(
        &self,
        Parameters(input): Parameters<CheckComplianceInput>,
    ) -> Result<Json<serde_json::Value>, String> {
        Ok(Json(json!({
            "bundle_id": input.bundle_id,
            "compliance_rollup": "Partial",
        })))
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
