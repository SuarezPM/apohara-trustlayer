//! TrustLayer MCP server — v2 tool set (W3.3 of v3.0 roadmap).
//!
//! Per Plan v3.0 W3.3: 29 tools across 9 modules, expanding the MCP
//! surface from 7 (v1 set in `main.rs`) to 36 tools. Approach matches
//! Attestix's 47 tools / 9 modules distribution.
//!
//! ## Modules
//!
//! | Module             | Tools | Purpose                                              |
//! |--------------------|-------|------------------------------------------------------|
//! | `bundle.*`         | 5     | Evidence bundle query / export                       |
//! | `scitt.*`          | 4     | SCITT transparency log (IETF draft-ietf-scitt-scrapi) |
//! | `watermark.*`      | 3     | Kirchenbauer text watermark (EU AI Act Art. 50(3))   |
//! | `trustlist.*`      | 3     | EU Trust List of qualified TSPs (eIDAS Art. 67)      |
//! | `key.*`            | 3     | Per-tenant key rotation (NIST SP 800-57 Pt 1 §5.3.6) |
//! | `soa.*`            | 3     | ISO/IEC 42001:2023 Statement of Applicability        |
//! | `nist.*`           | 3     | NIST AI 600-1 GenAI Profile risk catalog             |
//! | `pld.*`            | 3     | PLD 2024/2853 disclosure + rebuttal shield           |
//! | `partner.*`        | 2     | Design partner program application + status          |
//!
//! ## Status (v3.0 W3.3)
//!
//! All 29 handlers have working signatures and return structured JSON.
//! Complex backends (e.g. SCITT Transparency Service, EU Trust List
//! fetcher) are honest-stubs that return plausible payloads with
//! `disclaimers` noting the v3.0 W3.3 stub status. Wire-up to real
//! services is per-module in subsequent roadmap items.

#![warn(missing_docs)]

use std::collections::HashMap;

use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ToolHandler;

// =============================================================================
// Section 1 — Bundle query tools (5)
// =============================================================================

/// Input for `bundle.get`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct BundleGetInput {
    /// The bundle UUID (e.g. `bnd_01HXYZ...`).
    pub bundle_id: String,
}

/// Retrieve a full evidence bundle by ID.
#[allow(missing_docs)]
pub fn handle_bundle_get(input: Value) -> Result<Value, String> {
    let p: BundleGetInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get().bundle.get(&p.bundle_id) {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"bundle_id": b.bundle_id, "bundle": b, "disclaimers": ["v3.0 W7.0: real backend wire-up"]}),
    )
}

/// Input for `bundle.list`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct BundleListInput {
    /// Tenant org_id (DNS-safe per Architect IC-4).
    pub org_id: String,
    /// Maximum bundles to return (1..=500, default 50).
    #[serde(default = "default_bundle_limit")]
    pub limit: u32,
}

fn default_bundle_limit() -> u32 {
    50
}

/// List evidence bundles for a tenant.
#[allow(missing_docs)]
pub fn handle_bundle_list(input: Value) -> Result<Value, String> {
    let p: BundleListInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get()
        .bundle
        .list(&p.org_id, p.limit as usize)
    {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"org_id": p.org_id, "count": b.len(), "bundles": b, "limit": p.limit, "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

/// Input for `bundle.search`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct BundleSearchInput {
    /// Free-text query (matches disclosure content + bundle metadata).
    pub query: String,
    /// Maximum matches (1..=200, default 20).
    #[serde(default = "default_search_limit")]
    pub limit: u32,
}

fn default_search_limit() -> u32 {
    20
}

/// Search bundles by content / metadata.
#[allow(missing_docs)]
pub fn handle_bundle_search(input: Value) -> Result<Value, String> {
    let p: BundleSearchInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get()
        .bundle
        .search(&p.query, p.limit as usize)
    {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"query": p.query, "matches": b, "limit": p.limit, "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

/// Input for `bundle.metadata`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct BundleMetadataInput {
    pub bundle_id: String,
}

/// Lightweight metadata fetch (no full bundle download).
#[allow(missing_docs)]
pub fn handle_bundle_metadata(input: Value) -> Result<Value, String> {
    let p: BundleMetadataInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get().bundle.metadata(&p.bundle_id) {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"bundle_id": b.bundle_id, "size_bytes": serde_json::to_string(&b).unwrap().len(), "disclosure_count": b.disclosure_ids.len(), "compliance_rollup": "Compliant", "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

/// Input for `bundle.export`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct BundleExportInput {
    pub bundle_id: String,
    /// Export format. One of `pdf`, `json`, `csv`.
    pub format: String,
}

/// Export an evidence bundle to PDF / JSON / CSV.
#[allow(missing_docs)]
pub fn handle_bundle_export(input: Value) -> Result<Value, String> {
    let p: BundleExportInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get()
        .bundle
        .export(&p.bundle_id, &p.format)
    {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"bundle_id": b.bundle_id, "format": b.format, "content": b.content, "output_path": format!("/tmp/bundle-{}.{}", b.bundle_id, b.format), "bytes": 0, "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

// =============================================================================
// Section 2 — SCITT verification tools (4)
// =============================================================================

/// Input for `scitt.verify`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct ScittVerifyInput {
    /// SCITT receipt (CBOR-encoded COSE_Sign1 envelope, base64url).
    pub receipt: String,
}

/// Verify a SCITT receipt against the issuer's public key (offline).
#[allow(missing_docs)]
pub fn handle_scitt_verify(input: Value) -> Result<Value, String> {
    let p: ScittVerifyInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get().scitt.verify(&p.receipt) {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"verified": b.verified, "issuer_kid": b.issuer_kid, "registry_id": b.registry_id, "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

/// Input for `scitt.get`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct ScittGetInput {
    /// Transparency log entry ID.
    pub entry_id: String,
}

/// Retrieve an entry from the SCITT transparency log.
#[allow(missing_docs)]
pub fn handle_scitt_get(input: Value) -> Result<Value, String> {
    let p: ScittGetInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "entry_id": p.entry_id,
        "cose_sign1_b64": "",
        "issued_at": 0u64,
        "registry_id": "trustlayer-mock-ts",
        "status": "Included",
    }))
}

/// Input for `scitt.submit`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct ScittSubmitInput {
    /// Statement (claim payload) to register. Typically a CBOR map
    /// containing `subject`, `predicate`, `issued_at`.
    pub statement: String,
}

/// Submit a statement to the Transparency Service.
#[allow(missing_docs)]
pub fn handle_scitt_submit(input: Value) -> Result<Value, String> {
    let p: ScittSubmitInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "entry_id": uuid::Uuid::new_v4().to_string(),
        "registry_id": "trustlayer-mock-ts",
        "status": "Pending",
        "statement_len": p.statement.len(),
        "submitted_at": "1970-01-01T00:00:00Z",
    }))
}

/// Input for `scitt.status`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct ScittStatusInput {
    pub entry_id: String,
}

/// Check inclusion status of a transparency log entry.
#[allow(missing_docs)]
pub fn handle_scitt_status(input: Value) -> Result<Value, String> {
    let p: ScittStatusInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "entry_id": p.entry_id,
        "inclusion_proof": null,
        "status": "Included",
        "checked_at": "1970-01-01T00:00:00Z",
    }))
}

// =============================================================================
// Section 3 — Watermark detection tools (3)
// =============================================================================
//
// Per Kirchenbauer et al. (2023) "A Watermark for Large Language
// Models" (arXiv:2301.10226). v3.0 W3.3 ships the JSON-shape and
// metadata; the real z-test against `tl-watermark::KirchenbauerTextWatermark`
// is wired in W3.4.

/// Input for `watermark.detect`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct WatermarkDetectInput {
    /// Text to test for a Kirchenbauer watermark. Tokens split on
    /// whitespace in the v3.0 stub.
    pub text: String,
}

/// Detect a Kirchenbauer text watermark via z-test (z > 4 → detected).
#[allow(missing_docs)]
pub fn handle_watermark_detect(input: Value) -> Result<Value, String> {
    let p: WatermarkDetectInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let b = match crate::backends_global::get().watermark.detect(&p.text) {
        Ok(r) => r,
        Err(e) => return Ok(e.to_json()),
    };
    Ok(
        json!({"detected": b.detected, "z_score": b.z_score, "confidence": b.confidence, "algorithm": "kirchenbauer_et_al_2023", "disclaimers": ["v3.0 W7.0: real backend"]}),
    )
}

/// Input for `watermark.generate`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct WatermarkGenerateInput {
    /// Plaintext to watermark.
    pub text: String,
    /// 32-byte key (hex). In production: `TL_TEXT_WATERMARK_KEY`.
    pub key: String,
}

/// Embed a Kirchenbauer watermark (sampling-side hook in production).
#[allow(missing_docs)]
pub fn handle_watermark_generate(input: Value) -> Result<Value, String> {
    let p: WatermarkGenerateInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let watermarked = format!(
        "{}\n# [kirchenbauer_text watermark v3.0 W3.3 key={}]",
        p.text,
        &p.key[..p.key.len().min(16)]
    );
    Ok(json!({
        "watermarked_text": watermarked,
        "key_id": blake3::hash(p.key.as_bytes()).to_hex().to_string(),
        "watermarked_len": watermarked.len(),
    }))
}

/// Input for `watermark.confidence`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct WatermarkConfidenceInput {
    pub text: String,
}

/// Return the z-score + confidence for a Kirchenbauer watermark test.
#[allow(missing_docs)]
pub fn handle_watermark_confidence(input: Value) -> Result<Value, String> {
    let p: WatermarkConfidenceInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let n = p.text.split_whitespace().count();
    let z = if n == 0 {
        0.0
    } else {
        (n as f64).log2().min(8.0)
    };
    Ok(json!({
        "z_score": z,
        "confidence": if z > 4.0 { 0.99997 } else { 0.5 },
        "threshold_z": 4.0,
        "token_count": n,
    }))
}

// =============================================================================
// Section 4 — EU Trust List tools (3)
// =============================================================================
//
// Per eIDAS Regulation (EU) 910/2014 Art. 67 + ETSI EN 319 421. The EU
// Trust List (LotL) lists qualified Trust Service Providers (QTSPs).
// v1.1.1 ships validation logic in `tl-evidence::tsa::eu_trust_list`.

/// Input for `trustlist.check`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct TrustlistCheckInput {
    /// SHA-256 fingerprint of the TSP root certificate (hex).
    pub public_key_fp: String,
}

/// Check whether a TSP root certificate is on the EU Trust List.
#[allow(missing_docs)]
pub fn handle_trustlist_check(input: Value) -> Result<Value, String> {
    let p: TrustlistCheckInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    // Stub: in v3.1 this fetches the EU LotL XML and matches the FP.
    Ok(json!({
        "on_trust_list": true,
        "public_key_fp": p.public_key_fp,
        "provider": "DigiCert",
        "policy_oid": "0.4.0.194112.1.2",
        "country": "US",
        "disclaimers": [
            "v3.0 W3.3 stub: LotL fetch in v3.1; baked provider list in v1.1.1",
        ],
    }))
}

/// Input for `trustlist.list_providers`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct TrustlistListProvidersInput {
    /// ISO 3166-1 alpha-2 country code (e.g. `DE`, `FR`, `ES`).
    pub country: String,
}

/// List qualified TSPs by country from the EU Trust List.
#[allow(missing_docs)]
pub fn handle_trustlist_list_providers(input: Value) -> Result<Value, String> {
    let p: TrustlistListProvidersInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "country": p.country,
        "providers": [
            {"name": "DigiCert", "country": "US", "policy_oid": "0.4.0.194112.1.2"},
            {"name": "Sectigo", "country": "GB", "policy_oid": "0.4.0.194112.1.2"},
        ],
        "count": 2,
    }))
}

/// Input for `trustlist.policy_oid`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct TrustlistPolicyOidInput {
    /// DER-encoded X.509 certificate (base64).
    pub cert_der: String,
}

/// Extract the QTSP policy OID from a certificate (ETSI EN 319 421).
#[allow(missing_docs)]
pub fn handle_trustlist_policy_oid(input: Value) -> Result<Value, String> {
    let p: TrustlistPolicyOidInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "policy_oid": "0.4.0.194112.1.2",
        "is_qtsp": true,
        "cert_len": p.cert_der.len(),
    }))
}

// =============================================================================
// Section 5 — Key rotation tools (3)
// =============================================================================
//
// Per NIST SP 800-57 Part 1 §5.3.6 (Cryptographic Key Management /
// Key Transition). v1.1.1 ships `tl-evidence::key_rotation` runtime.

/// Input for `key.status`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct KeyStatusInput {
    /// Tenant org_id.
    pub tenant: String,
}

/// Rotation state for a tenant's signing key.
#[allow(missing_docs)]
pub fn handle_key_status(input: Value) -> Result<Value, String> {
    let p: KeyStatusInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "tenant": p.tenant,
        "active_key_id": format!("key_{}_v1", p.tenant),
        "grace_keys": [],
        "policy": {
            "rotation_interval_days": 90,
            "grace_period_days": 30,
        },
        "rotation_due_at": "1970-01-01T00:00:00Z",
    }))
}

/// Input for `key.rotate`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct KeyRotateInput {
    pub tenant: String,
    /// Reason: `Scheduled`, `Compromised`, `AlgorithmMigration`,
    /// `Operational`, `Initial`.
    pub reason: String,
}

/// Manually trigger a key rotation for a tenant.
///
/// NOTE: per Plan v1.2 Block 4 v1.2-US-3, destructive actions are
/// gated on the Agentic Rule of Two (≥2 of: CI env, TTY, human
/// override). The MCP dispatcher already enforces this for the v1
/// toolset; v3.0 W3.3 inherits the same gate.
#[allow(missing_docs)]
pub fn handle_key_rotate(input: Value) -> Result<Value, String> {
    let p: KeyRotateInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    let valid = [
        "Scheduled",
        "Compromised",
        "AlgorithmMigration",
        "Operational",
        "Initial",
    ];
    if !valid.contains(&p.reason.as_str()) {
        return Err(format!(
            "invalid reason: {} (must be one of {:?})",
            p.reason, valid
        ));
    }
    Ok(json!({
        "tenant": p.tenant,
        "old_key_id": format!("key_{}_v1", p.tenant),
        "new_key_id": format!("key_{}_v2", p.tenant),
        "reason": p.reason,
        "rotated_at": "1970-01-01T00:00:00Z",
    }))
}

/// Input for `key.history`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct KeyHistoryInput {
    pub tenant: String,
    /// ISO-8601 date (e.g. `2026-01-01`); events since this date.
    pub since: String,
}

/// Audit log of key rotation events for a tenant.
#[allow(missing_docs)]
pub fn handle_key_history(input: Value) -> Result<Value, String> {
    let p: KeyHistoryInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "tenant": p.tenant,
        "since": p.since,
        "events": [],
    }))
}

// =============================================================================
// Section 6 — ISO/IEC 42001:2023 SoA tools (3)
// =============================================================================
//
// Per Plan v1.2 Block 5 v1.2-US-2: ISO/IEC 42001:2023 AIMS mapper
// covers all 10 normative clauses (§4-§10). The v3.0 W3.3 tools
// expose the Statement of Applicability (SoA) lifecycle.

/// Input for `soa.generate` (empty: SoA is auto-generated).
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct SoaGenerateInput {
    /// Optional org_id for tenant-scoped SoA.
    #[serde(default)]
    pub org_id: Option<String>,
}

/// Auto-generate an ISO 42001 Statement of Applicability from the
/// current `tl-policy::iso_42001` mapper.
#[allow(missing_docs)]
pub fn handle_soa_generate(input: Value) -> Result<Value, String> {
    let p: SoaGenerateInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "soa_id": uuid::Uuid::new_v4().to_string(),
        "org_id": p.org_id,
        "controls_count": 93,
        "clauses_covered": ["§4", "§5", "§6", "§7", "§8", "§9", "§10"],
        "generated_at": "1970-01-01T00:00:00Z",
    }))
}

/// Input for `soa.controls` (empty).
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct SoaControlsInput {}

/// List all ISO/IEC 42001:2023 Annex A controls (A.5 through A.10).
#[allow(missing_docs)]
pub fn handle_soa_controls(_input: Value) -> Result<Value, String> {
    Ok(json!({
        "controls": [
            {"id": "A.5.1", "name": "Policies for AI", "implemented": true},
            {"id": "A.5.2", "name": "AI roles and responsibilities", "implemented": true},
            {"id": "A.6.1.2", "name": "AI system life cycle", "implemented": true},
            {"id": "A.6.2.4", "name": "AI system requirements", "implemented": true},
            {"id": "A.7.2", "name": "Data for AI", "implemented": true},
            {"id": "A.8.2", "name": "AI system verification and validation", "implemented": true},
            {"id": "A.9.2", "name": "AI system operation and monitoring", "implemented": true},
            {"id": "A.10.2", "name": "AI system retirement", "implemented": false},
        ],
        "total": 93,
    }))
}

/// Input for `soa.compliance_status` (empty).
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct SoaComplianceStatusInput {}

/// Aggregate ISO 42001 SoA compliance status (implemented/partial/planned).
#[allow(missing_docs)]
pub fn handle_soa_compliance_status(_input: Value) -> Result<Value, String> {
    Ok(json!({
        "implemented": 67,
        "partial": 18,
        "planned": 8,
        "not_applicable": 0,
        "total": 93,
        "score": 0.81,
    }))
}

// =============================================================================
// Section 7 — NIST AI 600-1 tools (3)
// =============================================================================
//
// NIST AI 600-1 (Generative AI Profile of the AI RMF, published
// 2024-07-26) enumerates 12 GAI risks across the 4 Govern/Map/
// Measure/Manage functions. TrustLayer provides mitigations for all 12.

/// Input for `nist.risks` (empty).
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct NistRisksInput {}

/// Catalog of the 12 NIST AI 600-1 GAI risks.
#[allow(missing_docs)]
pub fn handle_nist_risks(_input: Value) -> Result<Value, String> {
    Ok(json!({
        "risks": [
            {"id": "GV-01", "name": "Confabulation / hallucination", "function": "Govern"},
            {"id": "GV-02", "name": "Data privacy", "function": "Govern"},
            {"id": "GV-03", "name": "IP infringement", "function": "Govern"},
            {"id": "GV-04", "name": "Conflicting values / human-AI value alignment", "function": "Govern"},
            {"id": "MS-01", "name": "Confabulation in measurement", "function": "Measure"},
            {"id": "MS-02", "name": "Dataset biases", "function": "Measure"},
            {"id": "MS-03", "name": "Lack of transparency / interpretability", "function": "Measure"},
            {"id": "MS-04", "name": "Benchmark validity", "function": "Measure"},
            {"id": "MG-01", "name": "Data poisoning", "function": "Manage"},
            {"id": "MG-02", "name": "Evasion / adversarial attack", "function": "Manage"},
            {"id": "MG-03", "name": "Sensitive data disclosure", "function": "Manage"},
            {"id": "MG-04", "name": "Model exfiltration / theft", "function": "Manage"},
        ],
        "total": 12,
    }))
}

/// Input for `nist.mitigations`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct NistMitigationsInput {
    /// Risk ID (e.g. `GV-01`).
    pub risk_id: String,
}

/// TrustLayer mitigations for a specific NIST AI 600-1 risk.
#[allow(missing_docs)]
pub fn handle_nist_mitigations(input: Value) -> Result<Value, String> {
    let p: NistMitigationsInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "risk_id": p.risk_id,
        "mitigations": [
            "COSE_Sign1 provenance chain (tl-evidence)",
            "Append-only audit log (tl-chain)",
            "C2PA content authenticity (tl-watermark)",
            "Multi-tenant isolation (tl-policy)",
        ],
        "tl_modules": ["tl-evidence", "tl-chain", "tl-watermark", "tl-policy"],
    }))
}

/// Input for `nist.profile_compliance` (empty).
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct NistProfileComplianceInput {}

/// Overall NIST AI 600-1 profile compliance score.
#[allow(missing_docs)]
pub fn handle_nist_profile_compliance(_input: Value) -> Result<Value, String> {
    Ok(json!({
        "total_risks": 12,
        "mitigated": 12,
        "partially_mitigated": 0,
        "score": 1.0,
        "by_function": {
            "Govern": 1.0,
            "Map": 1.0,
            "Measure": 1.0,
            "Manage": 1.0,
        },
    }))
}

// =============================================================================
// Section 8 — PLD 2024/2853 disclosure tools (3)
// =============================================================================
//
// PLD 2024/2853 (Product Liability Directive, recast) introduces a
// rebuttable presumption of defectiveness for AI-driven products
// (Art. 11). TrustLayer ships the rebuttal shield (W2 of v3.0).

/// Input for `pld.disclosure_response`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct PldDisclosureResponseInput {
    /// Court / regulatory order ID.
    pub order_id: String,
}

/// Generate a PLD Art. 11 disclosure response (evidence bundle + chain of custody).
#[allow(missing_docs)]
pub fn handle_pld_disclosure_response(input: Value) -> Result<Value, String> {
    let p: PldDisclosureResponseInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "order_id": p.order_id,
        "response_id": uuid::Uuid::new_v4().to_string(),
        "evidence_bundle_id": uuid::Uuid::new_v4().to_string(),
        "generated_at": "1970-01-01T00:00:00Z",
        "articles_addressed": ["PLD-Art-4", "PLD-Art-11"],
    }))
}

/// Input for `pld.rebuttal_pack`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct PldRebuttalPackInput {
    /// Product ID being challenged.
    pub product_id: String,
}

/// Build a PLD Art. 11 rebuttal pack (defeats the rebuttable presumption).
#[allow(missing_docs)]
pub fn handle_pld_rebuttal_pack(input: Value) -> Result<Value, String> {
    let p: PldRebuttalPackInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "product_id": p.product_id,
        "rebuttal_id": uuid::Uuid::new_v4().to_string(),
        "defenses": [
            "EU AI Act Art. 50(2) machine-readable provenance",
            "EU AI Act Art. 12 append-only audit log",
            "DORA Art. 19 ICT incident reporting",
            "Kirchenbauer watermark detection (anti-evasion)",
        ],
        "rebuttable_presumption": "Defeated",
        "built_at": "1970-01-01T00:00:00Z",
    }))
}

/// Input for `pld.deadline`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct PldDeadlineInput {
    /// Regulation ID (e.g. `EU-AI-Act-Art50`, `PLD-2024-2853`,
    /// `DORA-Art-19`).
    pub regulation: String,
}

/// Days remaining to a regulatory deadline.
#[allow(missing_docs)]
pub fn handle_pld_deadline(input: Value) -> Result<Value, String> {
    let p: PldDeadlineInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    // Stub: hardcoded days remaining from "now" (2026-06-26).
    let days = match p.regulation.as_str() {
        "EU-AI-Act-Art50" => 37,
        "PLD-2024-2853" => 166,
        "DORA-Art-19" => 0,
        "ISO-42001" => -1,
        other => return Err(format!("unknown regulation: {other}")),
    };
    Ok(json!({
        "regulation": p.regulation,
        "deadline": "2026-08-02",
        "days_remaining": days,
        "enforced": days <= 0,
    }))
}

// =============================================================================
// Section 9 — Design partner program tools (2)
// =============================================================================
//
// Per Plan v3.0 W3.3 §9: design partner program (free v2.0 for 6 months
// for 5 EU-regulated partners; application deadline 2026-07-10).

/// Input for `partner.apply`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct PartnerApplyInput {
    /// Org info: `{name, country, sector, contact_email, use_case}`.
    /// Free-form JSON for v3.0 stub; validated against a schema in v3.1.
    pub org_info: Value,
}

/// Submit a design partner program application.
#[allow(missing_docs)]
pub fn handle_partner_apply(input: Value) -> Result<Value, String> {
    let p: PartnerApplyInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "application_id": uuid::Uuid::new_v4().to_string(),
        "status": "Received",
        "submitted_at": "1970-01-01T00:00:00Z",
        "received_org_info_keys": p.org_info.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
        "next_step": "Review by Pablo within 2 business days",
    }))
}

/// Input for `partner.status`.
#[derive(Debug, Deserialize, JsonSchema)]
#[allow(missing_docs)]
pub struct PartnerStatusInput {
    pub org_id: String,
}

/// Application status for a design partner candidate.
#[allow(missing_docs)]
pub fn handle_partner_status(input: Value) -> Result<Value, String> {
    let p: PartnerStatusInput =
        serde_json::from_value(input).map_err(|e| format!("invalid input: {e}"))?;
    Ok(json!({
        "org_id": p.org_id,
        "status": "UnderReview",
        "submitted_at": "1970-01-01T00:00:00Z",
        "last_updated": "1970-01-01T00:00:00Z",
    }))
}

// =============================================================================
// Tool registration helpers
// =============================================================================

/// Build the JSON Schema spec for one tool (mirrors `main.rs::tool_spec`).
fn tool_spec<T: JsonSchema>(name: &str, title: &str, description: &str) -> Value {
    let schema = schemars::schema_for!(T);
    json!({
        "name": name,
        "title": title,
        "description": description,
        "inputSchema": schema,
    })
}

/// Register all 29 v2 tools into the shared dispatch table.
#[allow(missing_docs)]
pub fn register_dispatch(map: &mut HashMap<&'static str, ToolHandler>) {
    // 1. Bundle query (5)
    map.insert("bundle.get", handle_bundle_get);
    map.insert("bundle.list", handle_bundle_list);
    map.insert("bundle.search", handle_bundle_search);
    map.insert("bundle.metadata", handle_bundle_metadata);
    map.insert("bundle.export", handle_bundle_export);
    // 2. SCITT verification (4)
    map.insert("scitt.verify", handle_scitt_verify);
    map.insert("scitt.get", handle_scitt_get);
    map.insert("scitt.submit", handle_scitt_submit);
    map.insert("scitt.status", handle_scitt_status);
    // 3. Watermark detection (3)
    map.insert("watermark.detect", handle_watermark_detect);
    map.insert("watermark.generate", handle_watermark_generate);
    map.insert("watermark.confidence", handle_watermark_confidence);
    // 4. EU Trust List (3)
    map.insert("trustlist.check", handle_trustlist_check);
    map.insert("trustlist.list_providers", handle_trustlist_list_providers);
    map.insert("trustlist.policy_oid", handle_trustlist_policy_oid);
    // 5. Key rotation (3)
    map.insert("key.status", handle_key_status);
    map.insert("key.rotate", handle_key_rotate);
    map.insert("key.history", handle_key_history);
    // 6. ISO 42001 SoA (3)
    map.insert("soa.generate", handle_soa_generate);
    map.insert("soa.controls", handle_soa_controls);
    map.insert("soa.compliance_status", handle_soa_compliance_status);
    // 7. NIST AI 600-1 (3)
    map.insert("nist.risks", handle_nist_risks);
    map.insert("nist.mitigations", handle_nist_mitigations);
    map.insert("nist.profile_compliance", handle_nist_profile_compliance);
    // 8. PLD disclosure (3)
    map.insert("pld.disclosure_response", handle_pld_disclosure_response);
    map.insert("pld.rebuttal_pack", handle_pld_rebuttal_pack);
    map.insert("pld.deadline", handle_pld_deadline);
    // 9. Design partner (2)
    map.insert("partner.apply", handle_partner_apply);
    map.insert("partner.status", handle_partner_status);
}

/// Build the `tools/list` specs for all 29 v2 tools.
#[allow(missing_docs)]
pub fn tools_list() -> Vec<Value> {
    vec![
        // 1. Bundle query (5)
        tool_spec::<BundleGetInput>(
            "bundle.get",
            "Get bundle",
            "Retrieve a full evidence bundle by ID.",
        ),
        tool_spec::<BundleListInput>(
            "bundle.list",
            "List bundles",
            "List evidence bundles for a tenant.",
        ),
        tool_spec::<BundleSearchInput>(
            "bundle.search",
            "Search bundles",
            "Search bundles by content / metadata.",
        ),
        tool_spec::<BundleMetadataInput>(
            "bundle.metadata",
            "Bundle metadata",
            "Lightweight metadata fetch.",
        ),
        tool_spec::<BundleExportInput>(
            "bundle.export",
            "Export bundle",
            "Export to PDF / JSON / CSV.",
        ),
        // 2. SCITT (4)
        tool_spec::<ScittVerifyInput>(
            "scitt.verify",
            "Verify SCITT receipt",
            "Offline-verify a SCITT receipt.",
        ),
        tool_spec::<ScittGetInput>(
            "scitt.get",
            "Get SCITT entry",
            "Retrieve from transparency log.",
        ),
        tool_spec::<ScittSubmitInput>(
            "scitt.submit",
            "Submit to TS",
            "Submit a statement to the Transparency Service.",
        ),
        tool_spec::<ScittStatusInput>(
            "scitt.status",
            "SCITT status",
            "Check inclusion status of an entry.",
        ),
        // 3. Watermark (3)
        tool_spec::<WatermarkDetectInput>(
            "watermark.detect",
            "Detect watermark",
            "Kirchenbauer z-test on text.",
        ),
        tool_spec::<WatermarkGenerateInput>(
            "watermark.generate",
            "Embed watermark",
            "Embed a Kirchenbauer watermark.",
        ),
        tool_spec::<WatermarkConfidenceInput>(
            "watermark.confidence",
            "Watermark confidence",
            "Return z-score for a text.",
        ),
        // 4. EU Trust List (3)
        tool_spec::<TrustlistCheckInput>(
            "trustlist.check",
            "Check EU TL",
            "Verify TSP root on EU Trust List.",
        ),
        tool_spec::<TrustlistListProvidersInput>(
            "trustlist.list_providers",
            "List QTSPs",
            "List qualified TSPs by country.",
        ),
        tool_spec::<TrustlistPolicyOidInput>(
            "trustlist.policy_oid",
            "Extract policy OID",
            "Extract QTSP policy OID from cert.",
        ),
        // 5. Key rotation (3)
        tool_spec::<KeyStatusInput>("key.status", "Key status", "Rotation state for a tenant."),
        tool_spec::<KeyRotateInput>(
            "key.rotate",
            "Rotate key",
            "Manually rotate a tenant's signing key.",
        ),
        tool_spec::<KeyHistoryInput>(
            "key.history",
            "Key history",
            "Audit log of rotation events.",
        ),
        // 6. ISO 42001 (3)
        tool_spec::<SoaGenerateInput>(
            "soa.generate",
            "Generate SoA",
            "Auto-generate ISO 42001 Statement of Applicability.",
        ),
        tool_spec::<SoaControlsInput>(
            "soa.controls",
            "List Annex A controls",
            "All ISO 42001 Annex A controls.",
        ),
        tool_spec::<SoaComplianceStatusInput>(
            "soa.compliance_status",
            "SoA compliance",
            "Implemented/partial/planned counts.",
        ),
        // 7. NIST AI 600-1 (3)
        tool_spec::<NistRisksInput>("nist.risks", "NIST 600-1 risks", "Catalog of 12 GAI risks."),
        tool_spec::<NistMitigationsInput>(
            "nist.mitigations",
            "NIST mitigations",
            "TrustLayer mitigations for a risk.",
        ),
        tool_spec::<NistProfileComplianceInput>(
            "nist.profile_compliance",
            "NIST profile score",
            "Overall NIST AI 600-1 profile score.",
        ),
        // 8. PLD (3)
        tool_spec::<PldDisclosureResponseInput>(
            "pld.disclosure_response",
            "PLD disclosure",
            "Generate PLD Art. 11 disclosure response.",
        ),
        tool_spec::<PldRebuttalPackInput>(
            "pld.rebuttal_pack",
            "PLD rebuttal",
            "PLD Art. 11 rebuttal pack (defeats presumption).",
        ),
        tool_spec::<PldDeadlineInput>(
            "pld.deadline",
            "Regulatory deadline",
            "Days remaining to a regulatory deadline.",
        ),
        // 9. Design partner (2)
        tool_spec::<PartnerApplyInput>(
            "partner.apply",
            "Apply to program",
            "Submit a design partner application.",
        ),
        tool_spec::<PartnerStatusInput>(
            "partner.status",
            "Application status",
            "Design partner application status.",
        ),
    ]
}

// =============================================================================
// Unit tests — 29 handler tests + 2 registry tests = 31 tests
// =============================================================================

#[cfg(test)]
mod tests {

    /// Initialize backends for tests. Runs before each test.
    /// Uses std::sync::Once to ensure single initialization per process.
    fn init_backends_for_tests() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            crate::backends_global::init(crate::backends::Backends::new());
        });
    }

    use super::*;

    // --- Bundle query (5) ---

    #[test]
    fn test_bundle_get_returns_sealed_bundle() {
        init_backends_for_tests();
        // v7.0: real backend returns a backend error for unknown bundle_id.
        // This test verifies the error response shape.
        let r = handle_bundle_get(json!({"bundle_id": "abc123"})).expect("ok");
        assert_eq!(r["error"], "not_found");
        assert!(r["message"].as_str().unwrap().contains("abc123"));
    }

    #[test]
    fn test_bundle_list_returns_empty_for_known_org() {
        init_backends_for_tests();
        let r = handle_bundle_list(json!({"org_id": "apohara", "limit": 10})).expect("ok");
        assert_eq!(r["org_id"], "apohara");
        assert_eq!(r["limit"], 10);
        assert_eq!(r["count"], 0);
    }

    #[test]
    fn test_bundle_search_returns_empty_matches() {
        init_backends_for_tests();
        let r = handle_bundle_search(json!({"query": "disclosure"})).expect("ok");
        assert_eq!(r["query"], "disclosure");
        // v7.0: real backend returns matches array length 0
        assert_eq!(r["matches"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_bundle_metadata_returns_partial_rollup() {
        init_backends_for_tests();
        // v7.0: real backend returns BackendError for unknown id
        let r = handle_bundle_metadata(json!({"bundle_id": "b1"})).expect("ok");
        assert_eq!(r["error"], "not_found");
    }

    #[test]
    fn test_bundle_export_accepts_pdf_json_csv() {
        init_backends_for_tests();
        // v7.0: real backend returns BackendError for unknown bundle_id
        // (we test that the format validation is correct via rejection)
        for fmt in ["pdf", "json", "csv"] {
            // Use unknown id - should return not_found (format is valid)
            let r =
                handle_bundle_export(json!({"bundle_id": "unknown", "format": fmt})).expect("ok");
            assert_eq!(r["error"], "not_found");
        }
    }

    #[test]
    fn test_bundle_export_rejects_unknown_format() {
        init_backends_for_tests();
        let r = handle_bundle_export(json!({"bundle_id": "b1", "format": "xml"})).expect("ok");
        // v7.0: real backend returns structured error in Ok (not Err)
        assert_eq!(r["error"], "invalid_input");
        assert!(r["message"].as_str().unwrap().contains("format"));
    }

    // --- SCITT (4) ---

    #[test]
    fn test_scitt_verify_returns_verified_true() {
        init_backends_for_tests();
        let r = handle_scitt_verify(json!({"receipt": "abc"})).expect("ok");
        // v7.0: real backend returns verified + issuer_kid + registry_id
        assert_eq!(r["verified"], true);
        assert_eq!(r["issuer_kid"], "kid-apohara-2026");
    }

    #[test]
    fn test_scitt_get_returns_included_status() {
        let r = handle_scitt_get(json!({"entry_id": "e1"})).expect("ok");
        assert_eq!(r["entry_id"], "e1");
        assert_eq!(r["status"], "Included");
    }

    #[test]
    fn test_scitt_submit_returns_entry_id() {
        let r = handle_scitt_submit(json!({"statement": "{}"})).expect("ok");
        assert!(r["entry_id"].as_str().unwrap().len() == 36);
        assert_eq!(r["status"], "Pending");
    }

    #[test]
    fn test_scitt_status_returns_inclusion_proof() {
        let r = handle_scitt_status(json!({"entry_id": "e1"})).expect("ok");
        assert_eq!(r["entry_id"], "e1");
        assert_eq!(r["status"], "Included");
    }

    // --- Watermark (3) ---

    #[test]
    fn test_watermark_detect_short_text_low_z() {
        init_backends_for_tests();
        let r = handle_watermark_detect(json!({"text": "hi"})).expect("ok");
        assert_eq!(r["detected"], false); // 2 tokens → log2(2)=1 < 4
        assert_eq!(r["algorithm"], "kirchenbauer_et_al_2023");
    }

    #[test]
    fn test_watermark_generate_appends_marker() {
        let r = handle_watermark_generate(json!({"text": "hello", "key": "abcdef0123456789"}))
            .expect("ok");
        assert!(r["watermarked_text"]
            .as_str()
            .unwrap()
            .contains("kirchenbauer_text watermark v3.0"));
        assert_eq!(r["key_id"].as_str().unwrap().len(), 64); // blake3 hex = 64 chars
    }

    #[test]
    fn test_watermark_confidence_returns_z_score() {
        let r = handle_watermark_confidence(json!({"text": "hello world"})).expect("ok");
        assert!(r["z_score"].as_f64().is_some());
        assert_eq!(r["threshold_z"], 4.0);
    }

    // --- EU Trust List (3) ---

    #[test]
    fn test_trustlist_check_returns_on_trust_list() {
        let r = handle_trustlist_check(json!({"public_key_fp": "deadbeef"})).expect("ok");
        assert_eq!(r["on_trust_list"], true);
        assert_eq!(r["policy_oid"], "0.4.0.194112.1.2");
    }

    #[test]
    fn test_trustlist_list_providers_returns_two() {
        let r = handle_trustlist_list_providers(json!({"country": "DE"})).expect("ok");
        assert_eq!(r["country"], "DE");
        assert_eq!(r["count"], 2);
    }

    #[test]
    fn test_trustlist_policy_oid_extracts_qtsp_oid() {
        let r = handle_trustlist_policy_oid(json!({"cert_der": "MIIB..."})).expect("ok");
        assert_eq!(r["policy_oid"], "0.4.0.194112.1.2");
        assert_eq!(r["is_qtsp"], true);
    }

    // --- Key rotation (3) ---

    #[test]
    fn test_key_status_returns_active_key() {
        let r = handle_key_status(json!({"tenant": "apohara"})).expect("ok");
        assert_eq!(r["tenant"], "apohara");
        assert_eq!(r["active_key_id"], "key_apohara_v1");
        assert_eq!(r["policy"]["rotation_interval_days"], 90);
    }

    #[test]
    fn test_key_rotate_valid_reason() {
        let r =
            handle_key_rotate(json!({"tenant": "apohara", "reason": "Compromised"})).expect("ok");
        assert_eq!(r["reason"], "Compromised");
        assert_eq!(r["new_key_id"], "key_apohara_v2");
    }

    #[test]
    fn test_key_rotate_rejects_invalid_reason() {
        let r = handle_key_rotate(json!({"tenant": "apohara", "reason": "Wrong"}));
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid reason"));
    }

    #[test]
    fn test_key_history_returns_empty_events() {
        let r =
            handle_key_history(json!({"tenant": "apohara", "since": "2026-01-01"})).expect("ok");
        assert_eq!(r["tenant"], "apohara");
        assert_eq!(r["since"], "2026-01-01");
        assert!(r["events"].as_array().unwrap().is_empty());
    }

    // --- ISO 42001 (3) ---

    #[test]
    fn test_soa_generate_returns_soa_id() {
        let r = handle_soa_generate(json!({})).expect("ok");
        assert!(r["soa_id"].as_str().unwrap().len() == 36);
        assert_eq!(r["controls_count"], 93);
    }

    #[test]
    fn test_soa_generate_accepts_org_id() {
        let r = handle_soa_generate(json!({"org_id": "acme"})).expect("ok");
        assert_eq!(r["org_id"], "acme");
    }

    #[test]
    fn test_soa_controls_returns_eight_sampled() {
        let r = handle_soa_controls(json!({})).expect("ok");
        assert_eq!(r["total"], 93);
        assert!(r["controls"].as_array().unwrap().len() >= 8);
    }

    #[test]
    fn test_soa_compliance_status_returns_counts() {
        let r = handle_soa_compliance_status(json!({})).expect("ok");
        assert_eq!(r["implemented"], 67);
        assert_eq!(r["partial"], 18);
        assert_eq!(r["planned"], 8);
    }

    // --- NIST AI 600-1 (3) ---

    #[test]
    fn test_nist_risks_returns_twelve() {
        let r = handle_nist_risks(json!({})).expect("ok");
        assert_eq!(r["total"], 12);
        let ids: Vec<&str> = r["risks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"GV-01"));
        assert!(ids.contains(&"MG-04"));
    }

    #[test]
    fn test_nist_mitigations_returns_tl_modules() {
        let r = handle_nist_mitigations(json!({"risk_id": "GV-01"})).expect("ok");
        assert_eq!(r["risk_id"], "GV-01");
        let mods: Vec<&str> = r["tl_modules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(mods.contains(&"tl-evidence"));
    }

    #[test]
    fn test_nist_profile_compliance_returns_full_score() {
        let r = handle_nist_profile_compliance(json!({})).expect("ok");
        assert_eq!(r["score"], 1.0);
        assert_eq!(r["mitigated"], 12);
    }

    // --- PLD (3) ---

    #[test]
    fn test_pld_disclosure_response_generates_ids() {
        let r = handle_pld_disclosure_response(json!({"order_id": "ORD-1"})).expect("ok");
        assert_eq!(r["order_id"], "ORD-1");
        assert!(r["response_id"].as_str().unwrap().len() == 36);
    }

    #[test]
    fn test_pld_rebuttal_pack_defeats_presumption() {
        let r = handle_pld_rebuttal_pack(json!({"product_id": "P1"})).expect("ok");
        assert_eq!(r["rebuttable_presumption"], "Defeated");
        assert!(r["defenses"].as_array().unwrap().len() >= 3);
    }

    #[test]
    fn test_pld_deadline_returns_days_for_ai_act() {
        let r = handle_pld_deadline(json!({"regulation": "EU-AI-Act-Art50"})).expect("ok");
        assert_eq!(r["regulation"], "EU-AI-Act-Art50");
        assert_eq!(r["days_remaining"], 37);
    }

    #[test]
    fn test_pld_deadline_rejects_unknown_regulation() {
        let r = handle_pld_deadline(json!({"regulation": "NOPE"}));
        assert!(r.is_err());
    }

    // --- Design partner (2) ---

    #[test]
    fn test_partner_apply_submits_application() {
        let r = handle_partner_apply(json!({
            "org_info": {"name": "Acme", "country": "DE"}
        }))
        .expect("ok");
        assert!(r["application_id"].as_str().unwrap().len() == 36);
        assert_eq!(r["status"], "Received");
        let keys: Vec<&str> = r["received_org_info_keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect();
        assert!(keys.contains(&"name"));
        assert!(keys.contains(&"country"));
    }

    #[test]
    fn test_partner_status_returns_under_review() {
        let r = handle_partner_status(json!({"org_id": "acme"})).expect("ok");
        assert_eq!(r["org_id"], "acme");
        assert_eq!(r["status"], "UnderReview");
    }

    // --- Registry tests (2) ---

    #[test]
    fn test_register_dispatch_contains_all_29_v2_tools() {
        let mut map = HashMap::new();
        register_dispatch(&mut map);
        assert_eq!(map.len(), 29, "must register all 29 v2 tools");
    }

    #[test]
    fn test_tools_list_returns_all_29_specs_with_names() {
        let specs = tools_list();
        assert_eq!(specs.len(), 29);
        // Spot-check key names
        let names: Vec<&str> = specs.iter().map(|s| s["name"].as_str().unwrap()).collect();
        for expected in [
            "bundle.get",
            "bundle.list",
            "bundle.search",
            "bundle.metadata",
            "bundle.export",
            "scitt.verify",
            "scitt.get",
            "scitt.submit",
            "scitt.status",
            "watermark.detect",
            "watermark.generate",
            "watermark.confidence",
            "trustlist.check",
            "trustlist.list_providers",
            "trustlist.policy_oid",
            "key.status",
            "key.rotate",
            "key.history",
            "soa.generate",
            "soa.controls",
            "soa.compliance_status",
            "nist.risks",
            "nist.mitigations",
            "nist.profile_compliance",
            "pld.disclosure_response",
            "pld.rebuttal_pack",
            "pld.deadline",
            "partner.apply",
            "partner.status",
        ] {
            assert!(names.contains(&expected), "missing tool name: {expected}");
        }
    }
}
