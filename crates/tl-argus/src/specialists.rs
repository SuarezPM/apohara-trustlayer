//! The 4 specialist module interfaces (aegis-slop / aegis-security /
//! aegis-arch / aegis-verdict), ported from `apohara-argus::argus-slop`.
//!
//! Each specialist has:
//! 1. A stable `name()` (`"aegis-slop"` etc.) — the prompt library looks
//!    these up by exact string. A typo breaks every invocation.
//! 2. A `prompt_name()` — the prompt template id.
//! 3. A `build_user_message()` — how to format the diff + context for
//!    the LLM.
//! 4. A `parse_response()` — turn the LLM JSON into a structured report.
//!
//! The trait is intentionally sync: the LLM runtime lives in the
//! consumer (`tl-orchestrator` or future `tl-mcp-server`). This crate
//! only ships the contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Common trait for all specialists. The associated `Output` type
/// carries the structured finding the specialist emits.
pub trait Specialist: Send + Sync {
    /// The structured output type this specialist produces.
    type Output: Serialize + serde::de::DeserializeOwned + Send + Sync;

    /// The agent id, e.g. `"aegis-slop"`. Stable string for prompt lookup.
    fn name(&self) -> &'static str;

    /// The prompt template id, e.g. `"slop-detector"`.
    fn prompt_name(&self) -> &'static str;

    /// Build the user message for the LLM call.
    fn build_user_message(&self, diff: &str, context: Option<&str>) -> String;

    /// Parse the LLM response into the structured output.
    fn parse_response(&self, raw: &str) -> Result<Self::Output, SlopError>;
}

/// Helper to extract JSON from an LLM response. LLMs often wrap JSON
/// in ```json fences or add prose around it.
pub fn extract_json(raw: &str) -> String {
    let s = raw.trim();
    let s = s.strip_prefix("```json").unwrap_or(s);
    let s = s.strip_prefix("```").unwrap_or(s);
    let s = s.strip_suffix("```").unwrap_or(s);
    s.trim().to_string()
}

/// Errors emitted by any specialist.
#[derive(Error, Debug)]
pub enum SlopError {
    /// LLM call failed.
    #[error("LLM error: {0}")]
    Llm(String),
    /// Response could not be parsed into the structured output.
    #[error("Parse error: {0}")]
    Parse(String),
    /// Prompt lookup failed.
    #[error("Prompt error: {0}")]
    Prompt(String),
}

// ============================================================================
// aegis-slop — AI-generated code signal detector
// ============================================================================

/// The structured output of the slop specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlopReport {
    /// Probability the diff is AI-generated, in [0.0, 1.0].
    pub slop_score: f32,
    /// Human-readable tags for each signal detected.
    pub signals_detected: Vec<String>,
    /// Specific examples backing the score.
    pub specific_examples: Vec<SlopExample>,
    /// Model confidence in the score, in [0.0, 1.0].
    pub confidence: f32,
    /// Free-form reasoning.
    pub reasoning: String,
}

/// A concrete slop signal with file:line attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlopExample {
    pub file: String,
    pub line: Option<u32>,
    pub quote: String,
    pub reason: String,
}

/// The slop specialist.
#[derive(Default)]
pub struct SlopDetector;

impl SlopDetector {
    /// Construct a new slop specialist.
    pub fn new() -> Self {
        Self
    }
}

impl Specialist for SlopDetector {
    type Output = SlopReport;

    fn name(&self) -> &'static str {
        "aegis-slop"
    }
    fn prompt_name(&self) -> &'static str {
        "slop-detector"
    }

    fn build_user_message(&self, diff: &str, _context: Option<&str>) -> String {
        format!(
            "Analyze the following PR diff for AI-generated code signals. \
             Return ONLY valid JSON.\n\n```diff\n{}\n```",
            diff
        )
    }

    fn parse_response(&self, raw: &str) -> Result<SlopReport, SlopError> {
        let json_str = extract_json(raw);
        serde_json::from_str(&json_str).map_err(|e| SlopError::Parse(e.to_string()))
    }
}

// ============================================================================
// aegis-security — adversarial red-team review
// ============================================================================

/// Severity of a security finding. Ordered so `Critical > High > Medium >
/// Low > Info > None`. The verdict synthesizer escalates on `High` /
/// `Critical`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    None,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A single security finding with file:line attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub severity: SecuritySeverity,
    pub file: String,
    pub line: Option<u32>,
    pub category: String,
    pub quote: String,
    pub description: String,
    pub recommendation: String,
}

/// The structured output of the security specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub highest_severity: SecuritySeverity,
    pub findings: Vec<SecurityFinding>,
    pub summary: String,
}

/// The security specialist.
#[derive(Default)]
pub struct SecurityReview;

impl SecurityReview {
    /// Construct a new security specialist.
    pub fn new() -> Self {
        Self
    }
}

impl Specialist for SecurityReview {
    type Output = SecurityReport;

    fn name(&self) -> &'static str {
        "aegis-security"
    }
    fn prompt_name(&self) -> &'static str {
        "redteam-security"
    }

    fn build_user_message(&self, diff: &str, _context: Option<&str>) -> String {
        format!(
            "Adversarially review the following PR diff for security issues. \
             Return ONLY valid JSON.\n\n```diff\n{}\n```",
            diff
        )
    }

    fn parse_response(&self, raw: &str) -> Result<SecurityReport, SlopError> {
        let json_str = extract_json(raw);
        serde_json::from_str(&json_str).map_err(|e| SlopError::Parse(e.to_string()))
    }
}

// ============================================================================
// aegis-arch — architecture-fit reviewer
// ============================================================================

/// A single concern raised by the architecture specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchConcern {
    pub file: String,
    pub line: Option<u32>,
    pub issue: String,
    pub severity: String,
    pub fix: String,
}

/// The structured output of the architecture specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchReport {
    pub fit_score: f32,
    pub verdict: String,
    pub positives: Vec<String>,
    pub concerns: Vec<ArchConcern>,
    pub summary: String,
}

/// The architecture-fit specialist.
#[derive(Default)]
pub struct ArchitectureFit;

impl ArchitectureFit {
    /// Construct a new architecture specialist.
    pub fn new() -> Self {
        Self
    }
}

impl Specialist for ArchitectureFit {
    type Output = ArchReport;

    fn name(&self) -> &'static str {
        "aegis-arch"
    }
    fn prompt_name(&self) -> &'static str {
        "architecture-fit"
    }

    fn build_user_message(&self, diff: &str, context: Option<&str>) -> String {
        let context = context.unwrap_or("");
        format!(
            "Evaluate whether this PR fits the existing repo architecture.\n\n\
             PR diff:\n```diff\n{}\n```\n\n\
             Repo context (sample of existing files):\n{}\n\n\
             Return ONLY valid JSON.",
            diff, context
        )
    }

    fn parse_response(&self, raw: &str) -> Result<ArchReport, SlopError> {
        let json_str = extract_json(raw);
        serde_json::from_str(&json_str).map_err(|e| SlopError::Parse(e.to_string()))
    }
}

// ============================================================================
// aegis-verdict — final verdict synthesizer (CORDON-ENFORCED)
// ============================================================================

/// Risk score clamped to [0.0, 1.0]. Higher = more risk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RiskScore(f32);

impl RiskScore {
    /// Construct with clamping to [0.0, 1.0].
    pub fn new(v: f32) -> Self {
        Self(v.clamp(0.0, 1.0))
    }
    /// Borrow as `f32`.
    pub fn as_f32(self) -> f32 {
        self.0
    }
    /// True iff score >= 0.7 (the "high risk" threshold).
    pub fn is_high(self) -> bool {
        self.0 >= 0.7
    }
    /// True iff score >= 0.85 (the "critical" threshold).
    pub fn is_critical(self) -> bool {
        self.0 >= 0.85
    }
}

/// The final verdict emitted by `aegis-verdict`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub risk_score: RiskScore,
    pub summary: String,
    pub key_findings: Vec<String>,
    pub action_items: Vec<String>,
    pub reasoning: String,
    pub issued_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerdictStatus {
    Approved,
    ReviewRequired,
    Halted,
}

/// The input the CordonEnforcer guarantees is safe for the synthesizer.
/// `pr_diff` is included only as a redacted sentinel (e.g. `"<redacted>"`).
/// The real diff MUST never appear here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizerInput {
    pub pr_ref: String,
    pub pr_diff: String,
    pub slop_report: serde_json::Value,
    pub security_report: serde_json::Value,
    pub architecture_report: serde_json::Value,
}

/// The verdict synthesizer. **This agent is Cordon-enforced** — the
/// [`crate::cordon::CordonEnforcer`] guarantees it only ever sees
/// `SynthesizerInput`, never raw diff text.
#[derive(Default)]
pub struct VerdictSynthesizer;

impl VerdictSynthesizer {
    /// Construct a new verdict synthesizer.
    pub fn new() -> Self {
        Self
    }

    /// Build a `Verdict` from a parsed synthesizer response.
    #[allow(clippy::too_many_arguments)]
    pub fn to_verdict(
        &self,
        status: VerdictStatus,
        risk: f32,
        summary: String,
        key_findings: Vec<String>,
        action_items: Vec<String>,
        reasoning: String,
    ) -> Verdict {
        Verdict {
            status,
            risk_score: RiskScore::new(risk),
            summary,
            key_findings,
            action_items,
            reasoning,
            issued_at: chrono::Utc::now(),
        }
    }
}

impl Specialist for VerdictSynthesizer {
    type Output = Verdict;

    fn name(&self) -> &'static str {
        "aegis-verdict"
    }
    fn prompt_name(&self) -> &'static str {
        "verdict-synthesizer"
    }

    fn build_user_message(&self, _diff: &str, _context: Option<&str>) -> String {
        // The verdict synthesizer uses a custom user message built by
        // the orchestrator (it needs the 3 prior outputs serialized,
        // not the raw diff). Returns empty string by design.
        String::new()
    }

    fn parse_response(&self, raw: &str) -> Result<Verdict, SlopError> {
        #[derive(Deserialize)]
        struct Resp {
            verdict: String,
            risk_score: f32,
            summary: String,
            key_findings: Vec<String>,
            action_items: Vec<String>,
            reasoning: String,
        }
        let json_str = extract_json(raw);
        let resp: Resp =
            serde_json::from_str(&json_str).map_err(|e| SlopError::Parse(e.to_string()))?;
        let status = match resp.verdict.as_str() {
            "APPROVED" => VerdictStatus::Approved,
            "HALTED" => VerdictStatus::Halted,
            _ => VerdictStatus::ReviewRequired, // defensive default
        };
        Ok(self.to_verdict(
            status,
            resp.risk_score,
            resp.summary,
            resp.key_findings,
            resp.action_items,
            resp.reasoning,
        ))
    }
}
