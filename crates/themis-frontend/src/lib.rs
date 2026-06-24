//! themis-frontend — demo UI for themis.apohara.dev.
//!
//! The actual UI lives in `static/` (HTML + CSS + JS) and is
//! embedded into the `themis-orchestrator` binary via
//! `include_dir!`. This crate exists so the workspace has a
//! first-class home for the assets and so a future `cargo build
//! -p themis-frontend --release` can ship a static-only deploy
//! (Vercel) without needing the orchestrator binary.

#![warn(missing_docs)]

/// EU AI Act Article 50 banner + Article 49 mock EU registration
/// id. The banner is rendered as the first SSE event on every
/// connection so the regulator / judge sees the AI disclosure
/// before any agent output.
pub mod art50_banner;

/// Crate version + name.
pub fn version() -> &'static str {
    "themis-frontend"
}

/// Re-export the static asset paths. The orchestrator's
/// `main.rs` does `include_dir!("../themis-frontend/static")` and
/// serves each file at `/static/<name>`.
pub const STATIC_DIR: &str = "static";

/// The index.html shipped at the demo URL root.
pub const INDEX_HTML: &str = include_str!("../static/index.html");

/// The compliance dashboard at `/compliance`.
pub const COMPLIANCE_HTML: &str = include_str!("../static/compliance.html");

/// The token CSS (referenced by both pages).
pub const TOKENS_CSS: &str = include_str!("../static/tokens.css");

/// The application CSS (referenced by both pages).
pub const APP_CSS: &str = include_str!("../static/app.css");

/// The application JS (EventSource-driven live counter, BAAAR
/// overlay, evidence download).
pub const APP_JS: &str = include_str!("../static/app.js");

/// A2A 1.0 agent card (Google Agent2Agent protocol, served at
/// `/.well-known/agent-card.json` so external peers can discover
/// the orchestrator). Story C-01 / G26.
pub const AGENT_CARD_JSON: &str = include_str!("../static/.well-known/agent-card.json");

/// Machine-readable list of all 6 agents in the orchestrator's
/// fleet, served at `/agents.json`. Story C-01 / G25.
pub const AGENTS_JSON: &str = include_str!("../static/agents.json");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_crate_name() {
        assert_eq!(version(), "themis-frontend");
    }

    /// A2A 1.0 agent card validity (Story C-01 / G26). The
    /// shipped card must declare `protocolVersion: "1.0"`,
    /// expose at least one skill, and list an authentication
    /// scheme — these are the three required fields a
    /// peer validator checks before dispatching a request.
    #[test]
    fn agent_card_validates_against_a2a_1_0() {
        let v: serde_json::Value =
            serde_json::from_str(AGENT_CARD_JSON).expect("agent card must be valid JSON");
        assert_eq!(v["protocolVersion"], "1.0");
        assert_eq!(v["name"], "THEMIS Orchestrator");
        let skills = v["skills"].as_array().expect("skills array");
        assert!(!skills.is_empty(), "at least one skill required");
        let auth = &v["authentication"];
        assert!(
            auth.get("schemes").and_then(|s| s.as_array()).is_some(),
            "authentication.schemes must be an array"
        );
    }

    /// `agents.json` must list at least 6 agents (the
    /// orchestrator coordinator + 5 production agents + the
    /// new 3.0.0 honesty-auditor) so external registries can
    /// pin the fleet size (Story C-01 / G25). The shipped
    /// registry has 7 entries (the orchestrator + 6
    /// specialists); future commits may append.
    #[test]
    fn agents_json_lists_six_agents() {
        let v: serde_json::Value =
            serde_json::from_str(AGENTS_JSON).expect("agents.json must be valid JSON");
        let agents = v["agents"].as_array().expect("agents array");
        assert!(
            agents.len() >= 6,
            "expected at least 6 agents, got {}",
            agents.len()
        );
    }

    #[test]
    fn index_html_starts_with_doctype() {
        assert!(INDEX_HTML.trim_start().starts_with("<!doctype html>"));
    }

    #[test]
    fn compliance_html_starts_with_doctype() {
        assert!(COMPLIANCE_HTML.trim_start().starts_with("<!doctype html>"));
    }

    #[test]
    fn tokens_css_contains_hallmark_stamp() {
        assert!(TOKENS_CSS.contains("Hallmark"));
        assert!(TOKENS_CSS.contains("Workbench"));
    }

    #[test]
    fn app_js_contains_submit_handler() {
        assert!(APP_JS.contains("submit-form"));
        assert!(APP_JS.contains("BAAAR"));
    }

    #[test]
    fn no_emoji_in_static_assets() {
        // Hallmark gate: no emoji in production UI.
        for (name, body) in [
            ("INDEX_HTML", INDEX_HTML),
            ("COMPLIANCE_HTML", COMPLIANCE_HTML),
            ("TOKENS_CSS", TOKENS_CSS),
            ("APP_CSS", APP_CSS),
            ("APP_JS", APP_JS),
        ] {
            // No emoji codepoints. Simple scan: anything above U+007F
            // is allowed in copy (the stamp says "Θ" and
            // "·") but the script-flagged emoji ranges are
            // 1F300+ (miscellaneous symbols and pictographs).
            for c in body.chars() {
                let cp = c as u32;
                assert!(
                    !(0x1F300..=0x1FAFF).contains(&cp) && !(0x2600..=0x27BF).contains(&cp),
                    "{name} contains emoji {c:?} (codepoint {cp:X})"
                );
            }
        }
    }
}
