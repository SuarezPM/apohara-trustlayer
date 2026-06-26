//! INV-15 prompt-injection verifier (regex MVP).
//!
//! Absorbed from `Apohara_Context_Forge`'s INV-15 verifier (Plan v3.0 W3.2).
//! Detects prompt-injection attempts before they reach the LLM, returning a
//! typed [`Verdict`] (Allow | Warn | Block) and the matched patterns for
//! audit logging.
//!
//! ## Pattern scoring
//!
//! Each pattern has a `weight` in `0.0..=1.0`. The verifier sums the
//! weights of every pattern that matches the input and compares against
//! [`Thresholds`] (defaults: `block_score = 0.8`, `warn_score = 0.5`).
//! `score >= block_score` -> [`Verdict::Block`]. `score >= warn_score` ->
//! [`Verdict::Warn`]. Else -> [`Verdict::Allow`].
//!
//! The thresholds are conservative on purpose: false positives (blocking
//! legit prompts) are cheap (operator review); false negatives (letting an
//! injection through) are catastrophic.
//!
//! ## 5 categories
//!
//! | Category              | Example patterns                            |
//! |-----------------------|---------------------------------------------|
//! | `GoalOverride`        | "ignore previous", "disregard prior"        |
//! | `SystemOverride`      | "system override", "sudo mode"              |
//! | `RoleImpersonation`   | "act as", "pretend to be", "you are now"    |
//! | `SecretExtraction`    | "reveal the secret", "show me the prompt"   |
//! | `Jailbreak`           | "DAN", "bypass restrictions", "developer mode" |

use regex::Regex;
use serde::Serialize;

/// The decision returned by [`Inv15Verifier::verify`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// Prompt looks safe - pass through to the LLM.
    Allow,
    /// Prompt is suspicious but not clearly malicious - log and pass.
    Warn(String),
    /// Prompt is an obvious injection attempt - block before send.
    Block(String),
}

/// Tunable thresholds for the verifier.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// Inclusive lower bound for [`Verdict::Block`]. Defaults to `0.8`.
    pub block_score: f32,
    /// Inclusive lower bound for [`Verdict::Warn`]. Defaults to `0.5`.
    pub warn_score: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            block_score: 0.8,
            warn_score: 0.5,
        }
    }
}

/// Category of a prompt-injection pattern. Mirrors OWASP LLM01's
/// attack surface so audit logs can be filtered per category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternCategory {
    /// "ignore previous instructions", "disregard prior rules".
    GoalOverride,
    /// "system override", "sudo mode".
    SystemOverride,
    /// "you are now", "act as", "pretend to be".
    RoleImpersonation,
    /// "reveal the secret", "show me the system prompt".
    SecretExtraction,
    /// "DAN", "bypass restrictions", "jailbreak".
    Jailbreak,
}

/// A compiled regex pattern with its category + weight.
#[derive(Debug)]
pub struct Pattern {
    /// Stable identifier used in audit logs (e.g. `"ignore_previous"`).
    pub name: &'static str,
    /// The compiled regex.
    pub regex: Regex,
    /// Score contribution in `0.0..=1.0`.
    pub weight: f32,
    /// Category for filtering.
    pub category: PatternCategory,
}

/// Spec for a pattern, used at construction time. `regex` is a
/// string the verifier compiles once at startup.
pub struct PatternSpec {
    /// Stable identifier (matches [`Pattern::name`]).
    pub name: &'static str,
    /// Raw regex source.
    pub regex: &'static str,
    /// Score contribution in `0.0..=1.0`.
    pub weight: f32,
    /// Category for filtering.
    pub category: PatternCategory,
}

/// A single match against the input. Returned by
/// [`Inv15Verifier::pattern_matches`] for audit logging.
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// Stable identifier of the matched pattern.
    pub pattern_name: &'static str,
    /// Category of the matched pattern.
    pub category: PatternCategory,
    /// Score contribution of the matched pattern.
    pub weight: f32,
}

/// The INV-15 verifier. Holds the compiled pattern set and the
/// block/warn thresholds.
///
/// Construct with [`Inv15Verifier::new`] for the default 10-pattern set
/// + default thresholds, or [`Inv15Verifier::with_patterns`] to override.
pub struct Inv15Verifier {
    /// Compiled patterns, in priority order.
    pub patterns: Vec<Pattern>,
    /// Score thresholds.
    pub thresholds: Thresholds,
}

/// Default pattern set - 10 patterns covering the 5 INV-15 categories
/// (GoalOverride, SystemOverride, RoleImpersonation, SecretExtraction,
/// Jailbreak). Weights are tuned so a single high-confidence pattern
/// (`ignore_previous`, `disregard_prior`, `reveal_secret`,
/// `forget_everything`, `pretend_to_be`) alone trips the block
/// threshold (>= 0.8), while role-impersonation patterns alone trip
/// only the warn threshold (>= 0.5, < 0.8).
pub const DEFAULT_PATTERNS: &[PatternSpec] = &[
    // ---- GoalOverride --------------------------------------------------
    PatternSpec {
        name: "ignore_previous",
        regex: r"(?i)\bignore\s+(?:all\s+|the\s+)?(?:previous|prior|above|my)\s*(?:instructions?|prompts?|rules?|context|safety|filters?|safeguards?)?\b",
        weight: 1.0,
        category: PatternCategory::GoalOverride,
    },
    PatternSpec {
        name: "disregard_prior",
        regex: r"(?i)\bdisregard\s+(?:all\s+|your\s+|the\s+|my\s+)?(?:prior|previous|above|training|context|rules?|instructions?|prompts?)\b",
        weight: 1.0,
        category: PatternCategory::GoalOverride,
    },
    PatternSpec {
        name: "forget_everything",
        regex: r"(?i)\bforget\s+(?:everything|all)\s+(?:above|prior|previous)\b",
        weight: 1.0,
        category: PatternCategory::GoalOverride,
    },
    // ---- SystemOverride ------------------------------------------------
    PatternSpec {
        name: "system_override",
        regex: r"(?i)\b(?:system|admin|sudo|root)\s*(?:override|mode|prompt|command|access|privileges?)\b",
        weight: 0.9,
        category: PatternCategory::SystemOverride,
    },
    // ---- RoleImpersonation ---------------------------------------------
    PatternSpec {
        name: "you_are_now",
        regex: r"(?i)\byou\s+are\s+now\s+(?:a|an|the|my)\b",
        weight: 0.7,
        category: PatternCategory::RoleImpersonation,
    },
    PatternSpec {
        name: "act_as",
        regex: r"(?i)\b(?:act|behave|respond)\s+as\s+(?:a|an|the|if)\b",
        weight: 0.6,
        category: PatternCategory::RoleImpersonation,
    },
    PatternSpec {
        name: "pretend_to_be",
        regex: r"(?i)\bpretend\s+(?:to\s+be|you(?:'re|\s+are))\b",
        weight: 0.85,
        category: PatternCategory::RoleImpersonation,
    },
    // ---- SecretExtraction ----------------------------------------------
    PatternSpec {
        name: "reveal_secret",
        regex: r"(?i)\b(?:reveal|show|print|leak|expose|dump)\s+(?:the\s+|my\s+)?(?:secret|password|api[_\s-]?key|token|credential)s?\b",
        weight: 1.0,
        category: PatternCategory::SecretExtraction,
    },
    PatternSpec {
        name: "system_prompt_extract",
        regex: r"(?i)\b(?:show|reveal|repeat|print|dump|leak)\s+(?:me\s+)?(?:the|your)\s+(?:system\s+prompt|hidden\s+instructions?|original\s+instructions?)\b",
        weight: 0.9,
        category: PatternCategory::SecretExtraction,
    },
    // ---- Jailbreak -----------------------------------------------------
    PatternSpec {
        name: "dan_jailbreak",
        regex: r"(?i)\b(?:DAN|do\s+anything\s+now|developer\s+mode|god\s+mode)\b",
        weight: 0.9,
        category: PatternCategory::Jailbreak,
    },
    PatternSpec {
        name: "bypass_restrictions",
        regex: r"(?i)\bbypass\s+(?:the\s+)?(?:restrictions?|filters?|safeguards?|guardrails?|safety\s+(?:filters?|checks?))\b",
        weight: 0.8,
        category: PatternCategory::Jailbreak,
    },
];

impl Default for Inv15Verifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Inv15Verifier {
    /// Build a verifier with the default 10-pattern set and the default
    /// thresholds (`block >= 0.8`, `warn >= 0.5`).
    pub fn new() -> Self {
        Self::with_patterns(DEFAULT_PATTERNS, Thresholds::default())
    }

    /// Build a verifier with a custom pattern set and thresholds.
    /// Returns the verifier, or panics with a clear message if any
    /// regex fails to compile (regex compilation is a programmer error,
    /// not a runtime condition).
    pub fn with_patterns(specs: &[PatternSpec], thresholds: Thresholds) -> Self {
        let patterns = specs
            .iter()
            .map(|s| Pattern {
                name: s.name,
                regex: Regex::new(s.regex).unwrap_or_else(|e| {
                    panic!("INV-15 pattern '{}' failed to compile: {e}", s.name)
                }),
                weight: s.weight,
                category: s.category,
            })
            .collect();
        Self {
            patterns,
            thresholds,
        }
    }

    /// Verify a single text against the pattern set. Sums the weights
    /// of every matching pattern and returns the verdict.
    pub fn verify(&self, text: &str) -> Verdict {
        let score = self.score(text);
        let matches = self.pattern_matches(text);
        if score >= self.thresholds.block_score {
            Verdict::Block(format!(
                "INV-15 score {score:.2} >= block_score {:.2}; matched: {}",
                self.thresholds.block_score,
                match_names(&matches)
            ))
        } else if score >= self.thresholds.warn_score {
            Verdict::Warn(format!(
                "INV-15 score {score:.2} >= warn_score {:.2}; matched: {}",
                self.thresholds.warn_score,
                match_names(&matches)
            ))
        } else {
            Verdict::Allow
        }
    }

    /// Return every matched pattern for audit logging. Use this alongside
    /// [`Self::verify`] to record WHY the verdict fired (the verdict
    /// string only summarizes).
    pub fn pattern_matches(&self, text: &str) -> Vec<PatternMatch> {
        self.patterns
            .iter()
            .filter(|p| p.regex.is_match(text))
            .map(|p| PatternMatch {
                pattern_name: p.name,
                category: p.category,
                weight: p.weight,
            })
            .collect()
    }

    /// Sum of all matching pattern weights. Used by [`Self::verify`] and
    /// exposed for callers that want a numeric signal (e.g. dashboards,
    /// regression tests).
    pub fn score(&self, text: &str) -> f32 {
        self.pattern_matches(text).iter().map(|m| m.weight).sum()
    }
}

fn match_names(matches: &[PatternMatch]) -> String {
    matches
        .iter()
        .map(|m| m.pattern_name)
        .collect::<Vec<_>>()
        .join(", ")
}
