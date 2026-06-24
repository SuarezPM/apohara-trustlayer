//! CompressionCoordinator — 4-strategy decision engine.
//!
//! Ported from Apohara Context Forge's `compression/coordinator.py:42-99`.
//! Decides which of 4 strategies to apply to an agent's raw incoming
//! context: `ApcReuse`, `CompressAndReuse`, `Compress`, `Passthrough`.
//!
//! Boundaries are strict `>` (a context is "long" when its token count
//! exceeds `min_context_tokens`; a prefix is "long" when it exceeds
//! `min_shared_prefix_tokens`). The port preserves the original
//! decision logic byte-for-byte; the only Rust-idiomatic changes are
//! the `enum Strategy` instead of a string union and explicit field
//! types instead of dicts.

/// The 4 strategies a CompressionCoordinator can pick for a context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Strong shared prefix + short context — reuse the prefix blocks,
    /// no compression needed.
    ApcReuse,
    /// Strong shared prefix + long context — reuse the prefix, compress
    /// only the unique tail.
    CompressAndReuse,
    /// No usable prefix + long context — compress the full context.
    Compress,
    /// Neither prefix nor context is long enough — pass through
    /// unchanged.
    Passthrough,
}

impl Strategy {
    /// Stable string identifier (useful for telemetry + Evidence Packet).
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::ApcReuse => "apc_reuse",
            Strategy::CompressAndReuse => "compress_and_reuse",
            Strategy::Compress => "compress",
            Strategy::Passthrough => "passthrough",
        }
    }
}

/// The decision the coordinator makes for one agent's raw context.
///
/// Mirrors the Python `CompressionDecision` dataclass: original/final
/// token counts, savings, and which strategy was applied. `prefix`
/// and `compressed_tail` are kept as owned `String` (not `&str`) so
/// the decision can be moved across async boundaries without lifetime
/// gymnastics.
#[derive(Debug, Clone, PartialEq)]
pub struct CompressionDecision {
    /// Which strategy was selected.
    pub strategy: Strategy,
    /// Stable identifier (same as `strategy.as_str()`).
    pub strategy_name: &'static str,
    /// The shared prefix text (empty when no prefix was used).
    pub prefix: String,
    /// The compressed tail text (empty when strategy does not compress
    /// a tail — e.g. `Compress` produces a single `final_context`).
    pub compressed_tail: String,
    /// The full final context the agent should see.
    pub final_context: String,
    /// Token count of the raw incoming context.
    pub original_tokens: usize,
    /// Token count of `final_context`.
    pub final_tokens: usize,
    /// `original_tokens - final_tokens`.
    pub tokens_saved: usize,
    /// `tokens_saved / original_tokens * 100`, or 0.0 if original is 0.
    pub savings_pct: f32,
}

impl CompressionDecision {
    fn passthrough(original_tokens: usize) -> Self {
        Self {
            strategy: Strategy::Passthrough,
            strategy_name: "passthrough",
            prefix: String::new(),
            compressed_tail: String::new(),
            final_context: String::new(),
            original_tokens,
            final_tokens: original_tokens,
            tokens_saved: 0,
            savings_pct: 0.0,
        }
    }

    fn apc_reuse(
        prefix: String,
        prefix_tokens: usize,
        context: String,
        context_tokens: usize,
    ) -> Self {
        // ApcReuse keeps the prefix blocks untouched; the agent will
        // still see the full context, so token count is unchanged.
        // `prefix_tokens` is surfaced for the caller to log.
        let _ = prefix_tokens;
        Self {
            strategy: Strategy::ApcReuse,
            strategy_name: "apc_reuse",
            prefix,
            compressed_tail: String::new(),
            final_context: context,
            original_tokens: context_tokens,
            final_tokens: context_tokens,
            tokens_saved: 0,
            savings_pct: 0.0,
        }
    }

    fn compress_and_reuse(
        prefix: String,
        prefix_tokens: usize,
        compressed_tail: String,
        tail_tokens: usize,
        context_tokens: usize,
    ) -> Self {
        let final_tokens = prefix_tokens + tail_tokens;
        let tokens_saved = context_tokens.saturating_sub(final_tokens);
        let savings_pct = if context_tokens > 0 {
            (tokens_saved as f32 / context_tokens as f32) * 100.0
        } else {
            0.0
        };
        let final_context = format!("{}{}", prefix, compressed_tail);
        Self {
            strategy: Strategy::CompressAndReuse,
            strategy_name: "compress_and_reuse",
            prefix,
            compressed_tail,
            final_context,
            original_tokens: context_tokens,
            final_tokens,
            tokens_saved,
            savings_pct,
        }
    }

    fn compress(compressed: String, compressed_tokens: usize, context_tokens: usize) -> Self {
        let tokens_saved = context_tokens.saturating_sub(compressed_tokens);
        let savings_pct = if context_tokens > 0 {
            (tokens_saved as f32 / context_tokens as f32) * 100.0
        } else {
            0.0
        };
        Self {
            strategy: Strategy::Compress,
            strategy_name: "compress",
            prefix: String::new(),
            compressed_tail: String::new(),
            final_context: compressed,
            original_tokens: context_tokens,
            final_tokens: compressed_tokens,
            tokens_saved,
            savings_pct,
        }
    }
}

/// The decision engine. Constructor takes the two thresholds; `decide`
/// returns the right `CompressionDecision` for the inputs.
///
/// # Example
///
/// ```
/// use themis_compressor::coordinator::{CompressionCoordinator, Strategy};
///
/// let coord = CompressionCoordinator::new(512, 256);
/// // Short context, no prefix → Passthrough.
/// let d = coord.decide(100, false, 0, "", "");
/// assert_eq!(d.strategy, Strategy::Passthrough);
/// ```
#[derive(Debug, Clone)]
pub struct CompressionCoordinator {
    min_context_tokens: usize,
    min_shared_prefix_tokens: usize,
}

impl CompressionCoordinator {
    /// Build a coordinator with explicit thresholds. No hardcoded values.
    pub fn new(min_context_tokens: usize, min_shared_prefix_tokens: usize) -> Self {
        Self {
            min_context_tokens,
            min_shared_prefix_tokens,
        }
    }

    /// Decide which strategy applies for the given inputs.
    ///
    /// * `context_tokens` — token count of the raw incoming context.
    /// * `has_shared_prefix` — whether a usable shared prefix exists.
    /// * `shared_prefix_tokens` — token count of that prefix (ignored
    ///   when `has_shared_prefix` is false).
    /// * `shared_prefix` — the prefix text (passed through to
    ///   `CompressionDecision::prefix` when the strategy keeps it).
    /// * `tail` — the unique tail text (compressed only on
    ///   `CompressAndReuse`; ignored otherwise).
    ///
    /// The decision logic follows Context Forge's 4-branch tree:
    /// 1. `has_long_prefix && !long_enough` → `ApcReuse`
    /// 2. `has_long_prefix && long_enough`  → `CompressAndReuse`
    /// 3. `long_enough` (no usable prefix)   → `Compress`
    /// 4. otherwise                          → `Passthrough`
    ///
    /// `tail` is taken as a `&str`; when compression is not needed,
    /// the original `context_tokens` and an empty `final_context`
    /// are returned (the agent will fetch the full context itself).
    pub fn decide(
        &self,
        context_tokens: usize,
        has_shared_prefix: bool,
        shared_prefix_tokens: usize,
        shared_prefix: &str,
        tail: &str,
    ) -> CompressionDecision {
        let long_enough = context_tokens > self.min_context_tokens;
        let has_long_prefix =
            has_shared_prefix && shared_prefix_tokens > self.min_shared_prefix_tokens;

        // Branch 1: ApcReuse — strong shared prefix on a short context.
        if has_long_prefix && !long_enough {
            return CompressionDecision::apc_reuse(
                shared_prefix.to_string(),
                shared_prefix_tokens,
                String::new(), // agent fetches full context
                context_tokens,
            );
        }

        // Branch 2: CompressAndReuse — strong prefix + long context.
        if has_long_prefix && long_enough {
            // Tail is the unique suffix; we don't actually run a compressor
            // here (that's US-003). For the coordinator's decision surface
            // we record the tail as if it were a 50% compression of the
            // tail's token count. US-003 will replace this stub.
            let tail_tokens = tail.split_whitespace().count();
            let compressed_tail_tokens = tail_tokens / 2;
            return CompressionDecision::compress_and_reuse(
                shared_prefix.to_string(),
                shared_prefix_tokens,
                tail.to_string(),
                compressed_tail_tokens,
                context_tokens,
            );
        }

        // Branch 3: Compress — no usable prefix but a long context.
        if long_enough {
            // Stub: 50% of context tokens. US-003 will replace.
            let compressed_tokens = context_tokens / 2;
            return CompressionDecision::compress(
                String::new(), // US-003 will fill with actual compressed text
                compressed_tokens,
                context_tokens,
            );
        }

        // Branch 4: Passthrough.
        CompressionDecision::passthrough(context_tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Min thresholds: 512 for context, 256 for shared prefix.
    fn coord() -> CompressionCoordinator {
        CompressionCoordinator::new(512, 256)
    }

    #[test]
    fn short_context_no_prefix_passes_through() {
        // 100 tokens (≤ 512), no prefix → Passthrough.
        let d = coord().decide(100, false, 0, "", "raw tail");
        assert_eq!(d.strategy, Strategy::Passthrough);
        assert_eq!(d.strategy_name, "passthrough");
        assert_eq!(d.original_tokens, 100);
        assert_eq!(d.final_tokens, 100);
        assert_eq!(d.tokens_saved, 0);
        assert_eq!(d.savings_pct, 0.0);
    }

    #[test]
    fn long_context_no_prefix_compresses() {
        // 1000 tokens (> 512), no prefix → Compress.
        let d = coord().decide(1000, false, 0, "", "long tail");
        assert_eq!(d.strategy, Strategy::Compress);
        assert_eq!(d.strategy_name, "compress");
        assert_eq!(d.original_tokens, 1000);
        assert_eq!(d.final_tokens, 500); // stub: 50% compression
        assert_eq!(d.tokens_saved, 500);
        assert!((d.savings_pct - 50.0).abs() < 0.01);
    }

    #[test]
    fn short_context_long_prefix_reuses_without_compressing() {
        // 100 tokens (≤ 512), 300-token prefix (> 256) → ApcReuse.
        let d = coord().decide(100, true, 300, "shared prefix text", "tail");
        assert_eq!(d.strategy, Strategy::ApcReuse);
        assert_eq!(d.strategy_name, "apc_reuse");
        assert_eq!(d.prefix, "shared prefix text");
        assert_eq!(d.original_tokens, 100);
        assert_eq!(d.final_tokens, 100);
        assert_eq!(d.tokens_saved, 0);
        assert_eq!(d.savings_pct, 0.0);
    }

    #[test]
    fn long_context_long_prefix_compresses_tail() {
        // 1000 tokens (> 512), 300-token prefix (> 256) → CompressAndReuse.
        let tail = "alpha beta gamma delta epsilon zeta eta theta"; // 8 words → 4 compressed
        let d = coord().decide(1000, true, 300, "shared prefix text", tail);
        assert_eq!(d.strategy, Strategy::CompressAndReuse);
        assert_eq!(d.strategy_name, "compress_and_reuse");
        assert_eq!(d.prefix, "shared prefix text");
        assert_eq!(d.compressed_tail, tail);
        assert_eq!(d.final_context, format!("shared prefix text{}", tail));
        // prefix_tokens (300) + tail_compressed (4) = 304; saved = 1000 - 304 = 696
        assert_eq!(d.final_tokens, 304);
        assert_eq!(d.tokens_saved, 696);
        assert!((d.savings_pct - 69.6).abs() < 0.01);
    }

    #[test]
    fn boundary_512_is_not_long_enough() {
        // Strict >: exactly 512 tokens is NOT long enough.
        let d = coord().decide(512, false, 0, "", "x");
        assert_eq!(d.strategy, Strategy::Passthrough);
    }

    #[test]
    fn boundary_513_is_long_enough() {
        // 513 tokens IS long enough (> 512).
        let d = coord().decide(513, false, 0, "", "x");
        assert_eq!(d.strategy, Strategy::Compress);
    }

    #[test]
    fn boundary_256_prefix_is_not_long() {
        // Strict >: exactly 256-token prefix is NOT long enough.
        let d = coord().decide(100, true, 256, "p", "t");
        assert_eq!(d.strategy, Strategy::Passthrough);
    }

    #[test]
    fn boundary_257_prefix_is_long() {
        let d = coord().decide(100, true, 257, "p", "t");
        assert_eq!(d.strategy, Strategy::ApcReuse);
    }

    #[test]
    fn strategy_as_str_is_stable() {
        // Telemetry + Evidence Packet depend on these strings.
        assert_eq!(Strategy::ApcReuse.as_str(), "apc_reuse");
        assert_eq!(Strategy::CompressAndReuse.as_str(), "compress_and_reuse");
        assert_eq!(Strategy::Compress.as_str(), "compress");
        assert_eq!(Strategy::Passthrough.as_str(), "passthrough");
    }
}
