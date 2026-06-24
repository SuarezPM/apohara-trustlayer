//! THEMIS_REKOR_MODE env gate for the production orchestrator.
//!
//! The orchestrator's `with_evidence` constructor takes an
//! `Option<Arc<dyn RekorClient>>`. The production binary picks the
//! concrete backend at startup based on the `THEMIS_REKOR_MODE`
//! environment variable, so demos and judges never need a code
//! change to switch transparency-log backends.
//!
//! ## Mode values
//!
//! | Mode     | Backend                                            |
//! |----------|----------------------------------------------------|
//! | `mock`   | `MockRekorClient` (default; deterministic in-mem)  |
//! | `v2`     | `RekorV2Client` (public-good Rekor v2 over gRPC)   |
//! | `cosign` | `CosignRekorClient` (shell-out to `cosign` binary)  |
//!
//! Unknown / unset values fall back to `mock` with a stderr
//! warning. **The demo must never break at startup** — even if
//! Rekor is unreachable, the orchestrator runs and emits evidence
//! packets without anchoring (graceful degradation is the
//! production contract; see `anchor_in_rekor`).
//!
//! ## Test seam
//!
//! `THEMIS_REKOR_ENDPOINT` (default
//! [`REKOR_V2_DEFAULT_ENDPOINT`]) feeds `RekorV2Client::connect`
//! in the `v2` mode. This is a TEST SEAM ONLY per the resolved
//! Q4 in the plan; the default is the hardcoded production
//! endpoint. Integration tests point it at a local Rekor docker
//! container via `127.0.0.1:1` to exercise the lazy-connect path.

use std::sync::Arc;

use themis_evidence::rekor::{CosignRekorClient, MockRekorClient, RekorClient};
use themis_evidence::rekor_v2::{RekorV2Client, REKOR_V2_DEFAULT_ENDPOINT};

/// Environment variable that selects the Rekor backend. Default
/// `"mock"` (see module docs).
pub const THEMIS_REKOR_MODE: &str = "THEMIS_REKOR_MODE";

/// Environment variable that overrides the Rekor v2 endpoint.
/// Test seam only (see module docs).
const THEMIS_REKOR_ENDPOINT: &str = "THEMIS_REKOR_ENDPOINT";

/// Build the production `Arc<dyn RekorClient>` from the env.
///
/// Always returns a usable client (mock on fallback). Logs to
/// stderr if the requested mode is unknown or the construction
/// failed; the demo path must never fail to start.
pub fn build_rekor_client() -> Arc<dyn RekorClient> {
    let mode = std::env::var(THEMIS_REKOR_MODE)
        .ok()
        .unwrap_or_else(|| "mock".to_string());
    match mode.as_str() {
        "mock" => Arc::new(MockRekorClient::new()),
        "v2" => build_v2_client(),
        "cosign" => Arc::new(CosignRekorClient::new()),
        other => {
            eprintln!("[warn] unknown THEMIS_REKOR_MODE={other:?}; falling back to mock");
            Arc::new(MockRekorClient::new())
        }
    }
}

/// Construct a `RekorV2Client` against the endpoint picked from
/// `THEMIS_REKOR_ENDPOINT` (default
/// `REKOR_V2_DEFAULT_ENDPOINT`). On construction failure
/// (invalid endpoint URL), warn + fall back to mock so the
/// binary still starts.
fn build_v2_client() -> Arc<dyn RekorClient> {
    let endpoint = std::env::var(THEMIS_REKOR_ENDPOINT)
        .ok()
        .unwrap_or_else(|| REKOR_V2_DEFAULT_ENDPOINT.to_string());
    match RekorV2Client::connect(&endpoint) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!(
                "[warn] THEMIS_REKOR_MODE=v2: failed to build RekorV2Client ({e}); falling back to mock"
            );
            Arc::new(MockRekorClient::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Global mutex serializes tests that mutate env vars.
    // `std::env` is process-global; cargo test runs in parallel,
    // so env mutations race. The mutex forces tests to be
    // sequential. Cost: ~1ms per test (negligible). Mirrors the
    // pattern in `llm_backend::tests::ENV_LOCK`.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Unset env → MockRekorClient. Debug assertion (each impl
    /// has a unique Debug representation; we use that to avoid
    /// coupling these tests to an `Any` derive).
    #[test]
    fn select_rekor_client_defaults_to_mock_when_env_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::remove_var(THEMIS_REKOR_MODE);
            std::env::remove_var(THEMIS_REKOR_ENDPOINT);
        }
        let client = build_rekor_client();
        let dbg = format!("{client:?}");
        assert!(
            dbg.contains("MockRekorClient"),
            "expected MockRekorClient, got: {dbg}"
        );
    }

    /// `THEMIS_REKOR_MODE=v2` → RekorV2Client. Channel::connect
    /// is lazy, so this only asserts on the constructed type
    /// (no real network I/O).
    #[tokio::test]
    async fn select_rekor_client_v2_returns_rekor_v2_client() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(THEMIS_REKOR_MODE, "v2");
            std::env::set_var(THEMIS_REKOR_ENDPOINT, "127.0.0.1:1");
        }
        let client = build_rekor_client();
        let dbg = format!("{client:?}");
        assert!(
            dbg.contains("RekorV2Client"),
            "expected RekorV2Client, got: {dbg}"
        );
    }

    /// Unknown mode value → mock + stderr warning. The demo must
    /// never fail to start.
    #[test]
    fn select_rekor_client_unknown_falls_back_to_mock() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(THEMIS_REKOR_MODE, "garbage");
            std::env::remove_var(THEMIS_REKOR_ENDPOINT);
        }
        let client = build_rekor_client();
        let dbg = format!("{client:?}");
        assert!(
            dbg.contains("MockRekorClient"),
            "expected MockRekorClient fallback for unknown mode, got: {dbg}"
        );
    }

    /// `THEMIS_REKOR_MODE=cosign` → CosignRekorClient. Whether
    /// `cosign` is on PATH doesn't affect construction (the
    /// client defers the lookup to `anchor()`); the assertion
    /// is on the constructed type, not on a successful shell-out.
    #[test]
    fn select_rekor_client_cosign_returns_cosign_client() {
        let _g = ENV_LOCK.lock().unwrap();
        unsafe {
            std::env::set_var(THEMIS_REKOR_MODE, "cosign");
            std::env::remove_var(THEMIS_REKOR_ENDPOINT);
        }
        let client = build_rekor_client();
        let dbg = format!("{client:?}");
        assert!(
            dbg.contains("CosignRekorClient"),
            "expected CosignRekorClient, got: {dbg}"
        );
    }
}
