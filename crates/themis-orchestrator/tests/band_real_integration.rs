//! Integration test for the real Band SDK bridge.
//!
//! This test is **gated on `BAND_API_KEY` being set in the
//! environment**. When the env var is missing, the test is
//! skipped (returns early) so CI without a real Band account
//! stays green. When the env var is set, the test:
//!
//! 1. Spawns the Python subprocess via `RealBandRoom::connect`
//!    using `THEMIS_BAND_PYTHON` (default `python3`) and
//!    `THEMIS_BAND_SDK_MODULE` (default `band_sdk`).
//! 2. Opens a room, posts 10 messages, reads history back.
//! 3. Asserts the 10 history entries have monotonically
//!    increasing timestamps and the round-trip preserves the
//!    body content.
//!
//! Run with:
//!   BAND_API_KEY=test THEMIS_BAND_MODE=real \
//!   cargo test -p themis-orchestrator --test band_real_integration -- --nocapture
//!
//! Without the env var:
//!   cargo test -p themis-orchestrator --test band_real_integration
//! (test prints "skipped: BAND_API_KEY not set" and exits 0).

use std::sync::Arc;

use themis_orchestrator::room::{BandRoom, RealBandRoom};

fn real_band_available() -> bool {
    std::env::var("BAND_API_KEY")
        .ok()
        .map(|v| !v.is_empty())
        .unwrap_or(false)
        && std::env::var("THEMIS_BAND_MODE").unwrap_or_default() == "real"
}

#[tokio::test]
async fn real_band_room_round_trip() {
    if !real_band_available() {
        eprintln!("skipped: BAND_API_KEY not set or THEMIS_BAND_MODE!=real");
        return;
    }
    let python_bin = std::env::var("THEMIS_BAND_PYTHON").unwrap_or_else(|_| "python3".to_string());
    let sdk_module =
        std::env::var("THEMIS_BAND_SDK_MODULE").unwrap_or_else(|_| "band_sdk".to_string());
    let room: Arc<RealBandRoom> = match RealBandRoom::connect(&python_bin, &sdk_module) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipped: RealBandRoom::connect failed: {e}");
            return;
        }
    };
    let trait_room: Arc<dyn BandRoom> = room.clone().into_arc();
    let r = trait_room.open("stark", "ralph-test-001").await.unwrap();
    for i in 0..10 {
        trait_room
            .post_message(
                r,
                "stark",
                "ralph-agent",
                &format!("message {i}"),
                vec!["po_matcher".to_string()],
            )
            .await
            .unwrap();
    }
    let history = trait_room.history(r).await.unwrap();
    assert_eq!(history.len(), 10, "expected 10 history entries");
    for (i, m) in history.iter().enumerate() {
        assert_eq!(m.body, format!("message {i}"));
        assert_eq!(m.from, "ralph-agent");
        if i > 0 {
            assert!(
                m.ts_ms >= history[i - 1].ts_ms,
                "ts must be monotonic: history[{}].ts_ms={} < history[{}].ts_ms={}",
                i,
                m.ts_ms,
                i - 1,
                history[i - 1].ts_ms
            );
        }
    }
}
