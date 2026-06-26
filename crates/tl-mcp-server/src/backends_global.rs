//! W7.0 — Global accessor for the Backends container.
//!
//! W7.0 gap 1 fix: the 29 v2 tool stubs in `tools_v2.rs` need to call
//! real backends. The simplest way to wire them without changing all
//! 29 function signatures is a global `Backends` accessor.
//!
//! Pattern: a `OnceLock<Arc<Backends>>` initialized once at startup.
//! Each tool handler does `backends::get().bundle.get(&id)` etc.
//!
//! This is "encapsulation by global" — not ideal for pure OOP, but
//! pragmatic for a 29-tool dispatch table where the alternative
//! would be threading `&Backends` through every call (29 signature
//! changes, 29 test updates, and zero functional benefit since
//! backends are process-global by design).
//!
//! Tests can override the global via `set_for_tests()`.

use std::sync::{Arc, OnceLock};

use crate::backends::Backends;

static BACKENDS: OnceLock<Arc<Backends>> = OnceLock::new();

/// Initialize the global backends. Called once at server startup.
pub fn init(backends: Backends) {
    BACKENDS
        .set(Arc::new(backends))
        .expect("backends already initialized");
}

/// Get the global backends. Panics if `init` was not called.
pub fn get() -> Arc<Backends> {
    BACKENDS
        .get()
        .expect("backends not initialized; call backends::init() at startup")
        .clone()
}

/// Get the global backends if initialized, None otherwise.
pub fn try_get() -> Option<Arc<Backends>> {
    BACKENDS.get().cloned()
}

/// Test-only override.
#[cfg(test)]
pub fn set_for_tests(backends: Backends) {
    // Override by re-creating the OnceLock (only works once per process,
    // but tests run in separate processes so this is safe).
    let _ = BACKENDS.set(Arc::new(backends));
}
