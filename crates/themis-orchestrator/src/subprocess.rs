//! THEMIS subprocess spawning helpers (Story C-02 / G15, G18, G33).
//!
//! Currently THEMIS spawns exactly one external subprocess: the Band
//! Python SDK bridge (see `themis-band-client::python_bridge::PythonBandBridge::spawn`).
//! That bridge is owned by the band-client crate; the orchestrator
//! does not spawn it directly. The helpers in this module are the
//! future-facing seam for any orchestrator-owned subprocess (e.g.
//! a `git` or `cosign` invocation that the orchestrator itself
//! initiates, not the band-client) and they route through the
//! `apohara-agentguard` sandbox profile.
//!
//! ## Why this lives here
//!
//! C-02's PRD entry refers to `src/subprocess.rs` as the place where
//! the AgentGuard sandbox is wired into "any subprocess that THEMIS
//! spawns." Today that's a single call site (the Python bridge), and
//! the bridge itself already calls `std::process::Command::new`
//! directly. The orchestrator-level helper is the place where a
//! future orchestrator-owned subprocess (e.g. a one-shot `git
//! rev-parse` for evidence correlation) plugs into the same
//! allow-list + seccomp + Landlock policy without each call site
//! having to re-implement it.
//!
//! ## Fail-closed posture
//!
//! `spawn_band_subprocess` validates the requested binary against
//! `allowed_commands` BEFORE handing the argv to the agentguard
//! `SandboxRunner`. A non-allow-listed binary returns
//! `Err(SpawnError::NotAllowed)` without spawning — the agentguard
//! fail-closed guarantees are layered on top of the THEMIS allow-list,
//! not substituted for it.

use std::path::{Path, PathBuf};
use std::process::Command;

use thiserror::Error;

use crate::sandbox::{run_sandboxed, SubprocessSandboxConfig, ThemIsSandboxError};

/// Errors raised by [`spawn_band_subprocess`]. Each variant maps to a
/// fail-closed outcome — the wrapper never spawns unconfined.
#[derive(Debug, Error)]
pub enum SpawnError {
    /// The binary path is not on `SubprocessSandboxConfig::allowed_commands`.
    /// Caller should NOT fall back to a direct `Command::new`.
    #[error("subprocess binary {0:?} is not on the sandbox allow-list")]
    NotAllowed(PathBuf),
    /// The agentguard sandbox refused to run (non-Linux, missing
    /// workspace_root, kernel rejected Landlock/seccomp, …).
    #[error("sandbox refused: {0}")]
    Sandbox(#[from] ThemIsSandboxError),
}

/// Spawn the Band Python SDK subprocess under the orchestrator-level
/// sandbox profile. The wrapper:
///
/// 1. Verifies `python` resolves to an allow-listed binary. If the
///    requested path is not on the allow-list, returns
///    `Err(SpawnError::NotAllowed)` without spawning. The
///    agentguard allow-list check is layered ON TOP of this check,
///    not substituted for it.
/// 2. Constructs a `std::process::Command` with the requested `args`.
/// 3. Routes the command through [`run_sandboxed`] which wraps the
///    agentguard `SandboxRunner` (namespace + Landlock + seccomp on
///    Linux; fail-closed elsewhere).
///
/// `python` is the resolved path to the Python interpreter; `args`
/// are passed verbatim as the argv tail. `config` carries the
/// permission tier, allow-list, and workspace root.
///
/// Note: this function returns the raw agentguard `SandboxResult`,
/// not the `Child`. The orchestrator does not currently own the
/// Python bridge lifecycle (the band-client does). For call sites
/// that need to capture the result, hand the closure a body that
/// stores the result and the helper returns the same value.
pub async fn spawn_band_subprocess(
    python: &Path,
    args: &[String],
    config: &SubprocessSandboxConfig,
) -> Result<apohara_agentguard::sandbox::SandboxResult, SpawnError> {
    // 1. Allow-list check (THEMIS-side). The agentguard policy file
    //    evaluator is the SECOND line of defense; this check is the
    //    FIRST and must NOT be skipped. We compare the absolute path
    //    to each allow-list entry (substring match on the file name
    //    or full path) — exact match on the file name, glob-ish
    //    substring on the full path.
    let python_str = python.to_string_lossy().to_string();
    let allowed = config.allowed_commands.iter().any(|entry| {
        entry == &python_str
            || python
                .file_name()
                .map(|f| f.to_string_lossy() == entry.as_str())
                .unwrap_or(false)
    });
    if !allowed {
        return Err(SpawnError::NotAllowed(python.to_path_buf()));
    }

    // 2. Build the command. The sandbox facade's `run_sandboxed` will
    //    re-derive argv from `cmd.get_program()` + `cmd.get_args()`,
    //    so we don't need to mirror that here.
    let mut cmd = Command::new(python);
    for a in args {
        cmd.arg(a);
    }

    // 3. Run under the agentguard sandbox. On Linux this installs
    //    namespace + Landlock + seccomp; on non-Linux the agentguard
    //    runner fails closed with `SandboxError::Unavailable`, which
    //    surfaces here as `ThemIsSandboxError::Unavailable` →
    //    `SpawnError::Sandbox`.
    let result = tokio::task::spawn_blocking({
        let cfg = config.clone();
        move || run_sandboxed(&cfg, &mut cmd, Ok)
    })
    .await
    .map_err(|e| {
        SpawnError::Sandbox(ThemIsSandboxError::Unavailable(format!(
            "worker panicked: {e}"
        )))
    })??;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apohara_agentguard::sandbox::PermissionTier;

    fn tmp_config(python_name: &str) -> SubprocessSandboxConfig {
        SubprocessSandboxConfig::new("/tmp")
            .with_tier(PermissionTier::ReadOnly)
            .with_allowed_commands([python_name])
    }

    #[test]
    fn spawn_band_subprocess_rejects_unlisted_python_binary() {
        // We don't actually spawn — the function returns
        // `Err(SpawnError::NotAllowed)` BEFORE reaching the
        // agentguard runner. The runtime is synchronous enough that
        // `tokio::runtime::Runtime::block_on` works inside a test
        // (we're not in an existing runtime).
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let cfg = tmp_config("python3");
        let result = rt.block_on(spawn_band_subprocess(
            Path::new("/usr/local/bin/evil-python"),
            &["-V".to_string()],
            &cfg,
        ));
        match result {
            Err(SpawnError::NotAllowed(p)) => {
                assert_eq!(p, PathBuf::from("/usr/local/bin/evil-python"));
            }
            other => panic!("expected NotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn allow_list_accepts_filename_match() {
        // The allow-list also matches by file name, so callers can
        // list "python3" once and have it cover any absolute path.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let cfg = tmp_config("python3");
        // `python3` is on the allow-list; we still expect the sandbox
        // to fail closed on non-Linux (the agentguard runner returns
        // SandboxError::Unavailable). What matters for THIS test is
        // that we did NOT get `SpawnError::NotAllowed` — we cleared
        // the THEMIS gate and reached the agentguard gate.
        let result = rt.block_on(spawn_band_subprocess(
            Path::new("/usr/bin/python3"),
            &["-V".to_string()],
            &cfg,
        ));
        match result {
            Err(SpawnError::NotAllowed(_)) => {
                panic!("allow-list filename match failed unexpectedly")
            }
            Err(SpawnError::Sandbox(_)) | Ok(_) => { /* cleared the THEMIS gate */ }
        }
    }
}
