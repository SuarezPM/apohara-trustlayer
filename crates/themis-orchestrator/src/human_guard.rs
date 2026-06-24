//! Alert-fatigue detector — ASI09 (Human-Agent Trust Exploitation) defense.
//!
//! OWASP Agentic 2026 / ASI09: a compromised or overly-trusting
//! human can be manipulated into rubber-stamping agent decisions
//! (e.g., approving every BAAAR HALT override without reading the
//! reason). This module detects that pattern and suspends HITL
//! until the human re-authenticates.
//!
//! Policy:
//!
//! * More than `max_approvals_per_window` approvals within
//!   `window` → `AlertFatigueStatus::Suspended`.
//! * While suspended, `check_authorization` returns
//!   `Err(AlertFatigueError::RequiresReauth)`.
//! * `reset_after_reauth` clears the queue and resumes HITL.
//!
//! Used by `Orchestrator::override_packet` (Story C-06 / G22 /
//! AC6) when the human posts a `POST /packets/:id/override` body.
//! Wiring lands in a follow-up when the WebAuthn override flow is
//! touched.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use thiserror::Error;

/// Default maximum approvals allowed within the sliding window.
pub const DEFAULT_MAX_APPROVALS: u32 = 5;

/// Default sliding window length.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(60);

/// Status returned by `record_approval`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertFatigueStatus {
    /// Human is within budget. `count` is the number of approvals
    /// recorded within the current window (including this one).
    Ok {
        /// Approvals in the current window.
        count: u32,
    },
    /// Human has crossed the alert-fatigue threshold. HITL is
    /// suspended until `reset_after_reauth` is called.
    Suspended {
        /// Earliest instant at which the window may clear (the
        /// timestamp of the (count - threshold)-th approval). The
        /// UI can render a countdown to this instant.
        until: Instant,
        /// Number of approvals currently in the window.
        count: u32,
    },
}

/// Errors emitted by `check_authorization`.
#[derive(Debug, Error)]
pub enum AlertFatigueError {
    /// Human has approved too many HALT overrides in too short a
    /// window. Re-authentication is required before further
    /// approvals are accepted.
    #[error("alert fatigue: HITL suspended, re-auth required")]
    RequiresReauth,
}

/// Alert-fatigue detector. Cheap to clone (no inner state) and
/// `Send + Sync` via the inner `Mutex`.
pub struct AlertFatigueDetector {
    /// Max approvals within the sliding window before suspension.
    pub max_approvals_per_window: u32,
    /// Sliding window length.
    pub window: Duration,
    /// Timestamps of approvals still inside the window.
    pub approvals: Mutex<VecDeque<Instant>>,
}

impl Default for AlertFatigueDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertFatigueDetector {
    /// Construct a detector with the default policy (5/60s).
    pub fn new() -> Self {
        Self::with_params(DEFAULT_MAX_APPROVALS, DEFAULT_WINDOW)
    }

    /// Construct a detector with a custom approval budget.
    pub fn with_max_approvals(max: u32) -> Self {
        Self::with_params(max, DEFAULT_WINDOW)
    }

    /// Construct a detector with a custom window length.
    pub fn with_window(window: Duration) -> Self {
        Self::with_params(DEFAULT_MAX_APPROVALS, window)
    }

    /// Construct a detector with both parameters set explicitly.
    pub fn with_params(max_approvals_per_window: u32, window: Duration) -> Self {
        assert!(
            max_approvals_per_window > 0,
            "max_approvals_per_window must be > 0"
        );
        Self {
            max_approvals_per_window,
            window,
            approvals: Mutex::new(VecDeque::new()),
        }
    }

    /// Record one human approval. Prunes timestamps older than
    /// the window, then either accepts or suspends HITL.
    pub fn record_approval(&self) -> AlertFatigueStatus {
        self.record_approval_at(Instant::now())
    }

    /// Same as `record_approval` but with an explicit timestamp —
    /// the test seam. Pruning is based on `now - window`.
    fn record_approval_at(&self, now: Instant) -> AlertFatigueStatus {
        let mut guard = self.lock_approvals();
        // Prune entries that have aged out of the window.
        while let Some(front) = guard.front() {
            if now.duration_since(*front) >= self.window {
                guard.pop_front();
            } else {
                break;
            }
        }
        // Record this approval.
        guard.push_back(now);
        let count: u32 = guard
            .len()
            .try_into()
            .expect("queue length fits in u32 (VecDeque is bounded by human approvals)");
        drop(guard);
        if count > self.max_approvals_per_window {
            // The earliest timestamp in the queue is the one that
            // will roll off next — that's when the window can
            // clear (modulo any new approvals coming in).
            let until = self
                .lock_approvals()
                .front()
                .copied()
                .map(|t| t + self.window)
                .unwrap_or(now);
            AlertFatigueStatus::Suspended { until, count }
        } else {
            AlertFatigueStatus::Ok { count }
        }
    }

    /// Gate for the override endpoint. Returns
    /// `Err(RequiresReauth)` if HITL is currently suspended,
    /// `Ok(())` otherwise.
    pub fn check_authorization(&self) -> Result<(), AlertFatigueError> {
        let mut guard = self.lock_approvals();
        let now = Instant::now();
        while let Some(front) = guard.front() {
            if now.duration_since(*front) >= self.window {
                guard.pop_front();
            } else {
                break;
            }
        }
        let count: u32 = guard.len().try_into().expect("queue length fits in u32");
        drop(guard);
        if count > self.max_approvals_per_window {
            Err(AlertFatigueError::RequiresReauth)
        } else {
            Ok(())
        }
    }

    /// Clear the approval queue. Called by the orchestrator after
    /// a successful re-authentication ceremony.
    pub fn reset_after_reauth(&self) {
        self.lock_approvals().clear();
    }

    /// Snapshot the current queue length (for dashboards/tests).
    pub fn current_count(&self) -> u32 {
        self.lock_approvals()
            .len()
            .try_into()
            .expect("queue length fits in u32")
    }

    /// Lock the queue, recovering from poisoning so a panic in
    /// one approval doesn't permanently brick the detector.
    fn lock_approvals(&self) -> std::sync::MutexGuard<'_, VecDeque<Instant>> {
        match self.approvals.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn first_5_approvals_are_ok() {
        let d = AlertFatigueDetector::new();
        for i in 1..=5 {
            let s = d.record_approval();
            assert!(
                matches!(s, AlertFatigueStatus::Ok { count } if count == i),
                "approval #{i} should be Ok(count={i}), got {s:?}"
            );
        }
    }

    #[test]
    fn sixth_approval_suspends() {
        let d = AlertFatigueDetector::new();
        for _ in 0..5 {
            let _ = d.record_approval();
        }
        let s = d.record_approval();
        assert!(
            matches!(s, AlertFatigueStatus::Suspended { count: 6, .. }),
            "6th approval should suspend, got {s:?}"
        );
    }

    #[test]
    fn expired_window_resets_count() {
        // Use a 50ms window so the test is fast.
        let d = AlertFatigueDetector::with_params(5, Duration::from_millis(50));
        for _ in 0..5 {
            assert!(matches!(d.record_approval(), AlertFatigueStatus::Ok { .. }));
        }
        assert!(matches!(
            d.record_approval(),
            AlertFatigueStatus::Suspended { .. }
        ));
        // Sleep just past the window — all 6 approvals age out.
        std::thread::sleep(Duration::from_millis(60));
        assert!(d.check_authorization().is_ok());
        assert_eq!(d.current_count(), 0);
    }

    #[test]
    fn reauth_clears_suspension() {
        let d = AlertFatigueDetector::new();
        for _ in 0..6 {
            let _ = d.record_approval();
        }
        assert!(matches!(
            d.check_authorization(),
            Err(AlertFatigueError::RequiresReauth)
        ));
        d.reset_after_reauth();
        assert!(d.check_authorization().is_ok());
        assert_eq!(d.current_count(), 0);
    }

    #[test]
    fn suspension_persists_through_check_authorization() {
        let d = AlertFatigueDetector::new();
        for _ in 0..6 {
            let _ = d.record_approval();
        }
        // check_authorization must report RequiresReauth without
        // mutating the queue (the suspension is sticky until
        // explicit reauth, not just window expiry).
        assert!(matches!(
            d.check_authorization(),
            Err(AlertFatigueError::RequiresReauth)
        ));
        assert!(matches!(
            d.check_authorization(),
            Err(AlertFatigueError::RequiresReauth)
        ));
        assert_eq!(d.current_count(), 6);
    }
}
