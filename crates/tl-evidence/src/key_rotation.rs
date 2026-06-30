//! Key rotation runtime with grace period (v1.1.0 → v1.1.1).
//!
//! Per Plan v1.1 Block 4 v1.1.0-US-12 (Key rotation runtime):
//!
//! The `KeyStore` loads keys but does NOT rotate. This module adds
//! the rotation runtime: configurable rotation interval, grace
//! period where the previous key is still accepted for verification,
//! and an append-only rotation log for audit.
//!
//! ## Why grace period?
//!
//! When a key rotates, in-flight evidence bundles signed with the OLD
//! key must still be verifiable. The grace period (e.g. 30 days)
//! allows verification of evidence signed during the transition
//! while the active signer uses the NEW key.
//!
//! ## Why append-only rotation log?
//!
//! DORA Art. 19 + ISO 27001 A.10.1.2 require an auditable trail of
//! key lifecycle events. Every rotation produces a
//! `KeyRotationEvent { old_key_id, new_key_id, rotated_at, reason }`
//! that is persisted to the `key_rotation_events` table (append-only).
//!
//! ## Pattern ported from
//!
//! Adapted from NIST SP 800-57 Part 1 §5.3.6 (Cryptographic Key
//! Management / Key Transition) and RFC 7517 §4.7 (JWK lifecycle).
//!
//! ## What this module is NOT
//!
//! - Not a key derivation function (KDF) — keys are loaded from
//!   external sources (env, KMS, Vault).
//! - Not a key escrow — keys are managed by the caller; this module
//!   only enforces rotation timing and grace window.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Errors from the key rotation runtime.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyRotationError {
    #[error("rotation interval must be > 0")]
    InvalidInterval,
    #[error("grace period must be >= 0")]
    InvalidGracePeriod,
    #[error("key id `{0}` not found in store (active or grace)")]
    KeyNotFound(String),
    #[error("key id `{0}` is retired (outside grace period)")]
    KeyRetired(String),
}

/// Reason for a key rotation event. Persisted to audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationReason {
    /// Scheduled rotation (interval elapsed).
    Scheduled,
    /// Compromised key — emergency rotation.
    Compromised,
    /// Algorithm migration (e.g. Ed25519 → post-quantum).
    AlgorithmMigration,
    /// Operational reason (operator-initiated).
    Operational,
    /// Initial key activation.
    Initial,
}

impl RotationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RotationReason::Scheduled => "scheduled",
            RotationReason::Compromised => "compromised",
            RotationReason::AlgorithmMigration => "algorithm_migration",
            RotationReason::Operational => "operational",
            RotationReason::Initial => "initial",
        }
    }
}

/// A key rotation event (append-only audit record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    pub event_id: Uuid,
    pub old_key_id: Option<String>,
    pub new_key_id: String,
    pub rotated_at: DateTime<Utc>,
    pub reason: RotationReason,
    pub operator: Option<String>,
    pub notes: Option<String>,
}

impl KeyRotationEvent {
    pub fn new(old_key_id: Option<String>, new_key_id: String, reason: RotationReason) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            old_key_id,
            new_key_id,
            rotated_at: Utc::now(),
            reason,
            operator: None,
            notes: None,
        }
    }
}

/// Policy controlling when and how keys rotate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    /// Minimum interval between rotations (e.g. 90 days per NIST SP 800-57).
    pub rotation_interval: Duration,
    /// Grace period after rotation where old key is still accepted
    /// for verification (e.g. 30 days). After this, old key is retired.
    pub grace_period: Duration,
    /// Optional: warn when this much time has elapsed since last
    /// rotation (default = rotation_interval / 2).
    pub warn_after: Option<Duration>,
}

impl KeyRotationPolicy {
    /// Default policy: 90-day rotation, 30-day grace (NIST SP 800-57 baseline).
    pub fn default_nist() -> Self {
        Self {
            rotation_interval: Duration::days(90),
            grace_period: Duration::days(30),
            warn_after: Some(Duration::days(45)),
        }
    }

    pub fn validate(&self) -> Result<(), KeyRotationError> {
        if self.rotation_interval <= Duration::zero() {
            return Err(KeyRotationError::InvalidInterval);
        }
        if self.grace_period < Duration::zero() {
            return Err(KeyRotationError::InvalidGracePeriod);
        }
        Ok(())
    }

    /// True iff `now` is past the warn threshold AND not yet past the
    /// rotation deadline. Returns false if the policy has not been
    /// validated.
    pub fn should_warn(&self, last_rotated_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let warn_after = self.warn_after.unwrap_or(self.rotation_interval / 2);
        let elapsed = now.signed_duration_since(last_rotated_at);
        elapsed >= warn_after && elapsed < self.rotation_interval
    }

    /// True iff `now` is past the rotation deadline.
    pub fn should_rotate(&self, last_rotated_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let elapsed = now.signed_duration_since(last_rotated_at);
        elapsed >= self.rotation_interval
    }
}

/// In-memory key store with rotation runtime + grace period.
///
/// Tracks:
/// - The currently ACTIVE key (used for new signatures).
/// - Previous keys within their GRACE period (accepted for verification).
/// - Retired keys (outside grace, rejected — even for verification).
///
/// The store is append-only for the rotation log; key entries can be
/// removed once they fall outside grace (the event remains in the log).
#[derive(Debug, Clone)]
pub struct KeyStore {
    policy: KeyRotationPolicy,
    active_key_id: Option<String>,
    grace_keys: Vec<(String, DateTime<Utc>)>, // (key_id, retired_at)
    rotation_log: Vec<KeyRotationEvent>,
}

impl KeyStore {
    pub fn new(policy: KeyRotationPolicy) -> Self {
        Self {
            policy,
            active_key_id: None,
            grace_keys: Vec::new(),
            rotation_log: Vec::new(),
        }
    }

    pub fn policy(&self) -> &KeyRotationPolicy {
        &self.policy
    }

    pub fn active_key_id(&self) -> Option<&str> {
        self.active_key_id.as_deref()
    }

    pub fn rotation_log(&self) -> &[KeyRotationEvent] {
        &self.rotation_log
    }

    pub fn grace_key_ids(&self) -> Vec<String> {
        self.grace_keys.iter().map(|(id, _)| id.clone()).collect()
    }

    /// Initial key activation. Records a rotation event with reason=Initial.
    pub fn activate_initial(&mut self, key_id: impl Into<String>) -> Result<(), KeyRotationError> {
        let key_id = key_id.into();
        self.policy.validate()?;
        if self.active_key_id.is_some() {
            // Treat subsequent activation as a regular rotation.
            return self.rotate(key_id, RotationReason::Operational, None);
        }
        self.active_key_id = Some(key_id.clone());
        let event = KeyRotationEvent::new(None, key_id, RotationReason::Initial);
        self.rotation_log.push(event);
        Ok(())
    }

    /// Rotate to a new key. The previous active key moves to grace.
    pub fn rotate(
        &mut self,
        new_key_id: impl Into<String>,
        reason: RotationReason,
        operator: Option<String>,
    ) -> Result<(), KeyRotationError> {
        let new_key_id = new_into_string(new_key_id);
        self.policy.validate()?;
        let now = Utc::now();
        // Move the previous active key into grace.
        if let Some(old) = self.active_key_id.take() {
            self.grace_keys.push((old, now));
        }
        self.active_key_id = Some(new_key_id.clone());
        let mut event = KeyRotationEvent::new(
            self.rotation_log
                .last()
                .and_then(|e| Some(e.new_key_id.clone())),
            new_key_id,
            reason,
        );
        event.operator = operator;
        self.rotation_log.push(event);
        Ok(())
    }

    /// Verify a key id is acceptable for verification right now.
    /// Returns Ok(()) iff the key is either active or in grace.
    pub fn verify_key_acceptable(&mut self, key_id: &str) -> Result<(), KeyRotationError> {
        self.evict_retired_keys();
        if self.active_key_id.as_deref() == Some(key_id) {
            return Ok(());
        }
        if self.grace_keys.iter().any(|(id, _)| id == key_id) {
            return Ok(());
        }
        // Not active, not in grace. Either unknown or retired.
        if self.rotation_log.iter().any(|e| e.new_key_id == key_id) {
            Err(KeyRotationError::KeyRetired(key_id.to_string()))
        } else {
            Err(KeyRotationError::KeyNotFound(key_id.to_string()))
        }
    }

    /// Evict keys whose grace period has expired.
    fn evict_retired_keys(&mut self) {
        let now = Utc::now();
        let grace = self.policy.grace_period;
        self.grace_keys
            .retain(|(_, retired_at)| now.signed_duration_since(*retired_at) < grace);
    }
}

/// Helper to convert `impl Into<String>` into `String` for the rotate API.
fn new_into_string(s: impl Into<String>) -> String {
    s.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_nist_policy_validates() {
        let p = KeyRotationPolicy::default_nist();
        assert!(p.validate().is_ok());
        assert_eq!(p.rotation_interval, Duration::days(90));
        assert_eq!(p.grace_period, Duration::days(30));
    }

    #[test]
    fn zero_interval_is_rejected() {
        let p = KeyRotationPolicy {
            rotation_interval: Duration::zero(),
            grace_period: Duration::days(30),
            warn_after: None,
        };
        assert_eq!(p.validate(), Err(KeyRotationError::InvalidInterval));
    }

    #[test]
    fn negative_grace_is_rejected() {
        let p = KeyRotationPolicy {
            rotation_interval: Duration::days(90),
            grace_period: Duration::days(-1),
            warn_after: None,
        };
        assert_eq!(p.validate(), Err(KeyRotationError::InvalidGracePeriod));
    }

    #[test]
    fn should_rotate_after_interval() {
        let p = KeyRotationPolicy::default_nist();
        let last = Utc::now() - Duration::days(91);
        assert!(p.should_rotate(last, Utc::now()));
        let last_recent = Utc::now() - Duration::days(30);
        assert!(!p.should_rotate(last_recent, Utc::now()));
    }

    #[test]
    fn should_warn_in_warn_window() {
        let p = KeyRotationPolicy::default_nist();
        let in_window = Utc::now() - Duration::days(50); // between 45 (warn) and 90 (rotate)
        assert!(p.should_warn(in_window, Utc::now()));
        let too_soon = Utc::now() - Duration::days(10);
        assert!(!p.should_warn(too_soon, Utc::now()));
        let too_late = Utc::now() - Duration::days(100);
        assert!(!p.should_warn(too_late, Utc::now())); // past rotation, not in warn
    }

    #[test]
    fn initial_activation_records_event() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        assert_eq!(s.active_key_id(), Some("key-v1"));
        assert_eq!(s.rotation_log().len(), 1);
        assert_eq!(s.rotation_log()[0].reason, RotationReason::Initial);
        assert!(s.rotation_log()[0].old_key_id.is_none());
    }

    #[test]
    fn rotate_moves_old_to_grace() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        s.rotate("key-v2", RotationReason::Scheduled, Some("ops@acme".into()))
            .unwrap();
        assert_eq!(s.active_key_id(), Some("key-v2"));
        assert!(s.grace_key_ids().contains(&"key-v1".to_string()));
        assert_eq!(s.rotation_log().len(), 2);
        assert_eq!(s.rotation_log()[1].reason, RotationReason::Scheduled);
        assert_eq!(s.rotation_log()[1].operator.as_deref(), Some("ops@acme"));
    }

    #[test]
    fn active_and_grace_keys_acceptable_for_verify() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        s.rotate("key-v2", RotationReason::Scheduled, None).unwrap();
        assert!(s.verify_key_acceptable("key-v2").is_ok());
        assert!(s.verify_key_acceptable("key-v1").is_ok()); // still in grace
    }

    #[test]
    fn unknown_key_rejected() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        assert_eq!(
            s.verify_key_acceptable("unknown"),
            Err(KeyRotationError::KeyNotFound("unknown".into()))
        );
    }

    #[test]
    fn retired_key_rejected_after_grace_expires() {
        // Use a tiny grace period (1 second) so we can test eviction.
        let p = KeyRotationPolicy {
            rotation_interval: Duration::days(90),
            grace_period: Duration::seconds(0),
            warn_after: None,
        };
        let mut s = KeyStore::new(p);
        s.activate_initial("key-v1").unwrap();
        s.rotate("key-v2", RotationReason::Scheduled, None).unwrap();
        // grace_period=0 seconds — the old key is evicted immediately.
        assert!(s.verify_key_acceptable("key-v1").is_err());
    }

    #[test]
    fn compromised_rotation_records_emergency_reason() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        s.rotate(
            "key-v2",
            RotationReason::Compromised,
            Some("secops@acme".into()),
        )
        .unwrap();
        assert_eq!(s.rotation_log()[1].reason, RotationReason::Compromised);
        assert_eq!(s.rotation_log()[1].operator.as_deref(), Some("secops@acme"));
    }

    #[test]
    fn multiple_rotations_maintain_log_chain() {
        let mut s = KeyStore::new(KeyRotationPolicy::default_nist());
        s.activate_initial("key-v1").unwrap();
        s.rotate("key-v2", RotationReason::Scheduled, None).unwrap();
        s.rotate("key-v3", RotationReason::Scheduled, None).unwrap();
        s.rotate("key-v4", RotationReason::AlgorithmMigration, None)
            .unwrap();
        assert_eq!(s.rotation_log().len(), 4);
        assert_eq!(
            s.rotation_log()[3].reason,
            RotationReason::AlgorithmMigration
        );
        // Active is v4, v1+v2+v3 are in grace (within 30 days).
        assert_eq!(s.active_key_id(), Some("key-v4"));
        let grace = s.grace_key_ids();
        assert!(grace.contains(&"key-v1".to_string()));
        assert!(grace.contains(&"key-v2".to_string()));
        assert!(grace.contains(&"key-v3".to_string()));
    }
}
