//! Shared types for Apohara TrustLayer.
//!
//! Currently: `OrgId` newtype with validation + feature-gated `apohara()`
//! constructor for the demo flow (Architect IC-4).
//!
//! ## Why a newtype (vs `String` raw)
//!
//! Plan v3.1 originally had `org_id = "apohara"` as a raw string. The
//! Architect v2 steelman was "string is a footgun" — empty strings,
//! path-traversal sequences, and shadowing of real customer identifiers
//! are all possible. A newtype with a validating constructor prevents
//! these at the type level.
//!
//! ## Why no env var (Architect IC-4)
//!
//! Plan v3.1's D3 proposed `TL_ORG_ID` env var with a default fallback.
//! Architect v2 rejected this as "silent default that masks
//! misconfiguration" (R-MISS-1 partial). OrgId is constructed explicitly
//! at the entrypoint (control plane auth middleware or SDK config).
//!
//! ## Demo gating
//!
//! `OrgId::apohara()` is gated to `#[cfg(any(test, feature = "demo"))]`.
//! Production builds cannot call it. Tests can always call it. The demo
//! flow uses `--features demo`. Per plan v3.1 AC-29.

#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors emitted by the OrgId type.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OrgIdError {
    /// Empty string passed to `OrgId::new`.
    #[error("OrgId cannot be empty")]
    Empty,

    /// String contains invalid characters (must be DNS-safe: a-z, 0-9, `-`).
    #[error("OrgId contains invalid characters: {0:?}; must be DNS-safe (a-z, 0-9, `-`)")]
    InvalidChars(String),

    /// String too long (max 64 chars to keep it human-readable).
    #[error("OrgId too long: {0} chars (max 64)")]
    TooLong(usize),

    /// Production build tried to call `OrgId::apohara()` (without `demo` feature or test cfg).
    #[error("OrgId::apohara() is gated to test/demo builds; production must construct from explicit org_id")]
    ProductionApoharaForbidden,
}

/// Strongly-typed org identifier. Use `OrgId::new(s)` to construct from
/// user input (validates). Use `OrgId::for_tests()` or `OrgId::apohara()`
/// for fixed-value cases (only in tests or with `--features demo`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OrgId(String);

impl OrgId {
    /// The hard-coded test org id (always available in tests).
    pub const TEST_ORG: &'static str = "test-org";

    /// The hard-coded demo org id (available with `--features demo` or in tests).
    pub const APOHARA: &'static str = "apohara";

    /// Validate the input string. Returns `Ok(())` if valid, `Err` with
    /// the specific reason otherwise.
    pub fn validate(s: &str) -> Result<(), OrgIdError> {
        if s.is_empty() {
            return Err(OrgIdError::Empty);
        }
        if s.len() > 64 {
            return Err(OrgIdError::TooLong(s.len()));
        }
        // DNS-safe: a-z, 0-9, `-`. No uppercase, no special chars (defends
        // against path-traversal sequences like `../../etc/passwd`).
        for c in s.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(OrgIdError::InvalidChars(s.to_string()));
            }
        }
        Ok(())
    }

    /// Construct from validated input.
    pub fn new(s: &str) -> Result<Self, OrgIdError> {
        Self::validate(s)?;
        Ok(Self(s.to_string()))
    }

    /// Test-only constructor (always available in tests). Returns the
    /// canonical test org id `test-org`.
    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self(Self::TEST_ORG.to_string())
    }

    /// Demo / dev constructor. Returns the canonical demo org id
    /// `apohara`. Gated to `#[cfg(any(test, feature = "demo"))]` so
    /// production builds cannot call this (per AC-29 / AC-33).
    #[cfg(any(test, feature = "demo"))]
    pub fn apohara() -> Self {
        Self(Self::APOHARA.to_string())
    }

    /// Borrow the underlying string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Issuer format per plan v3.1: `${org_id}/v1`.
    /// Example: `OrgId::new("acme").unwrap().issuer_v1() == "acme/v1"`.
    pub fn issuer_v1(&self) -> String {
        format!("{}/v1", self.0)
    }
}

impl TryFrom<String> for OrgId {
    type Error = OrgIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<OrgId> for String {
    fn from(id: OrgId) -> String {
        id.0
    }
}

impl AsRef<str> for OrgId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_accepts_valid_dns_safe() {
        assert!(OrgId::new("acme").is_ok());
        assert!(OrgId::new("acme-corp").is_ok());
        assert!(OrgId::new("acme-corp-2026").is_ok());
        assert!(OrgId::new("test-org").is_ok());
        assert!(OrgId::new("123").is_ok());
    }

    #[test]
    fn new_rejects_empty() {
        assert_eq!(OrgId::new(""), Err(OrgIdError::Empty));
    }

    #[test]
    fn new_rejects_invalid_chars() {
        assert!(matches!(
            OrgId::new("Apohara"), // uppercase
            Err(OrgIdError::InvalidChars(_))
        ));
        assert!(matches!(
            OrgId::new("../etc/passwd"), // path traversal
            Err(OrgIdError::InvalidChars(_))
        ));
        assert!(matches!(
            OrgId::new("with space"),
            Err(OrgIdError::InvalidChars(_))
        ));
        assert!(matches!(
            OrgId::new("with.dot"),
            Err(OrgIdError::InvalidChars(_))
        ));
        assert!(matches!(
            OrgId::new("with_under"),
            Err(OrgIdError::InvalidChars(_))
        ));
        assert!(matches!(
            OrgId::new("with/slash"),
            Err(OrgIdError::InvalidChars(_))
        ));
    }

    #[test]
    fn new_rejects_too_long() {
        let s = "a".repeat(65);
        assert_eq!(OrgId::new(&s), Err(OrgIdError::TooLong(65)));
    }

    #[test]
    fn for_tests_returns_test_org() {
        assert_eq!(OrgId::for_tests().as_str(), "test-org");
    }

    #[test]
    fn apohara_returns_apohara_in_tests() {
        // In tests cfg, apohara() is callable.
        assert_eq!(OrgId::apohara().as_str(), "apohara");
    }

    #[test]
    fn issuer_v1_format() {
        assert_eq!(OrgId::new("acme").unwrap().issuer_v1(), "acme/v1");
        assert_eq!(OrgId::new("apohara").unwrap().issuer_v1(), "apohara/v1");
        assert_eq!(
            OrgId::new("acme-corp-2026").unwrap().issuer_v1(),
            "acme-corp-2026/v1"
        );
    }

    #[test]
    fn serde_roundtrip_json() {
        let id = OrgId::new("acme").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"acme\"");
        let restored: OrgId = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, id);
    }

    #[test]
    fn serde_rejects_invalid_json() {
        let bad = serde_json::from_str::<OrgId>("\"../etc/passwd\"");
        assert!(bad.is_err());
    }

    #[test]
    fn try_from_string_validates() {
        assert!(OrgId::try_from("acme".to_string()).is_ok());
        assert!(OrgId::try_from("".to_string()).is_err());
        assert!(OrgId::try_from("../etc".to_string()).is_err());
    }

    #[test]
    fn display_and_as_ref() {
        let id = OrgId::new("acme").unwrap();
        assert_eq!(format!("{}", id), "acme");
        assert_eq!(id.as_ref(), "acme");
        assert_eq!(id.as_str(), "acme");
    }

    #[test]
    fn hash_works() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(OrgId::new("acme").unwrap());
        set.insert(OrgId::new("acme").unwrap()); // duplicate
        set.insert(OrgId::new("other").unwrap());
        assert_eq!(set.len(), 2);
    }
}
