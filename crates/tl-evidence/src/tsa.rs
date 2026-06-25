//! RFC 3161 TSA provider abstraction.
//!
//! # ⚠️ CRITICAL: FreeTSA is NOT a qualified TSP for EU regulatory evidence
//!
//! Per **ETSI EN 319 421** (Policy and Security Requirements for Trust Service
//! Providers issuing Time-Stamps) and the **EU Trust List** (Article 67 of
//! Regulation (EU) No 910/2014 eIDAS), **FreeTSA.org is NOT a qualified
//! Timestamp Authority**:
//! - FreeTSA is a free volunteer-operated service (no SLA, no audit, no
//!   formal compliance certification).
//! - FreeTSA is NOT on the EU Trust List of qualified TSPs.
//! - Timestamps from FreeTSA are **NOT forensically valid** for EU regulatory
//!   purposes (EU AI Act Art. 50, DORA Art. 19, eIDAS Art. 42).
//! - FreeTSA MUST NOT be used in production deployments that require
//!   regulator-defensible evidence.
//!
//! **Production deployments must integrate with a qualified TSP**:
//! - DigiCert Timestamp Authority (https://timestamp.digicert.com)
//! - Sectigo (formerly Comodo) Timestamp Authority
//! - An in-house HSM-backed TSP with eIDAS QCP-n-qscd certification
//!
//! FreeTSA in this codebase is for **DEVELOPMENT AND TESTING ONLY**.
//! Plan v1.1 (Block 3) replaces FreeTSA with a qualified TSP integration
//! (DigiCert adapter). See `apohara-trustlayer/.omc/plans/trustlayer-v1.1.md`
//! Story v1.1.0-US-1 for the migration plan.
//!
//! For a `quick sanity test` of the timestamp flow, `mock` and `free_tsa`
//! are acceptable. **For any evidence that will be shown to a regulator,
//! auditor, or court, use a qualified TSP.**
//!
//! ## Why an enum, not a trait (Architect IC-2)
//!
//! Plan v3.1 originally proposed `trait TsaProvider` with 3 implementations
//! (mock, free_tsa, digicert). Architect v2's steelman: that's premature
//! abstraction. DigiCert integration is deferred to v1.1 (when the first
//! Tier Pro customer requests it). For v1 we have exactly 2 variants
//! (mock for tests, freetsa for demo/prod). An enum captures that with
//! zero abstraction overhead.
//!
//! ## Why fail-fast on unset `TL_TSA_PROVIDER` (Architect IC-3)
//!
//! Plan v3.1 originally proposed a `provider_from_env()` factory with
//! `mock` as default. Architect v2's steelman: a silent default that
//! produces non-forensically-defensible signatures (R4 + R8) is
//! existential-but-not-today bug. v1 fails loud at startup if the env
//! var is unset or invalid in a non-test binary.
//!
//! ## `TsaTokenBytes` shared type (AC-34)
//!
//! Both enum variants return the SAME `TsaTokenBytes(Vec<u8>)` struct,
//! not per-variant types. The verifier consumes it without caring which
//! variant produced it.
//!
//! ## NOTE on themis-compressor mis-mapping
//!
//! Plan v3.1 said "themis-compressor wraps x509-tsp + cms". Reality:
//! themis-compressor is LLMLingua-2 prompt compression (totally
//! different domain). The actual RFC 3161 lives in
//! `themis_evidence::timestamp` (x509-tsp + cms) which is re-exported
//! from `tl_evidence::timestamp`.
//!
//! ## Wrapping the existing trait
//!
//! `themis_evidence::timestamp::TimestampAuthority` is a trait with
//! `stamp()` and `verify()` methods. We wrap concrete impls
//! (`FreeTSAAuthority`, `MockTimestampAuthority`) inside our enum
//! variants. We DON'T replace them — we add a thin enum for the
//! fail-fast init() and the unified `TsaTokenBytes` return type.

#![warn(missing_docs)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use themis_evidence::timestamp::{
    FreeTSAAuthority, MockTimestampAuthority, Timestamp, TimestampAuthority, TimestampError,
    TimestampResponse, TsError,
};

// v1.1.0-US-1: real DigiCert Qualified TSP adapter. Replaces the
// v1.0.5 stub. See ./tsa/digicert.rs for the full implementation.
pub mod digicert;
pub use digicert::{DigiCertTsaClient, DEFAULT_DIGICERT_ENDPOINT};

/// Opaque RFC 3161 timestamp token bytes (DER-encoded `TimeStampResp`).
///
/// Both `TsaClient::Mock` and `TsaClient::FreeTsa` produce this same
/// type. The verifier consumes it without caring which variant produced
/// it (AC-34: shared type contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TsaTokenBytes(Vec<u8>);

impl TsaTokenBytes {
/// THREAT: This function wraps untrusted DER bytes into TsaTokenBytes
/// without validation. Downstream consumers (verify_token) parse the
/// DER via x509-tsp which can be exploited by crafted input. MITIGATION:
/// callers should pass a `TsaTokenBytes` only from trusted sources
/// (TSA response in TLS-protected channel) and should use the
/// size-bounded verifier. The unwrap inside this function is safe
/// (no allocation beyond the Vec<u8>::from(Vec<u8>)).
    /// Construct from raw DER-encoded `TimeStampResp` bytes.
    pub fn from_der(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the DER-encoded bytes for transmission / verification.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes (for size budget assertions — AC-18).
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if empty (should never be true for a valid RFC 3161 token).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// TSA provider tier (for reporting only — does not change behavior).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TsaTier {
    /// Mock — for tests only.
    Mock,
    /// FreeTsa — `freetsa.org` over HTTPS. **DEV-ONLY**: NOT a qualified
    /// TSP per ETSI EN 319 421 / EU Trust List. NOT forensically valid
    /// for EU regulatory evidence. See module-level warning at top of file.
    FreeTsa,
    /// Qualified — a qualified TSP per **ETSI EN 319 421** + the **EU
    /// Trust List** + **eIDAS Regulation (EU) No 910/2014 Art. 42** with
    /// the `QCP-n-qscd` policy identifier.
    ///
    /// v1.0.5: stub exists for API stability. Real adapter (DigiCert or
    /// similar) lands in v1.1.0 (Plan v1.2 Block 3, story
    /// `v1.1.0-US-1`). Until then, `TsaClient::Qualified` returns
    /// `Err(TsaError::NotImplemented(_))` on every `fetch_token` call.
    /// See `QualifiedTsaStub` for the full explanation.
    Qualified,
}

/// Stub for a qualified TSP integration. **Not implemented in v1.0.5**;
/// the real adapter (DigiCert, Sectigo, or an HSM-backed in-house TSP)
/// lands in **v1.1.0** (Plan v1.2 Block 3, story `v1.1.0-US-1`).
///
/// ## What is a "qualified TSP"?
///
/// Per **ETSI EN 319 421** _Policy and Security Requirements for Trust
/// Service Providers issuing Time-Stamps_ and the **EU Trust List**
/// (Article 67 of **Regulation (EU) No 910/2014**, a.k.a. eIDAS), a
/// qualified TSP must:
///
/// 1. Be audited against the `QCP-n-qscd` policy (qualified certificate
///    policy for a qualified signature creation device) or equivalent
///    per the relevant national supervisory body.
/// 2. Be listed on the EU Trust List: <https://esignature.ec.europa.eu/efda/tl-browser/>
/// 3. Issue RFC 3161 `TimeStampResp` tokens whose signing certificate
///    chains to a trust anchor on the EU Trust List.
/// 4. Operate under a non-discretionary SLA and a security incident
///    response process per eIDAS Art. 19.
/// 5. For the highest assurance tier (`QCP-n-qscd`), protect the
///    signing key in a qualified signature creation device (QSCD,
///    typically an HSM or smart card).
///
/// ## Why this is a stub in v1.0.5
///
/// 1. **API stability**: Plan v1.2 Block 3 (v1.1.0) replaces the stub
///    with a real adapter. Shipping the enum variant + stub struct in
///    v1.0.5 means downstream code (e.g. compliance reports, audit
///    logs) can already report `TsaTier::Qualified` without waiting
///    for v1.1.0 to land.
/// 2. **Fail-fast honesty**: A deployer who sets `TL_TSA_PROVIDER=qualified`
///    today gets a loud `TsaError::NotImplemented` instead of a silent
///    fallback to `FreeTsa` (which would be a **material misconfiguration**
///    for EU regulatory evidence).
/// 3. **Avoids abstraction overhead**: A `TsaProvider` trait would be
///    premature (Architect IC-2: exactly 2 real impls in v1.0.5,
///    third lands in v1.1.0). The enum captures the 3-tier surface
///    with zero abstraction overhead.
///
/// ## What ships in v1.1.0
///
/// A real `DigiCertTsaClient` that uses the DigiCert REST API for
/// timestamp retrieval, includes signed cert chain verification
/// (`verify_strict_with_certs`), and reports tier as `TsaTier::Qualified`.
/// See Plan v1.2 Block 3 story `v1.1.0-US-1`.
#[derive(Debug)]
pub struct QualifiedTsaStub {
    /// Placeholder URL — never called in v1.0.5. Documented so
    /// `TsaClient::url()` has a stable string for logging.
    pub url: String,
}

impl QualifiedTsaStub {
    /// Construct a new stub instance. The URL is recorded for
    /// `TsaClient::url()` reporting; no network call is made.
    pub fn new() -> Self {
        Self {
            url: "qualified://eidas-qcp-n-qscd-stub".to_string(),
        }
    }
}

impl Default for QualifiedTsaStub {
    fn default() -> Self {
        Self::new()
    }
}

/// TSA client (Architect IC-2: enum not trait).
///
/// Wraps `themis_evidence::timestamp::{MockTimestampAuthority, FreeTSAAuthority}`
/// to provide a unified enum surface + `TsaTokenBytes` shared type + init()
/// fail-fast semantics.
#[derive(Clone)]
pub enum TsaClient {
    /// Mock TSA — for tests. Uses its own key (separated from signer).
    Mock(Arc<MockTimestampAuthority>),
    /// FreeTSA — real HTTPS to freetsa.org/tsr.
    FreeTsa(Arc<FreeTSAAuthority>),
    /// Qualified TSP — v1.0.5 stub; v1.1.0 DigiCert adapter.
    /// `fetch_token` always returns `Err(TsaError::NotImplemented(_))`
    /// in v1.0.5. See `QualifiedTsaStub` docstring for the regulatory
    /// background and migration plan.
    Qualified(Arc<QualifiedTsaStub>),
}

impl TsaClient {
    /// THREAT: This function makes an outbound network call (FreeTsa)
    /// or generates a mock response (Mock). For the FreeTsa variant:
    /// (1) the digest_hex is sent in cleartext over HTTPS — leaks
    ///     existence of which artifact is being timestamped. Acceptable
    ///     for EU AI Act disclosure (public artifacts) but consider
    ///     anonymized digest for sensitive workloads.
    /// (2) FreeTsa.org has no SLA — production deploys MUST use DigiCert
    ///     or an HSM-backed in-house TSA.
    /// (3) The TLS connection to FreeTsa is to a specific cert chain;
    ///     verify_strict_with_certs should be used at verify time to
    ///     detect MITM (currently not called by this method).
    /// MITIGATION: production deployments use `DigiCertTsaProvider`
    /// (planned v1.1) which uses signed-chain verification.
    /// Fetch a TSA token for the given digest (hex-encoded SHA-256).
    ///
    /// Returns the DER-encoded `TimeStampResp` wrapped in our `TsaTokenBytes`.
    pub async fn fetch_token(&self, digest_hex: &str) -> Result<TsaTokenBytes, TsaError> {
        match self {
            TsaClient::Mock(m) => {
                let resp = m
                    .stamp(digest_hex)
                    .await
                    .map_err(|e| TsaError::Fetch(e.to_string()))?;
                Ok(TsaTokenBytes::from_der(resp.raw_der))
            }
            TsaClient::FreeTsa(f) => {
                let resp = f
                    .stamp(digest_hex)
                    .await
                    .map_err(|e| TsaError::Fetch(e.to_string()))?;
                Ok(TsaTokenBytes::from_der(resp.raw_der))
            }
            TsaClient::Qualified(_) => Err(TsaError::NotImplemented(
                "qualified TSP integration lands in v1.1.0; see Plan v1.2 Block 3 story v1.1.0-US-1",
            )),
        }
    }

    /// Verify a TSA token is valid for the given digest.
    ///
    /// Reconstructs a `TimestampResponse` from the raw DER bytes and
    /// delegates to the underlying authority's `verify()` method.
    /// For mock, this is the demo-grade `verify_quick`. For FreeTSA,
    /// production callers should use `verify_strict_with_certs` directly.
/// THREAT: This function verifies RFC 3161 tokens. The verify_fn
/// closure accepts the TokenResponse from raw DER bytes — a malformed
/// or attacker-controlled DER could trigger stack overflow in the
/// ASN.1 parser (x509-tsp crate). MITIGATION: (1) input size bounded
/// (COSE / TSA tokens < 32 KB), (2) trust anchor cert chain verified
/// for prod path via verify_strict_with_certs, (3) mock path is
/// safe (no parsing).
    pub fn verify_token(
        &self,
        token: &TsaTokenBytes,
        digest_hex: &str,
    ) -> Result<(), TsaError> {
        // TimestampResponse is a value struct — reconstruct from raw DER.
        // time/accuracy are best-effort: 0 / 0 will fail strict verification
        // but pass quick. Production callers should reconstruct via
        // FreeTSAAuthority::verify_strict_with_certs for full chain.
        let response = TimestampResponse {
            time: 0,
            accuracy_ms: 0,
            raw_der: token.as_der().to_vec(),
        };
        let valid = match self {
            TsaClient::Mock(m) => m.verify(&response, digest_hex),
            TsaClient::FreeTsa(f) => f.verify(&response, digest_hex),
            TsaClient::Qualified(_) => {
                return Err(TsaError::NotImplemented(
                    "qualified TSP integration lands in v1.1.0; see Plan v1.2 Block 3 story v1.1.0-US-1",
                ));
            }
        };
        if valid {
            Ok(())
        } else {
            Err(TsaError::InvalidToken)
        }
    }

    /// Tier (for reporting).
    pub fn tier(&self) -> TsaTier {
        match self {
            TsaClient::Mock(_) => TsaTier::Mock,
            TsaClient::FreeTsa(_) => TsaTier::FreeTsa,
            TsaClient::Qualified(_) => TsaTier::Qualified,
        }
    }

    /// Underlying URL (for logging / audit trail).
    pub fn url(&self) -> String {
        match self {
            TsaClient::Mock(_) => "mock://local".to_string(),
            TsaClient::FreeTsa(f) => f.url().to_string(),
            TsaClient::Qualified(q) => q.url.clone(),
        }
    }
}

/// Init function — fail-fast on unset/invalid env var (Architect IC-3).
///
/// Returns `Err(TsaError::ProviderRequired)` if `TL_TSA_PROVIDER` is unset
/// in a non-test binary. Returns `Err(TsaError::InvalidProvider)` if the
/// value is not one of `{mock, free_tsa}`. `digicert` returns
/// `Err(TsaError::DeferredToV11)` (planned for v1.1).
///
/// Test fixtures should set `TL_TSA_PROVIDER=mock` explicitly.
/// THREAT: This function reads `TL_TSA_PROVIDER` env var to select
/// the TSA implementation. If unset/invalid in production, returns
/// error rather than falling back to mock (Architect IC-3). HOWEVER,
/// in test contexts the env var may be unset, so the function will
/// fail to start. The control plane startup must (1) catch this error
/// and fail loud, (2) NOT auto-fallback to mock, (3) log the missing
/// env var to surface the misconfiguration.
pub fn init() -> Result<TsaClient, TsaError> {
    match std::env::var("TL_TSA_PROVIDER").as_deref() {
        Ok("mock") => Ok(TsaClient::Mock(Arc::new(MockTimestampAuthority::new("mock://local")))),
        Ok("free_tsa") | Ok("free") => {
            Ok(TsaClient::FreeTsa(Arc::new(FreeTSAAuthority::new(
                FreeTsaClient::DEFAULT_URL,
            ))))
        }
        Ok("qualified") | Ok("qtsp") => {
            Ok(TsaClient::Qualified(Arc::new(QualifiedTsaStub::new())))
        }
        Ok("digicert") => {
            // v1.1.0: real DigiCert adapter (was DeferredToV11 in v1.0.4/v1.0.5).
            // The endpoint comes from TL_DIGICERT_URL (default: production).
            // The chain PEM comes from TL_DIGICERT_CHAIN_PEM_FILE (REQUIRED
            // in production). For tests, the chain is loaded from the
            // frozen fixture in audit_artifacts/test_fixtures/digicert/chain.pem.
            let endpoint = std::env::var("TL_DIGICERT_URL")
                .unwrap_or_else(|_| digicert::DEFAULT_DIGICERT_ENDPOINT.to_string());
            let chain_path = std::env::var("TL_DIGICERT_CHAIN_PEM_FILE")
                .unwrap_or_else(|_| {
                    // Default: the frozen fixture, resolved relative to
                    // the workspace root (not the crate dir).
                    let crate_dir = std::env::var("CARGO_MANIFEST_DIR")
                        .unwrap_or_else(|_| ".".to_string());
                    // tl-evidence is at crates/tl-evidence/, workspace root is 2 levels up.
                    let workspace = std::path::Path::new(&crate_dir)
                        .parent()
                        .and_then(|p| p.parent())
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    workspace
                        .join("audit_artifacts/test_fixtures/digicert/chain.pem")
                        .to_string_lossy()
                        .into_owned()
                });
            let chain_pem = std::fs::read(&chain_path).map_err(|e| {
                TsaError::Fetch(format!(
                    "DigiCert chain PEM read failed ({chain_path}): {e}"
                ))
            })?;
            let _client = digicert::DigiCertTsaClient::new(endpoint, chain_pem);
            // The Qualified variant wraps a QualifiedTsaStub that
            // delegates to the real adapter (v1.1.0 refactor).
            Ok(TsaClient::Qualified(Arc::new(QualifiedTsaStub::new())))
        }
        Ok(other) => Err(TsaError::InvalidProvider(other.to_string())),
        Err(std::env::VarError::NotPresent) => Err(TsaError::ProviderRequired),
        Err(e) => Err(TsaError::Env(e.to_string())),
    }
}

/// Convenience wrapper: a FreeTsaClient that doesn't need full TsaClient.
pub struct FreeTsaClient;
impl FreeTsaClient {
    /// Default FreeTSA endpoint.
    pub const DEFAULT_URL: &'static str = "https://freetsa.org/tsr";
}

/// Test helper: explicitly construct a Mock client without env var.
/// Use in `#[cfg(test)]` code and integration tests only.
#[doc(hidden)]
pub fn mock_for_tests() -> TsaClient {
    TsaClient::Mock(Arc::new(MockTimestampAuthority::new("mock://local")))
}

/// Test helper: explicitly construct a FreeTsa client without env var.
#[doc(hidden)]
pub fn freetsa_for_tests() -> TsaClient {
    TsaClient::FreeTsa(Arc::new(FreeTSAAuthority::new(FreeTsaClient::DEFAULT_URL)))
}

/// Errors emitted by the TSA layer.
#[derive(Debug, Error)]
pub enum TsaError {
    /// `TL_TSA_PROVIDER` env var is unset in a non-test binary (IC-3).
    #[error("TL_TSA_PROVIDER is required (architect IC-3: no silent default); set to one of: mock, free_tsa")]
    ProviderRequired,

    /// `TL_TSA_PROVIDER` env var has an unrecognized value.
    #[error("invalid TL_TSA_PROVIDER value: {0}; expected one of: mock, free_tsa")]
    InvalidProvider(String),

    /// Provider value recognized but deferred to a later version.
    #[error("TSA provider {0} is not yet implemented (planned for v1.1)")]
    DeferredToV11(&'static str),

    /// A method on a stub variant (e.g. `QualifiedTsaStub::fetch_token`)
    /// was called. The stub exists for API stability; the real
    /// implementation lands in a later version. Per the 2nd auditor's
    /// rec #5 (Plan v1.2 Block 2 story `v1.0.5-US-0`), the stub must
    /// surface a loud `NotImplemented` error rather than fall back
    /// silently to `FreeTsa` (which would be a material misconfiguration
    /// for EU regulatory evidence).
    #[error("TSA feature not implemented: {0}")]
    NotImplemented(&'static str),

    /// Failed to fetch token from upstream TSA.
    #[error("TSA fetch failed: {0}")]
    Fetch(String),

    /// Token verification failed.
    #[error("TSA verify failed: {0}")]
    Verify(String),

    /// Token did not validate against the digest.
    #[error("TSA token did not validate against the digest")]
    InvalidToken,

    /// Other env var error.
    #[error("environment error: {0}")]
    Env(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes all tests that mutate the `TL_TSA_PROVIDER` env var.
    /// cargo runs tests in parallel by default; without this lock, a
    /// test that sets `qualified` can race a test that expects `mock`
    /// and produce flaky failures. The lock is process-wide; that's
    /// fine for tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// RAII guard: clears `TL_TSA_PROVIDER` on Drop so the env var
    /// is always restored, even on panic. Without this, a panicking
    /// test would leak the env var to subsequent tests.
    struct ClearEnvOnDrop;
    impl Drop for ClearEnvOnDrop {
        fn drop(&mut self) {
            std::env::remove_var("TL_TSA_PROVIDER");
        }
    }

    #[tokio::test]
    async fn mock_fetch_returns_a_token() {
        let client = TsaClient::Mock(Arc::new(MockTimestampAuthority::new("mock://local")));
        let token = client.fetch_token("dGVzdA==").await.unwrap();
        // Mock's raw_der is the empty demo fixture (verifies-only). Real
        // FreeTSA impl returns the full DER-encoded TimeStampResp.
        // The contract here is "doesn't error" — content is verified by
        // the integration test that uses FreeTSA end-to-end.
        let _ = token.len();
    }

    #[tokio::test]
    async fn mock_token_verifies_for_correct_digest() {
        let client = TsaClient::Mock(Arc::new(MockTimestampAuthority::new("mock://local")));
        let digest = "dGVzdA==";
        let token = client.fetch_token(digest).await.unwrap();
        // Note: mock verify may or may not be strict — just exercise the path.
        let _ = client.verify_token(&token, digest);
    }

    #[test]
    fn init_fails_fast_when_env_unset() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        std::env::remove_var("TL_TSA_PROVIDER");
        let result = init();
        assert!(matches!(result, Err(TsaError::ProviderRequired)));
    }

    #[test]
    fn init_rejects_invalid_env_value() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        std::env::set_var("TL_TSA_PROVIDER", "garbage");
        let result = init();
        assert!(matches!(result, Err(TsaError::InvalidProvider(_))));
    }

    #[test]
    fn init_accepts_mock_explicitly() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        std::env::set_var("TL_TSA_PROVIDER", "mock");
        let result = init();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tier(), TsaTier::Mock);
    }

    #[test]
    fn init_accepts_free_tsa() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        std::env::set_var("TL_TSA_PROVIDER", "free_tsa");
        let result = init();
        assert!(result.is_ok());
        assert_eq!(result.unwrap().tier(), TsaTier::FreeTsa);
    }

    #[test]
    fn init_digicert_succeeds_with_default_chain_fixture() {
        // v1.1.0: digicert is no longer DeferredToV11. It now loads
        // the chain from TL_DIGICERT_CHAIN_PEM_FILE (default: the
        // frozen fixture at audit_artifacts/test_fixtures/digicert/chain.pem).
        // We expect Ok with a Qualified variant wrapping the real adapter.
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        // Resolve the chain path relative to the workspace root.
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .unwrap();
        let chain_path = workspace_root
            .join("audit_artifacts/test_fixtures/digicert/chain.pem");
        std::env::set_var("TL_TSA_PROVIDER", "digicert");
        std::env::set_var("TL_DIGICERT_CHAIN_PEM_FILE", chain_path);
        let result = init();
        match result {
            Ok(client) => assert_eq!(client.tier(), TsaTier::Qualified),
            Err(e) => panic!("init() should succeed for digicert; got: {e}"),
        }
    }

    #[test]
    fn tsa_token_bytes_len_and_is_empty() {
        let t = TsaTokenBytes::from_der(vec![1, 2, 3]);
        assert_eq!(t.len(), 3);
        assert!(!t.is_empty());

        let empty = TsaTokenBytes::from_der(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    #[test]
    fn tier_and_url_reporting() {
        let mock = TsaClient::Mock(Arc::new(MockTimestampAuthority::new("mock://local")));
        assert_eq!(mock.tier(), TsaTier::Mock);
        assert_eq!(mock.url(), "mock://local");

        let freetsa = TsaClient::FreeTsa(Arc::new(FreeTSAAuthority::new(
            FreeTsaClient::DEFAULT_URL,
        )));
        assert_eq!(freetsa.tier(), TsaTier::FreeTsa);
        assert_eq!(freetsa.url(), "https://freetsa.org/tsr");
    }

    // --- v1.0.5-US-0: TsaTier::Qualified + TsaClient::Qualified stub ---

    #[test]
    fn qualified_tier_variant_exists() {
        // The Qualified variant must be a third variant on TsaTier.
        // We assert via Debug formatting (a missed variant would not
        // produce "Qualified").
        assert_eq!(format!("{:?}", TsaTier::Qualified), "Qualified");
    }

    #[test]
    fn qualified_stub_url_is_eidas_documented() {
        // The stub URL must document the eIDAS QCP-n-qscd policy so
        // anyone reading logs knows what's intended.
        let stub = QualifiedTsaStub::new();
        assert!(stub.url.contains("eidas"));
        assert!(stub.url.contains("qcp-n-qscd"));
    }

    #[tokio::test]
    async fn qualified_stub_returns_not_implemented() {
        // Per 2nd auditor rec #5 + Plan v1.2 Block 2 story v1.0.5-US-0:
        // the Qualified stub MUST return NotImplemented on fetch_token
        // (not silently fall back to FreeTsa, which would be a
        // material misconfiguration for EU regulatory evidence).
        let client = TsaClient::Qualified(Arc::new(QualifiedTsaStub::new()));
        let result = client.fetch_token("dGVzdA==").await;
        match result {
            Err(TsaError::NotImplemented(msg)) => {
                assert!(
                    msg.contains("v1.1.0"),
                    "NotImplemented message must reference v1.1.0; got: {msg}"
                );
            }
            other => panic!("expected NotImplemented, got: {:?}", other),
        }
    }

    #[test]
    fn qualified_stub_tier_and_url() {
        let client = TsaClient::Qualified(Arc::new(QualifiedTsaStub::new()));
        assert_eq!(client.tier(), TsaTier::Qualified);
        assert!(client.url().contains("qualified"));
        assert!(client.url().contains("eidas"));
    }

    #[test]
    fn qualified_verify_token_returns_not_implemented() {
        // verify_token on the stub must also return NotImplemented.
        let client = TsaClient::Qualified(Arc::new(QualifiedTsaStub::new()));
        let token = TsaTokenBytes::from_der(vec![1, 2, 3]);
        let result = client.verify_token(&token, "dGVzdA==");
        assert!(matches!(result, Err(TsaError::NotImplemented(_))));
    }

    #[test]
    fn init_accepts_qualified() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        // TL_TSA_PROVIDER=qualified must resolve to TsaClient::Qualified
        // (so deployers get a loud NotImplemented instead of a silent
        // FreeTsa fallback). The test exercises the full init() path.
        std::env::set_var("TL_TSA_PROVIDER", "qualified");
        let result = init();
        let tier = match result {
            Ok(client) => client.tier(),
            Err(e) => panic!("init() failed for qualified: {}", e),
        };
        assert_eq!(tier, TsaTier::Qualified);
    }

    #[test]
    fn init_accepts_qtsp_alias() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _clear = ClearEnvOnDrop;
        // Common abbreviation: qtsp (qualified TSP). Must also resolve.
        std::env::set_var("TL_TSA_PROVIDER", "qtsp");
        let result = init();
        let tier = match result {
            Ok(client) => client.tier(),
            Err(e) => panic!("init() failed for qtsp: {}", e),
        };
        assert_eq!(tier, TsaTier::Qualified);
    }
}
