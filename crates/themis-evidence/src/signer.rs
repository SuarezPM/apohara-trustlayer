//! Ed25519 signer + multi-tenant key file IO.
//!
//! Two ways to construct a `SignerService`:
//!
//! - **`from_seed(tenant, [u8; 32])`** — in-memory seed (tests +
//!   the verifier binary's deterministic replay).
//! - **`new(tenant, key_dir)`** — reads `keys/{tenant}.ed25519`
//!   from disk (creates it with random bytes + chmod 600 if
//!   missing). This is the legacy path; suitable for dev machines
//!   with persistent FS.
//! - **`for_tenant(tenant)`** — compile-time baked key via
//!   `include_bytes!`. The 2 fixture tenants (stark, wayne) have
//!   their 32-byte seeds committed to `keys/{tenant}.ed25519`
//!   and embedded in the binary. **This is the deployment path**
//!   (R4 + R8 mitigation: Vercel's ephemeral FS cannot persist
//!   generated keys across deploys; baked keys survive that).
//!   For SaaS mode (any other tenant id), the seed is derived
//!   deterministically via HKDF-SHA256 from a baked master seed
//!   and the tenant id (see FIX-6).

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use thiserror::Error;

/// Stark's baked-in Ed25519 seed (32 bytes, hex sha256 of
/// `themis-stark-tenant-baked-seed-v1`). Embedded at compile time
/// via `include_bytes!`; survives Vercel's ephemeral FS.
pub static STARK_SEED: [u8; 32] = *include_bytes!("../keys/stark.ed25519");

/// Wayne's baked-in Ed25519 seed (32 bytes, hex sha256 of
/// `themis-wayne-tenant-baked-seed-v1`).
pub static WAYNE_SEED: [u8; 32] = *include_bytes!("../keys/wayne.ed25519");

/// SaaS multi-tenant master seed (FIX-6).
///
/// Baked at compile time. Never written to disk, never logged,
/// never serialised. Used as the IKM for HKDF-SHA256 derivation
/// of per-tenant seeds. 32 bytes is exactly the Ed25519 seed
/// length, so the HKDF output maps 1:1 to an Ed25519 signing key.
///
/// Distinct from `STARK_SEED` / `WAYNE_SEED` so that fixture
/// tenants cannot collide with SaaS-derived keys by accident.
const MASTER_SEED: [u8; 32] = [
    0x54, 0x68, 0x65, 0x6d, 0x69, 0x73, 0x2d, 0x6d, // "Themis-m"
    0x61, 0x73, 0x74, 0x65, 0x72, 0x2d, 0x73, 0x65, // "aster-se"
    0x65, 0x64, 0x2d, 0x76, 0x31, 0x2d, 0x6e, 0x6f, // "ed-v1-no"
    0x6e, 0x63, 0x65, 0x2d, 0x66, 0x69, 0x78, 0x21, // "nce-fix!"
];

/// HKDF-SHA256 salt for SaaS tenant derivation. Bumped as `v1`;
/// change the suffix if the derivation protocol is ever rotated.
const HKDF_SALT: &[u8] = b"themis-tenant-v1";

/// An Ed25519 keypair (signing + verifying).
#[derive(Debug, Clone)]
pub struct KeyPair {
    /// The signing key (private).
    pub signing: SigningKey,
    /// The verifying key (public).
    pub verifying: VerifyingKey,
}

impl KeyPair {
    /// Generate a fresh random keypair using the OS RNG.
    pub fn generate() -> Self {
        let mut csprng = rand::rng();
        let mut bytes = [0u8; 32];
        csprng.fill_bytes(&mut bytes);
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Construct from a 32-byte seed (deterministic).
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&seed);
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    /// Hex-encoded public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying.to_bytes())
    }
}

/// Signer errors.
#[derive(Debug, Error)]
pub enum SignerError {
    /// IO error reading or writing the key file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Key file is not exactly 32 bytes.
    #[error("invalid key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
}

/// Per-tenant signing service. Holds the signing key in memory;
/// loads from / writes to `keys/{tenant}.ed25519` on construction.
pub struct SignerService {
    keypair: KeyPair,
    tenant_id: String,
}

impl std::fmt::Debug for SignerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerService")
            .field("tenant_id", &self.tenant_id)
            .field("public_key_hex", &self.keypair.public_key_hex())
            .finish()
    }
}

impl SignerService {
    /// New signer for the given tenant. Reads `keys/{tenant}.ed25519`
    /// (creating it with random bytes + chmod 600 if missing).
    pub fn new(tenant_id: impl Into<String>, key_dir: &Path) -> Result<Self, SignerError> {
        let tenant_id = tenant_id.into();
        std::fs::create_dir_all(key_dir)?;
        let key_path = key_dir.join(format!("{tenant_id}.ed25519"));
        let keypair = if key_path.exists() {
            let bytes = std::fs::read(&key_path)?;
            if bytes.len() != 32 {
                return Err(SignerError::InvalidKeyLength(bytes.len()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            KeyPair::from_bytes(seed)
        } else {
            let kp = KeyPair::generate();
            std::fs::write(&key_path, kp.signing.to_bytes())?;
            // chmod 600 on Unix. On non-Unix this is a no-op.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                std::fs::set_permissions(&key_path, perms)?;
            }
            kp
        };
        Ok(Self { keypair, tenant_id })
    }

    /// New signer from an in-memory seed (no file IO). For tests.
    pub fn from_seed(tenant_id: impl Into<String>, seed: [u8; 32]) -> Self {
        Self {
            keypair: KeyPair::from_bytes(seed),
            tenant_id: tenant_id.into(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.signing.sign(message)
    }

    /// Sign a message, return hex-encoded signature (128 chars).
    pub fn sign_hex(&self, message: &[u8]) -> String {
        hex::encode(self.sign(message).to_bytes())
    }

    /// Verify a signature. Returns true iff the signature is valid
    /// for the given message under this signer's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.keypair.verifying.verify(message, signature).is_ok()
    }

    /// Hex-encoded public key (64 chars).
    pub fn public_key_hex(&self) -> String {
        self.keypair.public_key_hex()
    }

    /// The signer's tenant id.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Build a `SignerService` from a compile-time baked seed for
    /// the two fixture tenants (`stark`, `wayne`), or via
    /// HKDF-SHA256 derivation from a baked master seed for any
    /// other tenant id (SaaS multi-tenant mode, FIX-6).
    ///
    /// - `stark` and `wayne` use seeds committed to
    ///   `keys/{tenant}.ed25519` and embedded via `include_bytes!`.
    /// - Any other id is treated as a SaaS tenant: a 32-byte
    ///   Ed25519 seed is derived via HKDF-SHA256(salt=`"themis-tenant-v1"`,
    ///   ikm=`MASTER_SEED`, info=tenant_id). The derivation is
    ///   deterministic, so the same tenant id always produces the
    ///   same keypair (no key churn across deploys). Distinct
    ///   tenants get cryptographically isolated keys (the
    ///   HKDF output space is the full 256-bit Ed25519 seed space).
    ///
    /// Note: this never returns `SignerError::UnknownTenant` now —
    /// any string is a valid SaaS tenant id. The variant is kept
    /// for callers that explicitly want to reject unknown ids (use
    /// `from_seed` or `new` for that path).
    pub fn for_tenant(tenant_id: &str) -> Result<Self, SignerError> {
        let seed: [u8; 32] = match tenant_id {
            "stark" => STARK_SEED,
            "wayne" => WAYNE_SEED,
            other => derive_saas_seed(other),
        };
        Ok(Self::from_seed(tenant_id, seed))
    }
}

/// Derive a deterministic 32-byte Ed25519 seed for a SaaS tenant
/// id via HKDF-SHA256(salt=HKDF_SALT, ikm=MASTER_SEED, info=tenant_id).
///
/// The 32-byte output is exactly the Ed25519 seed length, so the
/// caller can pass it straight to `KeyPair::from_bytes`. Distinct
/// tenants get distinct keys (HKDF output space = 256 bits), and
/// the same tenant id always derives the same seed (deterministic,
/// no key churn across deploys).
fn derive_saas_seed(tenant_id: &str) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(HKDF_SALT), &MASTER_SEED);
    let mut seed = [0u8; 32];
    // expand() with a 32-byte L (within HKDF-SHA256's 255 *
    // HashLen = 8160-byte limit) is infallible — the only error
    // case is L > 8160, which cannot happen for a 32-byte output.
    hk.expand(tenant_id.as_bytes(), &mut seed)
        .expect("HKDF-SHA256 expand with 32-byte output cannot fail");
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = SignerService::from_seed("stark", [1u8; 32]);
        let msg = b"hello world";
        let sig = signer.sign(msg);
        assert!(signer.verify(msg, &sig));
    }

    #[test]
    fn from_seed_is_deterministic() {
        let s1 = SignerService::from_seed("stark", [1u8; 32]);
        let s2 = SignerService::from_seed("stark", [1u8; 32]);
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
        assert_eq!(s1.sign_hex(b"hello"), s2.sign_hex(b"hello"),);
    }

    #[test]
    fn from_seed_distinct_tenants_differ() {
        let s1 = SignerService::from_seed("stark", [1u8; 32]);
        let s2 = SignerService::from_seed("wayne", [2u8; 32]);
        assert_ne!(s1.public_key_hex(), s2.public_key_hex());
    }

    #[test]
    fn public_key_hex_is_64_chars() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        assert_eq!(s.public_key_hex().len(), 64);
    }

    #[test]
    fn sign_hex_is_128_chars() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        assert_eq!(s.sign_hex(b"hello").len(), 128);
    }

    #[test]
    fn verify_fails_on_tampered_message() {
        let s = SignerService::from_seed("x", [0u8; 32]);
        let sig = s.sign(b"hello");
        assert!(!s.verify(b"hellp", &sig));
    }

    #[test]
    fn new_persists_key_with_chmod_600() {
        let tmp = TempDir::new().unwrap();
        let s1 = SignerService::new("stark", tmp.path()).unwrap();
        // Second construction reads the same file → same key.
        let s2 = SignerService::new("stark", tmp.path()).unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());

        // chmod 600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = tmp.path().join("stark.ed25519");
            let meta = std::fs::metadata(&path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn new_rejects_invalid_key_length() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("broken.ed25519");
        std::fs::write(&path, b"short").unwrap();
        let err = SignerService::new("broken", tmp.path()).unwrap_err();
        assert!(matches!(err, SignerError::InvalidKeyLength(5)));
    }

    #[test]
    fn for_tenant_returns_baked_signers() {
        let stark = SignerService::for_tenant("stark").unwrap();
        let wayne = SignerService::for_tenant("wayne").unwrap();
        assert_eq!(stark.tenant_id(), "stark");
        assert_eq!(wayne.tenant_id(), "wayne");
        // The two tenants must NOT share a key.
        assert_ne!(stark.public_key_hex(), wayne.public_key_hex());
    }

    #[test]
    fn for_tenant_is_deterministic() {
        // Same tenant → same keypair (baked seeds are constants).
        let s1 = SignerService::for_tenant("stark").unwrap();
        let s2 = SignerService::for_tenant("stark").unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
        // Same input → same signature (deterministic Ed25519).
        let msg = b"deterministic test";
        assert_eq!(s1.sign_hex(msg), s2.sign_hex(msg));
    }

    #[test]
    fn for_tenant_accepts_saas_tenant_via_hkdf() {
        // FIX-6: any non-fixture tenant id is now accepted via
        // HKDF-SHA256 derivation (SaaS mode). Previously this
        // returned `SignerError::UnknownTenant`.
        let lexcorp = SignerService::for_tenant("lexcorp").unwrap();
        assert_eq!(lexcorp.tenant_id(), "lexcorp");
        // 64-char hex public key = a valid Ed25519 verifying key.
        assert_eq!(lexcorp.public_key_hex().len(), 64);
    }

    #[test]
    fn for_tenant_saas_key_differs_from_fixtures() {
        // A SaaS-derived key must NOT collide with stark or wayne.
        let stark = SignerService::for_tenant("stark").unwrap();
        let wayne = SignerService::for_tenant("wayne").unwrap();
        let acme = SignerService::for_tenant("acme_corp").unwrap();
        assert_ne!(acme.public_key_hex(), stark.public_key_hex());
        assert_ne!(acme.public_key_hex(), wayne.public_key_hex());
    }

    #[test]
    fn for_tenant_saas_is_deterministic() {
        // Same tenant id → same key (HKDF is a pure function).
        let s1 = SignerService::for_tenant("acme_corp").unwrap();
        let s2 = SignerService::for_tenant("acme_corp").unwrap();
        assert_eq!(s1.public_key_hex(), s2.public_key_hex());
        // Deterministic Ed25519 ⇒ same signature for same message.
        let msg = b"saas deterministic test";
        assert_eq!(s1.sign_hex(msg), s2.sign_hex(msg));
    }

    #[test]
    fn for_tenant_distinct_saas_tenants_get_distinct_keys() {
        // Two SaaS tenants must derive different keys (collision
        // resistance of HKDF-SHA256 in the 256-bit output space).
        let a = SignerService::for_tenant("acme_corp").unwrap();
        let b = SignerService::for_tenant("initech").unwrap();
        assert_ne!(a.public_key_hex(), b.public_key_hex());
    }

    #[test]
    fn for_tenant_saas_roundtrip_sign_verify() {
        // Sanity: HKDF-derived key is a valid Ed25519 signing key.
        let s = SignerService::for_tenant("acme_corp").unwrap();
        let msg = b"hkdf roundtrip";
        let sig = s.sign(msg);
        assert!(s.verify(msg, &sig));
        assert!(!s.verify(b"tampered", &sig));
    }

    #[test]
    fn derive_saas_seed_is_32_bytes() {
        // The HKDF output must be exactly 32 bytes for Ed25519.
        let seed = derive_saas_seed("anything");
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn cross_tenant_verify_fails_with_baked_keys() {
        let stark = SignerService::for_tenant("stark").unwrap();
        let wayne = SignerService::for_tenant("wayne").unwrap();
        let msg = b"only stark should be able to verify this";
        let sig = stark.sign(msg);
        // Wayne cannot verify Stark's signature.
        assert!(!wayne.verify(msg, &sig));
        // But Stark can.
        assert!(stark.verify(msg, &sig));
    }

    #[test]
    fn baked_seed_is_32_bytes() {
        assert_eq!(STARK_SEED.len(), 32);
        assert_eq!(WAYNE_SEED.len(), 32);
        // Stark and Wayne seeds differ (no key reuse).
        assert_ne!(STARK_SEED, WAYNE_SEED);
    }
}
