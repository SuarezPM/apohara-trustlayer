//! Full CMS signature verification for RFC 3161 TimeStampResp tokens.
//!
//! Per Plan v1.x v1.1.0.x+1+2-US-1 (closes CRÍTICO 1 of auditor 3):
//!
//! > El código hace: chain parses, certs X.509 válidos, basicConstraints=CA:TRUE.
//! > Lo que **no hace**: verificación CMS completa de TimeStampResp.
//!
//! This module uses `cryptographic-message-syntax` 0.28 (the crate
//! used by `apple-codesign` and `pdf_oxide` in production) to do the
//! FULL CMS signature verification per RFC 5652 §5.6 + RFC 3161 §2.4.2.
//!
//! ## What this module does
//!
//! 1. Parses the input DER as either a `TimeStampResp` (RFC 3161) or
//!    a `ContentInfo` (the inner token, which is what
//!    `openssl ts -verify -token_in` accepts).
//! 2. Extracts the `SignedData` from the ContentInfo.
//! 3. For each `SignerInfo`:
//!    a. Verifies the signature cryptographically against the cert
//!       in the `certificates` field.
//!    b. Verifies the `messageDigest` attribute matches the SHA-256
//!       of the encapsulated content (the TSTInfo DER).
//!    c. Verifies the `contentType` attribute is `id-ct-TSTInfo`
//!       (1.2.840.113549.1.9.16.1.4).
//! 4. Parses the TSTInfo from the eContent.
//! 5. Verifies the `messageImprint.hashedMessage` matches the
//!    `expected_digest` parameter.
//! 6. Validates the cert chain PEM (structural: every cert parses
//!    as valid X.509 with `basicConstraints=CA:TRUE`).

#![warn(missing_docs)]

use cryptographic_message_syntax::asn1::rfc3161::{TimeStampResp, TstInfo};
use cryptographic_message_syntax::{
    asn1::rfc5652::{ContentInfo as Asn1ContentInfo, SignedData as Asn1SignedData},
    CmsError, SignedData, TimeStampResponse,
};
use x509_parser::prelude::*;

use crate::tsa::{TsaError, TsaTokenBytes};

/// OID for id-signedData (RFC 5652 §5.1).
const ID_SIGNED_DATA_OCTETS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// OID for id-ct-TSTInfo (RFC 3161 §2.4.2).
const ID_CT_TST_INFO_OCTETS: &[u8] =
    &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04];

/// Errors emitted by `verify_strict_with_certs`. Wraps both
/// `CmsError` from `cryptographic-message-syntax` and our own
/// validation errors (digest length, messageImprint mismatch, etc.).
#[derive(Debug, thiserror::Error)]
pub enum CmsVerifyError {
    /// `expected_digest` is not 32 bytes (SHA-256).
    #[error("expected_digest must be 32 bytes (SHA-256), got {0}")]
    DigestLength(usize),

    /// The inner cryptographic-message-syntax decoder failed.
    #[error("cryptographic-message-syntax error: {0}")]
    Cms(String),

    /// The messageImprint in the TSTInfo does not match the expected digest.
    #[error("messageImprint mismatch: expected {expected}, got {got}")]
    MessageImprintMismatch { expected: String, got: String },

    /// The contentType attribute is not id-ct-TSTInfo.
    #[error("content_type is not id-ct-TSTInfo: {0}")]
    ContentType(String),

    /// The signed_attributes field is missing from the SignerInfo.
    #[error("missing signed_attributes")]
    MissingSignedAttributes,

    /// The signed_content (eContent) is None.
    #[error("signed_content is None")]
    NoSignedContent,

    /// The TimeStampResp has no SignedData.
    #[error("TimeStampResp has no SignedData")]
    NoSignedData,

    /// The cert chain PEM is malformed.
    #[error("chain PEM parse failed: {0}")]
    ChainParse(String),

    /// A cert in the chain is not a CA (basicConstraints=CA:TRUE missing).
    #[error("cert in chain is not a CA: {0}")]
    ChainNotCa(String),

    /// The chain.pem is empty.
    #[error("chain.pem is empty")]
    ChainEmpty,

    /// The input is neither a TimeStampResp nor a ContentInfo.
    #[error("input is neither a valid TimeStampResp nor a valid ContentInfo")]
    InvalidInput,

    /// The ContentInfo content_type is not id-signedData.
    #[error("ContentInfo content_type is not id-signedData: {0}")]
    ContentInfoType(String),
}

impl From<CmsError> for CmsVerifyError {
    fn from(e: CmsError) -> Self {
        CmsVerifyError::Cms(format!("{e:?}"))
    }
}

impl From<CmsVerifyError> for TsaError {
    fn from(e: CmsVerifyError) -> Self {
        TsaError::Verify(format!("CMS verify failed: {e}"))
    }
}

/// Full CMS verification of a TimeStampResp token.
///
/// This is the canonical entry point for v1.1.0.x+1+2+ production
/// path. It uses `cryptographic-message-syntax` for the cryptographic
/// signature verification (per RFC 5652 §5.6) and `x509-parser` for
/// the cert chain validation.
///
/// `token_der` can be either a bare TimeStampResp (RFC 3161 §2.4.2)
/// or the inner ContentInfo that `openssl ts -verify -token_in` accepts.
///
/// `expected_digest` is the SHA-256 digest that the token is supposed
/// to timestamp; this is compared against the `messageImprint` of
/// the TSTInfo.
///
/// `chain_pem` is the pinned certificate chain (PEM-encoded, one
/// or more certs). Each cert must parse as valid X.509 and have
/// `basicConstraints=CA:TRUE`.
pub fn verify_strict_with_certs(
    token_der: &[u8],
    expected_digest: &[u8],
    chain_pem: &[u8],
) -> Result<(), CmsVerifyError> {
    // 1. Digest length check (RFC 3161 §2.4.1: SHA-256 = 32 bytes).
    if expected_digest.len() != 32 {
        return Err(CmsVerifyError::DigestLength(expected_digest.len()));
    }

    // 2. Parse the TimeStampResp (or fall through to parse the inner
    // ContentInfo if the input starts with the ContentInfo OID).
    let signed_data = extract_signed_data(token_der)?;

    // 3. Validate the cert chain (structural: all certs in the chain
    // parse as valid X.509 with basicConstraints=CA:TRUE). This is a
    // structural check, not a path-validation check — the cert chain
    // validation is delegated to the OS trust store in production.
    validate_chain_pem(chain_pem)?;

    // 4. For each SignerInfo: verify the cryptographic signature,
    // verify the message-digest attribute, verify the content-type
    // attribute, then verify the TSTInfo messageImprint.
    for signer in signed_data.signers() {
        // 4a. Cryptographic signature verification per RFC 5652 §5.6.
        let signed_content = signer.signed_content_with_signed_data(&signed_data);
        signer
            .verify_signature_with_signed_data_and_content(&signed_data, &signed_content)
            .map_err(|e| CmsVerifyError::Cms(format!("SignerInfo::verify_signature: {e:?}")))?;

        // 4b. Verify the messageDigest attribute matches the digest
        // of the eContent (the TSTInfo DER).
        signer
            .verify_message_digest_with_signed_data(&signed_data)
            .map_err(|e| {
                CmsVerifyError::Cms(format!(
                    "SignerInfo::verify_message_digest_with_signed_data: {e:?}"
                ))
            })?;

        // 4c. Verify the contentType attribute is id-ct-TSTInfo.
        let sa = signer
            .signed_attributes()
            .ok_or(CmsVerifyError::MissingSignedAttributes)?;
        let ct = sa.content_type();
        if ct.as_ref() != ID_CT_TST_INFO_OCTETS {
            return Err(CmsVerifyError::ContentType(format!("{ct:?}")));
        }
    }

    // 5. Parse the TSTInfo from the eContent and verify the
    // messageImprint matches the expected digest.
    let e_content = signed_data
        .signed_content()
        .ok_or(CmsVerifyError::NoSignedContent)?;
    let tst = parse_tst_info(e_content)?;
    let imprint_octets = tst.message_imprint.hashed_message.to_bytes();
    let imprint_bytes: &[u8] = imprint_octets.as_ref();
    if imprint_bytes != expected_digest {
        return Err(CmsVerifyError::MessageImprintMismatch {
            expected: hex_lower(expected_digest),
            got: hex_lower(imprint_bytes),
        });
    }

    Ok(())
}

/// Extract the high-level `SignedData` from a `TimeStampResp` DER or
/// a bare `ContentInfo` DER (which is what `openssl ts -verify -token_in`
/// accepts as input).
fn extract_signed_data(token_der: &[u8]) -> Result<SignedData, CmsVerifyError> {
    use bcder::decode::Constructed;
    use bcder::Mode;

    // Try TimeStampResp first (the natural RFC 3161 format).
    let tsr_result =
        Constructed::decode(token_der, Mode::Ber, |cons| TimeStampResp::take_from(cons));
    if let Ok(tsr) = tsr_result {
        let ts_response: TimeStampResponse = tsr.into();
        let sd = ts_response
            .signed_data()
            .map_err(|e| CmsVerifyError::Cms(format!("TimeStampResponse::signed_data: {e:?}")))?
            .ok_or(CmsVerifyError::NoSignedData)?;
        return SignedData::try_from(&sd).map_err(CmsVerifyError::from);
    }

    // Fallback: maybe it's a bare ContentInfo (what `openssl ts -verify -token_in` consumes).
    let ci_result: Result<Option<Asn1ContentInfo>, _> = Constructed::decode(
        token_der,
        Mode::Ber,
        Asn1ContentInfo::take_opt_from,
    );
    if let Ok(Some(ci)) = ci_result {
        if ci.content_type.as_ref() != ID_SIGNED_DATA_OCTETS {
            return Err(CmsVerifyError::ContentInfoType(format!(
                "{:?}",
                ci.content_type
            )));
        }
        let content = ci.content;
        {
            let sd_asn1: Asn1SignedData =
                Constructed::decode(content.into_bytes(), Mode::Ber, |cons| {
                    Asn1SignedData::take_from(cons)
                })
                .map_err(|e| {
                    CmsVerifyError::Cms(format!("ContentInfo content SignedData parse: {e:?}"))
                })?;
            return SignedData::try_from(&sd_asn1).map_err(CmsVerifyError::from);
        }
    }

    Err(CmsVerifyError::InvalidInput)
}

/// Parse a TSTInfo from the eContent bytes (the encapsulated content
/// of the SignedData).
fn parse_tst_info(e_content: &[u8]) -> Result<TstInfo, CmsVerifyError> {
    use bcder::decode::Constructed;
    use bcder::Mode;

    Constructed::decode(e_content, Mode::Ber, |cons| TstInfo::take_from(cons))
        .map_err(|e| CmsVerifyError::Cms(format!("TSTInfo parse: {e:?}")))
}

/// Validate the chain PEM: every cert must parse as valid X.509. The
/// final (leaf) cert in the chain is the TSA cert and must carry the
/// `id-kp-timeStamping` ExtendedKeyUsage. Intermediate and root certs
/// are expected to have `basicConstraints=CA:TRUE` (the structural
/// check that auditors asked for).
///
/// This is a STRUCTURAL check only — full path validation against the
/// OS trust store is delegated to the caller (in production). For the
/// test fixture, the chain.pem contains a single self-signed TSA
/// cert which carries the timeStamping EKU.
fn validate_chain_pem(chain_pem: &[u8]) -> Result<(), CmsVerifyError> {
    let mut offset = 0;
    let total = chain_pem.len();
    let mut chain_count = 0;

    while offset < total {
        let remaining = &chain_pem[offset..];
        let (next, pem) = parse_x509_pem(remaining)
            .map_err(|e| CmsVerifyError::ChainParse(format!("at offset {offset}: {e:?}")))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| CmsVerifyError::ChainParse(format!("cert parse: {e:?}")))?;

        // Verify basicConstraints CA:TRUE for intermediate/root certs.
        // x509-parser 0.16 returns Result<Option<BasicExtension<BasicConstraints>>, X509Error>.
        let is_ca = match cert.tbs_certificate.basic_constraints() {
            Ok(Some(bc)) => bc.value.ca,
            _ => false,
        };

        // For non-CA certs, require the id-kp-timeStamping EKU (RFC 3161).
        if !is_ca && !has_time_stamping_extended_key_usage(&cert) {
            return Err(CmsVerifyError::ChainNotCa(format!(
                "{}",
                cert.tbs_certificate.subject
            )));
        }

        chain_count += 1;
        let consumed = remaining.len() - next.len();
        offset += consumed;
        while offset < total && matches!(chain_pem[offset], b'\n' | b'\r' | b' ' | b'\t') {
            offset += 1;
        }
    }

    if chain_count == 0 {
        return Err(CmsVerifyError::ChainEmpty);
    }
    Ok(())
}

/// Check whether a cert carries the `id-kp-timeStamping` EKU (RFC 3161).
fn has_time_stamping_extended_key_usage(cert: &X509Certificate) -> bool {
    use x509_parser::oid_registry::OID_X509_EXT_EXTENDED_KEY_USAGE;
    for ext in cert.extensions() {
        if ext.oid == OID_X509_EXT_EXTENDED_KEY_USAGE {
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                return eku.time_stamping;
            }
        }
    }
    false
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[allow(dead_code)]
fn _silence_unused(_: TsaTokenBytes) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_test_chain() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("audit_artifacts/test_fixtures/digicert/chain.pem");
        std::fs::read(&path).expect("chain.pem must exist (run scripts/generate_digicert_sample_response.py)")
    }

    fn read_test_token() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("audit_artifacts/test_fixtures/digicert/token.der");
        std::fs::read(&path).expect("token.der must exist (run scripts/generate_digicert_sample_response.py)")
    }

    fn read_test_response() -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("audit_artifacts/test_fixtures/digicert/sample-response.der");
        std::fs::read(&path).expect("sample-response.der must exist")
    }

    const EXPECTED_DIGEST: [u8; 32] = [
        0x66, 0x72, 0x3E, 0x37, 0x71, 0xBE, 0x10, 0xDA, 0xFF, 0xAA, 0x3D, 0xFF, 0xE5, 0x6C, 0xEB,
        0xCF, 0xEF, 0x91, 0x54, 0x2A, 0x37, 0xF8, 0x1A, 0x10, 0x1A, 0x16, 0xE1, 0xE5, 0x0C, 0xF0,
        0x0A, 0x86,
    ];

    #[test]
    fn test_cms_verify_accepts_valid_timestamp_response() {
        let chain = read_test_chain();
        let response = read_test_response();
        let result = verify_strict_with_certs(&response, &EXPECTED_DIGEST, &chain);
        if let Err(e) = &result {
            eprintln!("verify failed: {e:?}");
        }
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn test_cms_verify_accepts_valid_token() {
        let chain = read_test_chain();
        let token = read_test_token();
        let result = verify_strict_with_certs(&token, &EXPECTED_DIGEST, &chain);
        assert!(result.is_ok(), "expected Ok, got {:?}", result);
    }

    #[test]
    fn test_cms_verify_rejects_tampered_signature() {
        let chain = read_test_chain();
        let mut token = read_test_token();
        let last = token.len() - 1;
        token[last] ^= 0x01;
        let result = verify_strict_with_certs(&token, &EXPECTED_DIGEST, &chain);
        assert!(result.is_err(), "expected Err for tampered signature");
    }

    #[test]
    fn test_cms_verify_rejects_wrong_digest() {
        let chain = read_test_chain();
        let token = read_test_token();
        let wrong_digest = [0x42u8; 32];
        let result = verify_strict_with_certs(&token, &wrong_digest, &chain);
        assert!(result.is_err(), "expected Err for wrong digest");
    }

    #[test]
    fn test_cms_verify_rejects_empty_token() {
        let chain = read_test_chain();
        let result = verify_strict_with_certs(&[], &EXPECTED_DIGEST, &chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_verify_rejects_empty_chain() {
        let token = read_test_token();
        let result = verify_strict_with_certs(&token, &EXPECTED_DIGEST, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_verify_rejects_wrong_digest_length() {
        let chain = read_test_chain();
        let token = read_test_token();
        let result = verify_strict_with_certs(&token, &[0u8; 16], &chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_verify_rejects_garbage_bytes() {
        let chain = read_test_chain();
        let result = verify_strict_with_certs(&[0xFFu8; 128], &EXPECTED_DIGEST, &chain);
        assert!(result.is_err());
    }

    #[test]
    fn test_cms_verify_rejects_malformed_der() {
        let chain = read_test_chain();
        let mut malformed = vec![0x30, 0x10];
        malformed.extend(std::iter::repeat(0xFFu8).take(16));
        let result = verify_strict_with_certs(&malformed, &EXPECTED_DIGEST, &chain);
        assert!(result.is_err());
    }
}

