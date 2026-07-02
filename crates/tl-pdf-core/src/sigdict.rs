//! Signature dictionary stub.
//!
//! PDF digital signatures live in an `/AcroForm` dictionary and a
//! `/Sig` field on the page or catalog. The minimum required for a
//! valid signature reference is `/ByteRange` (the four offsets of
//! the signed bytes) and `/Contents` (a hex string holding the
//! signature, padded to a fixed size).
//!
//! This module is a placeholder so future signature work has an
//! entry point. It is **not currently emitted** by
//! `PdfDocumentBuilder::into_bytes` — the minimal writer
//! intentionally omits `/AcroForm` to keep the byte stream as
//! small as possible. Adding a real signature dictionary here
//! will be a follow-up patch.

/// Stub signature dictionary (not yet emitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureDict {
    /// The four offsets `[a, b, c, d]` of the signed/unsigned byte
    /// ranges per PDF 1.7 §12.8.1.
    pub byte_range: [u32; 4],
    /// The signature payload as a hex string (PKCS#7 / CAdES).
    pub contents_hex: String,
}

impl SignatureDict {
    /// New empty signature dict. `byte_range = [0, 0, 0, 0]` and
    /// `contents_hex = String::new()`.
    pub fn new() -> Self {
        Self {
            byte_range: [0, 0, 0, 0],
            contents_hex: String::new(),
        }
    }
}

impl Default for SignatureDict {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_dict_is_zeroed() {
        let d = SignatureDict::default();
        assert_eq!(d.byte_range, [0, 0, 0, 0]);
        assert!(d.contents_hex.is_empty());
    }
}
