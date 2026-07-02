//! # tl-pdf-core
//!
//! Minimal PDF 1.4 emitter. Replaces `printpdf 0.9.1` to eliminate
//! 9 transitive RUSTSECs (`lopdf`, `ttf-parser`, `bincode`, `fxhash`,
//! `kuchiki`, `allsorts`, `azul-layout`, `ouroboros`, `proc-macro-error`).
//!
//! ## Modules
//!
//! - [`content`] — PDF content-stream operators (`rg`, `re f`,
//!   `BT…ET`, `q cm Do Q`, text escape).
//! - [`writer`] — document assembly (header, catalog, pages,
//!   fonts, image XObjects, content streams, xref, trailer).
//! - [`sigdict`] — stub for the future PDF signature dictionary.
//!
//! ## Public API at a glance
//!
//! ```ignore
//! use tl_pdf_core::{PdfDocumentBuilder, PageBuilder, ImageBuilder,
//!                  ContentOps, BuiltinFont, Rgb};
//!
//! let mut page = PdfDocumentBuilder::new("title").add_page();
//! page.content_ops()
//!     .begin_text()
//!     .set_font(BuiltinFont::Helvetica, 12.0)
//!     .text_cursor(0.0, 0.0)
//!     .show_text("hello")
//!     .end_text();
//! let bytes = PdfDocumentBuilder::new("title")
//!     .with_page(page)
//!     .into_bytes()?;
//! ```
//!
//! Coordinates are in **mm** at the public API; the writer
//! converts to pt internally (`1mm = 2.834_645_7 pt`).
//!
//! Images are embedded **uncompressed** as grayscale (`/DeviceGray`,
//! `/BitsPerComponent 8`) so we don't pull in `flate2`. The QR
//! sizes we use (≤48mm @ 300 dpi → ≤566 px) make the file-size
//! delta negligible.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod content;
pub mod sigdict;
pub mod writer;

pub use content::{BuiltinFont, ContentOps, Rgb, MM_TO_PT};
pub use sigdict::SignatureDict;
pub use writer::{
    ImageBuilder, Mm, PageBuilder, PdfDocumentBuilder, PdfWriterError, Pt,
};
