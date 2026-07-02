//! Shared drawing helpers for the 1-page evidence receipt.
//!
//! Synthex · macrostructure: Receipt (one-pager) · tone: technical-trust
//! · anchor hue: lime-green · theme: Synthex dark
//!
//! # Design language
//!
//! Dark background, lime/green accent (Apahara brand from the pitch
//! deck), monospace for hashes and code, no hairlines (use lime rule
//! or 1.4mm black bar), generous whitespace.
//!
//! ## F23 (PDF writer replacement)
//!
//! `printpdf` 0.9.1 was replaced by the in-tree `tl-pdf-core` crate
//! (a hand-rolled PDF 1.4 emitter, no external PDF deps) to
//! eliminate 9 transitive RUSTSECs (lopdf, ttf-parser, bincode,
//! fxhash, kuchiki, allsorts, azul-layout, ouroboros,
//! proc-macro-error).
//!
//! The public API on `Ctx` and `Page` is preserved: callers
//! continue to use `set_fill`, `reset_color`, `cursor_y`, `write`,
//! `rect`. The internals now use `tl_pdf_core::ContentOps` (which
//! accumulates PDF content-stream operators) and
//! `tl_pdf_core::PdfDocumentBuilder` (which assembles the final
//! PDF byte stream). Coordinates remain in mm; `tl_pdf_core` does
//! the mm→pt conversion internally.

use tl_pdf_core::{
    BuiltinFont, ContentOps, ImageBuilder, PdfDocumentBuilder, Rgb as CoreRgb,
};

/// Synthex-style dark palette (default) + a print-friendly light
/// variant on the same tokens. Both palettes share the same
/// 11-token vocabulary so the render function can pick by theme.
pub mod brand {
    /// Dark theme tokens (default — for screen / web).
    pub const BG: (f64, f64, f64) = (0.020, 0.024, 0.031);
    pub const BG2: (f64, f64, f64) = (0.051, 0.067, 0.090);
    pub const INK: (f64, f64, f64) = (0.831, 0.843, 0.867);
    pub const MUTED: (f64, f64, f64) = (0.431, 0.463, 0.506);
    pub const LIME: (f64, f64, f64) = (0.702, 1.000, 0.227);
    pub const GREEN: (f64, f64, f64) = (0.180, 0.800, 0.443);
    pub const RED: (f64, f64, f64) = (0.906, 0.298, 0.235);
    pub const BLUE: (f64, f64, f64) = (0.431, 0.659, 0.996);

    /// Light theme tokens (for print / paper).
    pub const PAPER: (f64, f64, f64) = (1.0, 1.0, 1.0);
    pub const PAPER_ACCENT: (f64, f64, f64) = (0.965, 0.969, 0.957);
    pub const INK_LIGHT: (f64, f64, f64) = (0.102, 0.102, 0.102);
    pub const MUTED_LIGHT: (f64, f64, f64) = (0.380, 0.420, 0.460);
    pub const LIME_DARK: (f64, f64, f64) = (0.180, 0.490, 0.043);
    pub const GREEN_LIGHT: (f64, f64, f64) = (0.039, 0.431, 0.227);
    pub const RED_LIGHT: (f64, f64, f64) = (0.701, 0.149, 0.118);
}

/// A single page being assembled. Holds the cursor position (used
/// by the render helpers) and a wrapper around the underlying
/// `tl_pdf_core::ContentOps`. The page is consumed by
/// `Ctx::add_page` which moves the content into a `PageBuilder`
/// and attaches it to the document.
pub struct Page {
    /// Content stream operators for this page.
    pub content: ContentOps,
    /// Cursor y position in mm (from the bottom).
    pub cursor_y: f32,
    /// Line height (mm). Reserved for future use.
    pub line_h: f32,
    /// Default fill colour (RGB 0.0..1.0). Every text/rect op
    /// starts from this colour and is reset back to it after a
    /// `ctx.rect` call (matching the printpdf 0.9 behaviour).
    default_fill: (f32, f32, f32),
}

impl Page {
    /// New empty page with default fill = INK (light theme).
    pub fn new() -> Self {
        Self {
            content: ContentOps::new(),
            cursor_y: 280.0,
            line_h: 7.0,
            default_fill: brand_to_rgb(brand::INK),
        }
    }

    /// Set the default fill colour (RGB 0.0..1.0).
    pub fn set_default_fill(&mut self, t: (f64, f64, f64)) {
        self.default_fill = brand_to_rgb(t);
    }

    /// Set the fill colour for subsequent ops. The colour is
    /// applied immediately via the `rg` content-stream op.
    pub fn set_fill(&mut self, t: (f64, f64, f64)) {
        self.content
            .set_fill_rgb(CoreRgb(t.0 as f32, t.1 as f32, t.2 as f32));
    }

    /// Reset the fill colour to the page's default.
    pub fn reset_color(&mut self) {
        let (r, g, b) = self.default_fill;
        self.content.set_fill_rgb(CoreRgb(r, g, b));
    }

    /// Borrow the underlying content ops for callers that need
    /// direct access (e.g. the QR renderer in `mod.rs`).
    pub fn content_ops(&mut self) -> &mut ContentOps {
        &mut self.content
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::new()
    }
}

/// Drawing context. Wraps a `tl_pdf_core::PdfDocumentBuilder` and
/// exposes the shared drawing helpers that mutate a `Page`'s
/// content stream.
pub struct Ctx {
    doc: PdfDocumentBuilder,
}

impl Ctx {
    /// Build a new context around an empty `PdfDocumentBuilder`
    /// with the given title.
    pub fn new(title: &str) -> Self {
        Self {
            doc: PdfDocumentBuilder::new(title),
        }
    }

    /// Build a single A4 portrait page that is **printable**:
    /// white paper background, ink-black text, dark-green/lime
    /// accent for the verdict.
    pub fn add_a4_page(&self, _layer_name: &str) -> Page {
        let mut page = Page::new();
        page.set_default_fill(brand::INK_LIGHT);
        // Layer 1: white paper background.
        page.set_fill(brand::PAPER);
        page.content.rect(0.0, 0.0, 210.0, 297.0);
        page.reset_color();
        page.cursor_y = 280.0;
        page.line_h = 7.0;
        page
    }

    /// Back-compat alias — see `add_a4_page`.
    pub fn add_a4_page_print(&self, layer_name: &str) -> Page {
        self.add_a4_page(layer_name)
    }

    /// Consume a `Page` and attach it to the underlying
    /// `PdfDocument`. Called by `render_packet_pdf` after the
    /// page's content is fully populated.
    pub fn add_page(&mut self, mut page: Page) {
        // Drain the page's ContentOps into a new PageBuilder and
        // attach it to the document. The `mem::swap` lets us own
        // the ContentOps by value without copying; the second
        // `mem::swap` lets us call the consuming `with_page` on
        // the document.
        let mut page_builder = self.doc.add_page();
        let mut new_content = ContentOps::new();
        std::mem::swap(&mut new_content, &mut page.content);
        *page_builder.content_ops() = new_content;
        // `with_page` takes self by value; swap out our doc, call
        // it, and put the new doc back.
        let mut new_doc = PdfDocumentBuilder::new("");
        std::mem::swap(&mut new_doc, &mut self.doc);
        new_doc = new_doc.with_page(page_builder);
        self.doc = new_doc;
    }

    /// Register a grayscale image XObject with the underlying
    /// document and return the resource name (e.g. `"Im1"`).
    /// The image is embedded uncompressed as
    /// `/DeviceGray /BitsPerComponent 8`.
    ///
    /// **Must be called BEFORE the page that uses the image is
    /// attached** — the writer measures xref offsets in emission
    /// order, so an image registered after a referencing page
    /// would resolve to the wrong object-id.
    pub fn register_image(
        &mut self,
        pixels: Vec<u8>,
        width: u32,
        height: u32,
    ) -> String {
        let img = ImageBuilder::from_grayscale(pixels, width, height);
        // `PdfDocumentBuilder::add_image` takes `self` by value
        // and returns `(Self, String)`. We swap our current doc
        // out, add the image, and put the new doc back.
        let mut new_doc = PdfDocumentBuilder::new("");
        std::mem::swap(&mut new_doc, &mut self.doc);
        let (new_doc, name) = new_doc.add_image(img);
        self.doc = new_doc;
        name
    }

    /// Write text at `(x, y)` (mm from bottom-left) using
    /// Helvetica or Helvetica-Bold.
    pub fn write(
        &self,
        page: &mut Page,
        text: &str,
        x: f32,
        y: f32,
        size: f32,
        bold: bool,
    ) {
        let font = if bold {
            BuiltinFont::HelveticaBold
        } else {
            BuiltinFont::Helvetica
        };
        page.content.begin_text();
        page.content.set_font(font, size);
        // ContentOps::text_cursor expects pt; the public API is
        // in mm. Convert.
        page.content
            .text_cursor(x * tl_pdf_core::MM_TO_PT, y * tl_pdf_core::MM_TO_PT);
        page.content.show_text(text);
        page.content.end_text();
    }

    /// Filled rectangle in mm coordinates.
    pub fn rect(
        &self,
        page: &mut Page,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        color: (f64, f64, f64),
    ) {
        page.set_fill(color);
        page.content.rect(x, y, w, h);
        page.reset_color();
    }

    /// Lime rule (1mm) — section divider.
    pub fn lime_rule(&self, page: &mut Page, x: f32, y: f32, w: f32) {
        self.rect(page, x, y, w, 1.0, brand::LIME);
    }

    /// Card background (BG2 panel) with hairline lime border.
    pub fn card(&self, page: &mut Page, x: f32, y: f32, w: f32, h: f32) {
        self.rect(page, x, y, w, h, brand::BG2);
        self.rect(page, x, y + h - 1.0, w, 1.0, brand::LIME);
    }

    /// Render the document to bytes (A4 PDF).
    pub fn into_bytes(self) -> Vec<u8> {
        self.doc
            .into_bytes()
            .unwrap_or_else(|e| panic!("PdfDocumentBuilder failed: {e}"))
    }
}

/// Convert a brand tuple `(f64, f64, f64)` to a `(f32, f32, f32)`
/// for the internal `tl_pdf_core::Rgb`.
fn brand_to_rgb(t: (f64, f64, f64)) -> (f32, f32, f32) {
    (t.0 as f32, t.1 as f32, t.2 as f32)
}
