//! Shared drawing helpers for the 1-page evidence receipt.
//!
//! Hallmark · macrostructure: Receipt (one-pager) · tone: technical-trust
//! · anchor hue: lime-green · theme: Synthex dark
//!
#![allow(missing_docs)]
//! Design language: dark background, lime/green accent (Apahara brand
//! from the pitch deck), monospace for hashes and code, no hairlines
//! (use lime rule or 1.4mm black bar), generous whitespace.
//!
//! ## printpdf 0.9.1 migration notes
//!
//! In printpdf 0.9 the API is Op-based. `Page` now owns a `Vec<Op>`
//! that the `Ctx` helpers append to. The `Ctx` itself owns the
//! `PdfDocument` (it must be `&mut` to add images / finalize pages).
//! `BuiltinFont` is referenced inline as a `PdfFontHandle::Builtin(...)`
//! and is *not* registered on the document.

use printpdf::{
    text::TextItem, BuiltinFont, Color, LinePoint, Mm, Op, PaintMode, PdfDocument, PdfFontHandle,
    PdfPage, Point, Polygon, PolygonRing, Pt, Rgb, WindingOrder,
};

/// Synthex-style dark palette (default) + a print-friendly light
/// variant on the same tokens. Both palettes share the same
/// 11-token vocabulary so the render function can pick by theme.
pub mod brand {
    use super::Rgb;

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

    /// Build a printpdf `Rgb` from a token triple.
    pub fn rgb(t: (f64, f64, f64)) -> Rgb {
        Rgb::new(t.0 as f32, t.1 as f32, t.2 as f32, None)
    }
}

/// A single page being assembled. Holds the cursor position (used
/// by the render helpers) and the accumulated `Op` stream. The
/// `Page` is consumed by `Ctx::add_page` which moves the ops into
/// a `PdfPage` and attaches it to the document.
pub struct Page {
    /// PDF op stream for this page.
    pub ops: Vec<Op>,
    /// Cursor y position in mm (from the bottom). The render
    /// helpers update this as they emit text.
    pub cursor_y: f32,
    /// Line height (mm). Reserved for future use; not consumed
    /// in the printpdf 0.9.1 Op-based text model.
    pub line_h: f32,
}

impl Page {
    /// Set the fill color for subsequent ops.
    pub fn set_fill(&mut self, t: (f64, f64, f64)) {
        self.ops
            .push(Op::SetFillColor { col: Color::Rgb(brand::rgb(t)) });
    }

    /// Reset the fill color to the default INK (light theme).
    pub fn reset_color(&mut self) {
        self.set_fill(brand::INK);
    }
}

/// Drawing context. Owns the mutable `PdfDocument` (which the
/// render functions push images into) and exposes the shared
/// drawing helpers that append to a `Page`'s op stream.
pub struct Ctx {
    /// The PDF document being built. Mutable so we can register
    /// images via `add_image` before the page ops reference them.
    pub doc: PdfDocument,
}

impl Ctx {
    /// Build a new context around an empty `PdfDocument` with the
    /// given title.
    pub fn new(title: &str) -> Self {
        Self {
            doc: PdfDocument::new(title),
        }
    }

    /// Build a single A4 portrait page that is **printable**:
    /// white paper background (so it prints on any printer), ink-
    /// black text, dark-green/lime accent for the verdict.
    pub fn add_a4_page(&self, _layer_name: &str) -> Page {
        let mut ops = Vec::new();

        // Layer 1: white paper background.
        ops.push(Op::SetFillColor {
            col: Color::Rgb(brand::rgb(brand::PAPER)),
        });
        ops.push(Op::DrawPolygon {
            polygon: Polygon {
                rings: vec![PolygonRing {
                    points: (0..4)
                        .map(|i| {
                            let (x, y) = match i {
                                0 => (0.0_f32, 0.0_f32),
                                1 => (210.0_f32, 0.0_f32),
                                2 => (210.0_f32, 297.0_f32),
                                _ => (0.0_f32, 297.0_f32),
                            };
                            LinePoint {
                                p: Point::new(Mm(x), Mm(y)),
                                bezier: false,
                            }
                        })
                        .collect(),
                }],
                mode: PaintMode::Fill,
                winding_order: WindingOrder::NonZero,
            },
        });

        // Reset to ink color for content.
        ops.push(Op::SetFillColor {
            col: Color::Rgb(brand::rgb(brand::INK_LIGHT)),
        });

        Page {
            ops,
            cursor_y: 280.0,
            line_h: 7.0,
        }
    }

    /// Build a single A4 portrait page for print. The 0.7 helper
    /// existed alongside `add_a4_page`; the two are now identical
    /// (single light theme), but we keep the symbol for API
    /// compatibility with the 0.7 callers.
    pub fn add_a4_page_print(&self, layer_name: &str) -> Page {
        self.add_a4_page(layer_name)
    }

    /// Consume a `Page` and attach it to the underlying
    /// `PdfDocument`. Called by the render top-level function
    /// (`render_packet_pdf` / `render_bundle_pdf`) after the
    /// `Page`'s op stream is fully populated.
    pub fn add_page(&mut self, page: Page) {
        let pdf_page = PdfPage::new(Mm(210.0), Mm(297.0), page.ops);
        self.doc.with_pages(vec![pdf_page]);
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
        page.ops.push(Op::StartTextSection);
        page.ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(y)),
        });
        page.ops.push(Op::SetFont {
            font: PdfFontHandle::Builtin(font),
            size: Pt(size),
        });
        page.ops.push(Op::SetLineHeight { lh: Pt(size) });
        page.ops.push(Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        });
        page.ops.push(Op::EndTextSection);
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
        page.ops.push(Op::DrawPolygon {
            polygon: Polygon {
                rings: vec![PolygonRing {
                    points: vec![
                        LinePoint {
                            p: Point::new(Mm(x), Mm(y)),
                            bezier: false,
                        },
                        LinePoint {
                            p: Point::new(Mm(x + w), Mm(y)),
                            bezier: false,
                        },
                        LinePoint {
                            p: Point::new(Mm(x + w), Mm(y + h)),
                            bezier: false,
                        },
                        LinePoint {
                            p: Point::new(Mm(x), Mm(y + h)),
                            bezier: false,
                        },
                    ],
                }],
                mode: PaintMode::Fill,
                winding_order: WindingOrder::NonZero,
            },
        });
        page.reset_color();
    }

    /// Lime rule (1mm) — section divider.
    pub fn lime_rule(&self, page: &mut Page, x: f32, y: f32, w: f32) {
        self.rect(page, x, y, w, 1.0, brand::LIME);
    }

    /// Card background (BG2 panel) with hairline lime border.
    pub fn card(&self, page: &mut Page, x: f32, y: f32, w: f32, h: f32) {
        self.rect(page, x, y, w, h, brand::BG2);
        // Top lime accent stripe (1mm).
        self.rect(page, x, y + h - 1.0, w, 1.0, brand::LIME);
    }

    /// Render the document to bytes (A4 PDF, no font subsetting,
    /// optimize on). Consumes the Ctx.
    pub fn into_bytes(self) -> Vec<u8> {
        self.doc.save(&Default::default(), &mut Vec::new())
    }
}
