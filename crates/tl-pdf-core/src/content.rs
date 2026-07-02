//! PDF content stream operators.
//!
//! Builds the bytes that go between `stream` and `endstream` in a
//! page's content stream object. PDF 1.4 operators used here:
//!
//! - `rg` — non-stroking RGB color (fill)
//! - `re f` — filled rectangle (with `q`/`Q` to keep state local)
//! - `q cm Do Q` — place an image XObject with a translate+scale matrix
//! - `BT … ET` — text block: `Tf` font+size, `Td` cursor, `Tj` show
//!
//! Text escaping per PDF 1.4 §7.3.4.2: literal strings use balanced
//! parens with backslash escaping for `(`, `)`, and `\\`. Non-ASCII
//! bytes are passed through (PDF 1.4 default encoding is WinAnsi; for
//! our use-case the source data is ASCII labels + hex hashes).
//!
//! The mm→pt conversion is `1mm = 2.834_645_7 pt`. Callers pass mm,
//! we convert to pt internally for the xref and content operators.

use std::io::Write as _;

/// 1 millimetre in PDF user units (points). 1 inch = 72 pt = 25.4 mm
/// → 1 mm = 72/25.4 = 2.834_645_7 pt.
pub const MM_TO_PT: f32 = 2.834_645_7;

/// Built-in PDF Type1 fonts we register. We always emit three
/// entries (F1/F2/F3) so the caller can mix Helvetica, Helvetica-Bold,
/// and Courier without re-declaring them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinFont {
    /// Helvetica — registered as `/F1`.
    Helvetica,
    /// Helvetica-Bold — registered as `/F2`.
    HelveticaBold,
    /// Courier — registered as `/F3`.
    Courier,
}

impl BuiltinFont {
    /// Resource name (the `/F1`, `/F2`, `/F3` key) for this font.
    pub fn resource_name(self) -> &'static str {
        match self {
            BuiltinFont::Helvetica => "F1",
            BuiltinFont::HelveticaBold => "F2",
            BuiltinFont::Courier => "F3",
        }
    }
}

/// RGB colour for fill (`rg` op) and stroke (`RG` op). Channels in
/// `0.0..=1.0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgb(pub f32, pub f32, pub f32);

/// Builder for a page's content stream. All methods take `&mut self`
/// and return `&mut Self` for fluent chaining. Finalise with
/// [`ContentOps::into_bytes`].
#[derive(Debug, Default, Clone)]
pub struct ContentOps {
    buf: Vec<u8>,
}

impl ContentOps {
    /// New empty content stream.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// `BT` — begin text block. Must be matched with [`end_text`].
    pub fn begin_text(&mut self) -> &mut Self {
        self.push_str("BT\n");
        self
    }

    /// `/F1 12 Tf` — set the active font and size (in pt).
    pub fn set_font(&mut self, font: BuiltinFont, size_pt: f32) -> &mut Self {
        let _ = writeln!(self.buf, "/{} {} Tf", font.resource_name(), size_pt);
        self
    }

    /// `x y Td` — move the text cursor to `(x, y)` in **pt** (NOT mm).
    /// Most callers should convert with `MM_TO_PT` before calling.
    pub fn text_cursor(&mut self, x_pt: f32, y_pt: f32) -> &mut Self {
        let _ = writeln!(self.buf, "{} {} Td", fmt_f32(x_pt), fmt_f32(y_pt));
        self
    }

    /// `(escaped) Tj` — show a string. Parens and backslash are
    /// escaped per PDF 1.4 §7.3.4.2.
    pub fn show_text(&mut self, text: &str) -> &mut Self {
        self.buf.push(b'(');
        for b in text.bytes() {
            match b {
                b'(' => self.buf.extend_from_slice(b"\\("),
                b')' => self.buf.extend_from_slice(b"\\)"),
                b'\\' => self.buf.extend_from_slice(b"\\\\"),
                _ => self.buf.push(b),
            }
        }
        self.buf.extend_from_slice(b") Tj\n");
        self
    }

    /// `ET` — end text block.
    pub fn end_text(&mut self) -> &mut Self {
        self.push_str("ET\n");
        self
    }

    /// `r g b rg` — non-stroking (fill) RGB color in `0.0..=1.0`.
    pub fn set_fill_rgb(&mut self, c: Rgb) -> &mut Self {
        let _ = writeln!(
            self.buf,
            "{} {} {} rg",
            fmt_f32(c.0),
            fmt_f32(c.1),
            fmt_f32(c.2)
        );
        self
    }

    /// `r g b RG` — stroking (outline) RGB color in `0.0..=1.0`.
    pub fn set_stroke_rgb(&mut self, c: Rgb) -> &mut Self {
        let _ = writeln!(
            self.buf,
            "{} {} {} RG",
            fmt_f32(c.0),
            fmt_f32(c.1),
            fmt_f32(c.2)
        );
        self
    }

    /// `w` — line width in pt (used for hairlines and rules).
    pub fn set_line_width(&mut self, width_pt: f32) -> &mut Self {
        let _ = writeln!(self.buf, "{} w", fmt_f32(width_pt));
        self
    }

    /// Filled rectangle via `q re f Q` (state-pushing variant). The
    /// inputs are in **mm** — we convert to pt internally.
    pub fn rect(&mut self, x_mm: f32, y_mm: f32, w_mm: f32, h_mm: f32) -> &mut Self {
        let x = x_mm * MM_TO_PT;
        let y = y_mm * MM_TO_PT;
        let w = w_mm * MM_TO_PT;
        let h = h_mm * MM_TO_PT;
        self.push_str("q\n");
        let _ = writeln!(
            self.buf,
            "{} {} {} {} re f",
            fmt_f32(x),
            fmt_f32(y),
            fmt_f32(w),
            fmt_f32(h)
        );
        self.push_str("Q\n");
        self
    }

    /// Stroked rectangle (outline only). Inputs in **mm**.
    pub fn rect_stroke(&mut self, x_mm: f32, y_mm: f32, w_mm: f32, h_mm: f32) -> &mut Self {
        let x = x_mm * MM_TO_PT;
        let y = y_mm * MM_TO_PT;
        let w = w_mm * MM_TO_PT;
        let h = h_mm * MM_TO_PT;
        let _ = writeln!(
            self.buf,
            "{} {} {} {} re S",
            fmt_f32(x),
            fmt_f32(y),
            fmt_f32(w),
            fmt_f32(h)
        );
        self
    }

    /// Horizontal line at y from x to x+width (mm). 0.3 pt default
    /// stroke.
    pub fn hline(&mut self, x_mm: f32, y_mm: f32, width_mm: f32) -> &mut Self {
        let x = x_mm * MM_TO_PT;
        let y = y_mm * MM_TO_PT;
        let w = width_mm * MM_TO_PT;
        self.push_str("q\n");
        self.set_line_width(0.3);
        let _ = writeln!(
            self.buf,
            "{} {} m {} {} l S",
            fmt_f32(x),
            fmt_f32(y),
            fmt_f32(x + w),
            fmt_f32(y)
        );
        self.push_str("Q\n");
        self
    }

    /// Place an XObject (image) with a translate+scale. Caller
    /// supplies translation in mm and a scale factor.
    pub fn place_image(
        &mut self,
        xobject_name: &str,
        tx_mm: f32,
        ty_mm: f32,
        sx: f32,
        sy: f32,
    ) -> &mut Self {
        let tx = tx_mm * MM_TO_PT;
        let ty = ty_mm * MM_TO_PT;
        self.push_str("q\n");
        let _ = writeln!(
            self.buf,
            "{} 0 0 {} {} {} cm /{} Do",
            fmt_f32(sx),
            fmt_f32(sy),
            fmt_f32(tx),
            fmt_f32(ty),
            xobject_name
        );
        self.push_str("Q\n");
        self
    }

    /// Borrow the accumulated bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Consume and return the accumulated bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn push_str(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }
}

/// Format a `f32` for inclusion in a content stream. We avoid
/// `format!` because we want a tight, deterministic representation
/// (no scientific notation, no trailing zeros that differ across
/// `rustc` versions). Uses 3 decimal places which is more than
/// enough precision for 595×842 pt A4 (~0.001 pt = 0.0004 mm).
fn fmt_f32(v: f32) -> String {
    // Avoid `-0.000` from `-0.0 * MM_TO_PT` style calculations.
    let v = if v == 0.0 { 0.0 } else { v };
    let mut s = format!("{:.3}", v);
    // Strip trailing zeros + the decimal point if it ends up
    // dangling (so we emit `1` rather than `1.0`).
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stream_is_empty() {
        let b = ContentOps::new().into_bytes();
        assert!(b.is_empty());
    }

    #[test]
    fn fill_rgb_emits_rg_operator() {
        let mut co = ContentOps::new();
        co.set_fill_rgb(Rgb(0.5, 0.5, 0.5));
        let b = co.into_bytes();
        let s = std::str::from_utf8(&b).unwrap();
        assert!(s.contains("rg"), "missing rg op: {s}");
        assert!(s.contains("0.5"), "missing color value: {s}");
    }

    #[test]
    fn text_escapes_parens_and_backslash() {
        let mut co = ContentOps::new();
        co.begin_text();
        co.set_font(BuiltinFont::Helvetica, 12.0);
        co.text_cursor(100.0, 100.0);
        co.show_text("hello (paren) and \\ back");
        co.end_text();
        let bytes = co.into_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("hello \\(paren\\) and \\\\ back"), "got: {s}");
        assert!(s.contains("Tj"), "missing Tj op: {s}");
        assert!(s.contains("BT"));
        assert!(s.contains("ET"));
    }

    #[test]
    fn rect_emits_q_re_f_q_block() {
        let mut co = ContentOps::new();
        co.rect(10.0, 20.0, 50.0, 5.0);
        let bytes = co.into_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.starts_with("q\n"), "should start with q: {s}");
        assert!(s.contains(" re f"), "missing re f: {s}");
        assert!(s.contains("\nQ\n"), "should end with Q: {s}");
    }

    #[test]
    fn place_image_emits_cm_do() {
        let mut co = ContentOps::new();
        co.place_image("Im1", 100.0, 200.0, 1.5, 1.5);
        let bytes = co.into_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(" cm "), "missing cm op: {s}");
        assert!(s.contains("/Im1 Do"), "missing XObject ref: {s}");
    }

    #[test]
    fn mm_to_pt_conversion_is_correct() {
        // 25.4 mm = 72 pt → 1mm = 2.8346457 pt
        let pt = 25.4 * MM_TO_PT;
        assert!((pt - 72.0).abs() < 0.001, "expected 72, got {pt}");
    }

    #[test]
    fn fmt_f32_strips_trailing_zeros() {
        assert_eq!(fmt_f32(1.0), "1");
        assert_eq!(fmt_f32(1.5), "1.5");
        assert_eq!(fmt_f32(1.50), "1.5");
        assert_eq!(fmt_f32(0.0), "0");
    }

    #[test]
    fn font_resource_names_match_writer() {
        // The writer registers fonts as F1/F2/F3; we mirror that here.
        assert_eq!(BuiltinFont::Helvetica.resource_name(), "F1");
        assert_eq!(BuiltinFont::HelveticaBold.resource_name(), "F2");
        assert_eq!(BuiltinFont::Courier.resource_name(), "F3");
    }
}
