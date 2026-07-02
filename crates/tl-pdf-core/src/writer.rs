//! PDF document assembly (header, xref, trailer, %%EOF).
//!
//! Layout produced (PDF 1.4):
//!
//! ```text
//! %PDF-1.4
//! %<binary marker>
//! 1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
//! 2 0 obj << /Type /Pages /Count N /Kids [3 0 R ...] >> endobj
//! 3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842]
//!             /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >>
//!                          /XObject << /Im1 7 0 R ... >> >>
//!             /Contents 8 0 R >> endobj
//! 4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica
//!             /Encoding /WinAnsiEncoding >> endobj
//! 5 0 obj ...Helvetica-Bold...
//! 6 0 obj ...Courier...
//! 7 0 obj << /Type /XObject /Subtype /Image /Width W /Height H
//!             /ColorSpace /DeviceGray /BitsPerComponent 8 /Length L >>
//!             stream
//!             <raw pixels>
//!             endstream
//!             endobj
//! 8 0 obj << /Length L >>
//!         stream
//!         <content ops>
//!         endstream
//!         endobj
//! ...
//! xref
//! 0 N
//! 0000000000 65535 f
//! 0000000015 00000 n
//! ...
//! trailer << /Size M /Root 1 0 R >>
//! startxref
//! {offset}
//! %%EOF
//! ```
//!
//! Xref offsets are **byte-exact** — the writer tracks cumulative
//! bytes via a single `Vec<u8>` and records each object's start
//! offset as it goes. After all objects are emitted, the xref table
//! is appended at the known offset.

use std::io::Write as _;

use thiserror::Error;

use crate::content::{ContentOps, MM_TO_PT};

/// A4 portrait dimensions in PDF user units (pt).
/// Width  = 210 mm × 2.8346457 ≈ 595.276 pt (rounded to 595)
/// Height = 297 mm × 2.8346457 ≈ 841.890 pt (rounded to 842)
const A4_WIDTH_PT: u32 = 595;
const A4_HEIGHT_PT: u32 = 842;

/// Errors produced by the writer. Only includes structural problems
/// (no IO happens — the output is a `Vec<u8>`).
#[derive(Debug, Error)]
pub enum PdfWriterError {
    /// Tried to finalise a document with no pages.
    #[error("document has no pages")]
    NoPages,
}

/// Millimetre wrapper. The internal representation is `f32` pt
/// (we don't actually carry mm around — the conversion is
/// performed at the content-stream level). This newtype exists for
/// API symmetry with printpdf; the f32 field is in mm and the
/// helper does the conversion when the doc is built.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mm(pub f32);

/// Point wrapper. The internal representation is in pt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pt(pub f32);

/// Grayscale 8-bit image. Used for QR code bitmap XObjects.
#[derive(Debug, Clone)]
pub struct ImageBuilder {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
}

impl ImageBuilder {
    /// Build a grayscale image from raw 8-bit pixels (0 = black,
    /// 255 = white). `width * height` must equal `pixels.len()`.
    /// The data is embedded **uncompressed** in the PDF — for the
    /// QR sizes we use (≤48mm @ 300dpi → ≤566 px) the file size
    /// delta vs. FlateDecode is negligible, and we save ourselves
    /// the `flate2` dependency.
    pub fn from_grayscale(pixels: Vec<u8>, width: u32, height: u32) -> Self {
        debug_assert_eq!(pixels.len() as u64, (width as u64) * (height as u64));
        Self {
            pixels,
            width,
            height,
        }
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }
    /// Height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }
    /// Borrow the raw pixel bytes.
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

/// PDF page being assembled. Holds the content ops and the page
/// index for the parent. Consumed by `PdfDocumentBuilder::add_page`.
#[derive(Debug, Default)]
pub struct PageBuilder {
    content: ContentOps,
    width_pt: u32,
    height_pt: u32,
}

impl PageBuilder {
    /// New A4-portrait page.
    pub fn new() -> Self {
        Self {
            content: ContentOps::new(),
            width_pt: A4_WIDTH_PT,
            height_pt: A4_HEIGHT_PT,
        }
    }

    /// Set the page size (pt).
    pub fn with_size(mut self, width_pt: u32, height_pt: u32) -> Self {
        self.width_pt = width_pt;
        self.height_pt = height_pt;
        self
    }

    /// Access the content stream builder (for `set_fill_rgb`, `rect`,
    /// `begin_text`, etc.).
    pub fn content_ops(&mut self) -> &mut ContentOps {
        &mut self.content
    }

    /// Consume the page and return the content bytes.
    pub(crate) fn into_content(self) -> (ContentOps, u32, u32) {
        (self.content, self.width_pt, self.height_pt)
    }
}

/// A PDF document. The `add_image` method must be called BEFORE
/// the image is referenced from a page (the page emits a `/Im1 Do`
/// op and the XObject must exist as object 7).
#[derive(Debug, Default)]
pub struct PdfDocumentBuilder {
    title: String,
    pages: Vec<PageBuilder>,
    images: Vec<ImageBuilder>,
    image_names: Vec<String>,
    /// Width of subsequent pages, default A4.
    page_width_pt: u32,
    /// Height of subsequent pages, default A4.
    page_height_pt: u32,
}

impl PdfDocumentBuilder {
    /// New empty document with the given `/Title` (cosmetic — not
    /// emitted in our minimal writer).
    pub fn new(title: &str) -> Self {
        Self {
            title: title.to_string(),
            ..Self::default()
        }
    }

    /// Set the page size used for subsequent `add_page` calls.
    pub fn with_page_size(mut self, width_pt: u32, height_pt: u32) -> Self {
        self.page_width_pt = width_pt;
        self.page_height_pt = height_pt;
        self
    }

    /// Start a new page. The returned builder can be filled with
    /// content ops and then attached to the document.
    pub fn add_page(&self) -> PageBuilder {
        PageBuilder {
            content: ContentOps::new(),
            width_pt: if self.page_width_pt == 0 {
                A4_WIDTH_PT
            } else {
                self.page_width_pt
            },
            height_pt: if self.page_height_pt == 0 {
                A4_HEIGHT_PT
            } else {
                self.page_height_pt
            },
        }
    }

    /// Register an image XObject. Returns `(self, name)` where
    /// `name` is the resource name to use in a `ContentOps::place_image`
    /// call (e.g. `/Im1`).
    pub fn add_image(mut self, img: ImageBuilder) -> (Self, String) {
        let idx = self.images.len();
        let name = format!("Im{}", idx + 1);
        self.images.push(img);
        self.image_names.push(name.clone());
        (self, name)
    }

    /// Attach a page to the document. Consumes the page.
    pub fn with_page(mut self, page: PageBuilder) -> Self {
        self.pages.push(page);
        self
    }

    /// Number of pages currently in the document.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Number of images currently in the document.
    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Render the document to a `Vec<u8>` (PDF 1.4).
    pub fn into_bytes(self) -> Result<Vec<u8>, PdfWriterError> {
        if self.pages.is_empty() {
            return Err(PdfWriterError::NoPages);
        }
        let mut out: Vec<u8> = Vec::with_capacity(4096);

        // ── Header ──────────────────────────────────────────────
        // %PDF-1.4 on the first line. We skip the optional
        // binary-marker comment (PDF 1.4 §7.5.2) — using only
        // ASCII bytes here keeps the output text-safe for tools
        // that parse the PDF as UTF-8 (a common pattern in
        // higher-level acceptance tests that substring-search the
        // receipt content).
        out.extend_from_slice(b"%PDF-1.4\n");

        // ── Object 1: Catalog ───────────────────────────────────
        let catalog_offset = out.len() as u32;
        write_obj_header(&mut out, 1, "<< /Type /Catalog /Pages 2 0 R >>");

        // ── Object 2: Pages (top-level) ─────────────────────────
        // Object IDs for the body are reserved up-front so the
        // /Kids array can reference the right page-object IDs.
        // Layout:
        //   1            Catalog
        //   2            Pages (top-level)
        //   3            Font Helvetica        (F1)
        //   4            Font Helvetica-Bold   (F2)
        //   5            Font Courier          (F3)
        //   6 .. 6+I-1   Image XObjects        (one per image)
        //   P0 .. P0+N-1 Page objects          (P0 = 6 + I)
        //   C0 .. C0+N-1 Content-stream objects (C0 = P0 + N)
        let n_pages = self.pages.len();
        let n_images = self.images.len();
        let page_id_start: u32 = 6 + n_images as u32;
        let content_id_start: u32 = page_id_start + n_pages as u32;
        let total_objects = content_id_start + n_pages as u32;

        let mut kids = String::with_capacity(n_pages * 8);
        for i in 0..n_pages {
            if i > 0 {
                kids.push(' ');
            }
            kids.push_str(&format!("{} 0 R", page_id_start + i as u32));
        }
        let pages_offset = out.len() as u32;
        write_obj_header(
            &mut out,
            2,
            &format!("<< /Type /Pages /Count {} /Kids [{}] >>", n_pages, kids),
        );

        // ── Fonts (3=Helvetica, 4=Helvetica-Bold, 5=Courier) ────
        let font_helvetica_offset = out.len() as u32;
        write_obj_header(
            &mut out,
            3,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
        );
        let font_bold_offset = out.len() as u32;
        write_obj_header(
            &mut out,
            4,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
        );
        let font_courier_offset = out.len() as u32;
        write_obj_header(
            &mut out,
            5,
            "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
        );

        // ── Image XObjects (starting at 6, one per image) ───────
        let mut image_offsets: Vec<u32> = Vec::with_capacity(n_images);
        for (i, img) in self.images.iter().enumerate() {
            let id = 6 + i as u32;
            let offset = out.len() as u32;
            image_offsets.push(offset);
            // Stream header. No /Filter — uncompressed grayscale.
            // The /Length is the number of bytes in the pixel
            // array (not the entire stream).
            let header = format!(
                "<< /Type /XObject /Subtype /Image /Width {} /Height {} \
                 /ColorSpace /DeviceGray /BitsPerComponent 8 /Length {} >>\nstream\n",
                img.width(),
                img.height(),
                img.pixels().len()
            );
            write_stream_obj(&mut out, id, &header, img.pixels());
        }

        // ── Page objects (then content stream objects) ──────────
        let mut page_offsets: Vec<u32> = Vec::with_capacity(n_pages);
        let mut content_offsets: Vec<u32> = Vec::with_capacity(n_pages);
        for (i, page) in self.pages.into_iter().enumerate() {
            let (content, width_pt, height_pt) = page.into_content();
            let page_id = page_id_start + i as u32;
            let content_id = content_id_start + i as u32;

            let page_offset = out.len() as u32;
            page_offsets.push(page_offset);
            let resources = build_resources_dict(&self.image_names);
            let page_dict = format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] \
                 /Resources {} /Contents {} 0 R >>",
                width_pt, height_pt, resources, content_id
            );
            write_obj_header(&mut out, page_id, &page_dict);

            // Content stream object.
            let content_offset = out.len() as u32;
            content_offsets.push(content_offset);
            let content_bytes = content.into_bytes();
            let content_header = format!(
                "<< /Length {} >>\nstream\n",
                content_bytes.len()
            );
            write_stream_obj(&mut out, content_id, &content_header, &content_bytes);
        }

        // ── xref ────────────────────────────────────────────────
        let xref_offset = out.len() as u32;
        let _ = writeln!(out, "xref");
        let _ = writeln!(out, "0 {}", total_objects);
        // Object 0 (free).
        let _ = writeln!(out, "0000000000 65535 f ");
        // Objects 1..total_objects. Each entry is exactly 20 bytes:
        // 10-digit offset, ' ', 5-digit generation, ' ', 'n', ' ', CR, LF.
        for obj_id in 1..total_objects {
            let offset = match obj_id {
                1 => catalog_offset,
                2 => pages_offset,
                3 => font_helvetica_offset,
                4 => font_bold_offset,
                5 => font_courier_offset,
                id if (6..6 + n_images as u32).contains(&id) => {
                    image_offsets[(id - 6) as usize]
                }
                id if (page_id_start..page_id_start + n_pages as u32).contains(&id) => {
                    page_offsets[(id - page_id_start) as usize]
                }
                _ => {
                    // content-stream object
                    let local = obj_id - content_id_start;
                    content_offsets[local as usize]
                }
            };
            out.extend_from_slice(format!("{:010} {:05} n \n", offset, 0).as_bytes());
        }

        // ── trailer ─────────────────────────────────────────────
        let _ = writeln!(out, "trailer");
        let _ = writeln!(
            out,
            "<< /Size {} /Root 1 0 R >>",
            total_objects
        );
        let _ = writeln!(out, "startxref");
        let _ = writeln!(out, "{}", xref_offset);
        out.extend_from_slice(b"%%EOF\n");

        // Suppress unused warning for the title field — we keep
        // it on the struct so the API matches printpdf.
        let _ = self.title;
        let _ = MM_TO_PT; // re-exported at crate root
        Ok(out)
    }
}

/// Write a complete object header: `N 0 obj\n<dict>\nendobj\n`.
fn write_obj_header(out: &mut Vec<u8>, id: u32, dict: &str) {
    let _ = writeln!(out, "{} 0 obj", id);
    out.extend_from_slice(dict.as_bytes());
    // Ensure the dict line ends with a newline before endobj.
    if !dict.ends_with('\n') {
        out.push(b'\n');
    }
    out.extend_from_slice(b"endobj\n");
}

/// Write a complete stream object:
/// `N 0 obj\n<dict-with-`stream`-keyword>\n<data>\nendstream\nendobj\n`.
///
/// The caller passes a `dict_prefix` that already contains the
/// `<< ... /Length L >>\nstream\n` trailer (we add nothing more
/// between the dict and the data). After the data the writer
/// emits a newline + `endstream` + newline + `endobj` + newline.
fn write_stream_obj(out: &mut Vec<u8>, id: u32, dict_prefix: &str, data: &[u8]) {
    let _ = writeln!(out, "{} 0 obj", id);
    out.extend_from_slice(dict_prefix.as_bytes());
    out.extend_from_slice(data);
    out.push(b'\n');
    out.extend_from_slice(b"endstream\nendobj\n");
}

/// Build the `/Resources` dict for a page. Always emits the three
/// font entries (F1=3, F2=4, F3=5); image XObjects are listed by
/// name with the object-id derived from the image index
/// (Im1 → 6, Im2 → 7, ...).
fn build_resources_dict(image_names: &[String]) -> String {
    let mut s = String::with_capacity(128);
    s.push_str("<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >>");
    if !image_names.is_empty() {
        s.push_str(" /XObject <<");
        for n in image_names {
            let idx: usize = n
                .strip_prefix("Im")
                .and_then(|t| t.parse::<usize>().ok())
                .unwrap_or(0);
            let id = 5 + idx as u32;
            s.push_str(&format!(" /{} {} 0 R", n, id));
        }
        s.push_str(" >>");
    }
    s.push_str(" >>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::{BuiltinFont, Rgb};

    #[test]
    fn empty_doc_errors() {
        let doc = PdfDocumentBuilder::new("empty");
        let r = doc.into_bytes();
        assert!(matches!(r, Err(PdfWriterError::NoPages)));
    }

    #[test]
    fn minimal_doc_starts_with_magic_and_ends_with_eof() {
        let mut page = PdfDocumentBuilder::new("t").add_page();
        page.content_ops()
            .set_fill_rgb(Rgb(0.0, 0.0, 0.0))
            .rect(0.0, 0.0, 50.0, 5.0);
        let bytes = PdfDocumentBuilder::new("t")
            .with_page(page)
            .into_bytes()
            .expect("ok");
        assert!(bytes.starts_with(b"%PDF-1.4\n"), "magic bytes");
        assert!(bytes.windows(5).any(|w| w == b"%%EOF"), "EOF marker");
        // No printpdf-style content (sanity: ensure we use rg/re
        // and not Tj-style hex).
        let s = std::str::from_utf8(&bytes).unwrap_or("");
        assert!(s.contains(" rg\n"), "missing fill color: {s}");
        assert!(s.contains(" re f\n"), "missing filled rect: {s}");
    }

    #[test]
    fn multi_page_doc_has_correct_kids_array() {
        let mut doc = PdfDocumentBuilder::new("multi");
        for _ in 0..3 {
            let p = doc.add_page();
            let mut p = p;
            p.content_ops().rect(0.0, 0.0, 1.0, 1.0);
            doc = doc.with_page(p);
        }
        let bytes = doc.into_bytes().expect("ok");
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("/Count 3"), "missing page count: {s}");
        // With 3 pages and 0 images: page_id_start = 6, so Kids
        // references 6, 7, 8.
        assert!(s.contains("/Kids [6 0 R 7 0 R 8 0 R]"), "missing kids: {s}");
    }

    #[test]
    fn image_xobject_emits_stream_and_endstream() {
        // 4x4 grayscale checkerboard.
        let mut px = Vec::with_capacity(16);
        for y in 0..4 {
            for x in 0..4 {
                px.push(if (x + y) % 2 == 0 { 0 } else { 255 });
            }
        }
        let img = ImageBuilder::from_grayscale(px, 4, 4);
        let (doc, name) = PdfDocumentBuilder::new("img").add_image(img);
        assert_eq!(name, "Im1");

        let mut page = doc.add_page();
        page.content_ops()
            .place_image("Im1", 0.0, 0.0, 1.0, 1.0);
        let bytes = doc.with_page(page).into_bytes().expect("ok");
        // The output contains a binary pixel array after the
        // first `stream` marker, so a full UTF-8 parse fails.
        // We assert byte-by-byte: locate the XObject dict, then
        // verify the stream markers around the pixel data.
        // Slice to just the first object (Catalog + Pages + 3
        // font dicts + the XObject header) — before the binary
        // stream payload.
        let ascii_end = bytes
            .windows(7)
            .position(|w| w == b"stream\n")
            .expect("first stream marker");
        let s_text = std::str::from_utf8(&bytes[..ascii_end + 7])
            .expect("ascii prefix is utf-8");
        assert!(s_text.contains("/Type /XObject"), "missing XObject dict");
        assert!(s_text.contains("/Subtype /Image"), "missing Image subtype");
        assert!(s_text.contains("/Width 4"), "missing width");
        assert!(s_text.contains("/Height 4"), "missing height");
        assert!(s_text.contains("stream\n"), "missing stream marker");
        // The endstream marker is after the binary data.
        assert!(
            bytes.windows(10).any(|w| w == b"endstream\n"),
            "missing endstream"
        );
    }

    #[test]
    fn xref_table_is_byte_exact() {
        // The xref table MUST start at the offset declared in
        // startxref. We parse our own output to verify.
        let mut page = PdfDocumentBuilder::new("xref").add_page();
        page.content_ops()
            .begin_text()
            .set_font(BuiltinFont::Helvetica, 10.0)
            .text_cursor(0.0, 0.0)
            .show_text("hi")
            .end_text();
        let bytes = PdfDocumentBuilder::new("xref")
            .with_page(page)
            .into_bytes()
            .expect("ok");
        let s = std::str::from_utf8(&bytes).unwrap();

        // Locate "startxref\nNNN\n%%EOF"
        let start = s.find("startxref\n").expect("startxref marker");
        let after = start + "startxref\n".len();
        let end = s[after..].find('\n').expect("end of offset");
        let offset: usize = s[after..after + end]
            .trim()
            .parse()
            .expect("offset integer");
        // The byte at that offset must be 'x' (the start of "xref").
        assert_eq!(bytes[offset] as char, 'x', "xref not at declared offset");
    }

    #[test]
    fn every_object_offset_points_at_known_marker() {
        // For each xref entry that says "n" (in-use), the offset
        // must point at "N 0 obj". This catches the classic
        // off-by-N bug in hand-rolled PDF writers.
        let mut page = PdfDocumentBuilder::new("validate").add_page();
        page.content_ops().rect(0.0, 0.0, 1.0, 1.0);
        let bytes = PdfDocumentBuilder::new("validate")
            .with_page(page)
            .into_bytes()
            .expect("ok");
        let s = std::str::from_utf8(&bytes).unwrap();

        // Find xref section.
        let xref_pos = s.find("\nxref\n").expect("xref section");
        let xref_section = &s[ref_xref_pos(&bytes, xref_pos) + 1..];
        // Parse: "0 N\n" then N lines of 20 bytes each.
        let mut lines = xref_section.lines();
        let _ = lines.next(); // "xref"
        let header = lines.next().expect("xref header");
        let (start, count) = {
            let mut it = header.split_whitespace();
            let s = it.next().unwrap().parse::<u32>().unwrap();
            let c = it.next().unwrap().parse::<u32>().unwrap();
            (s, c)
        };
        assert_eq!(start, 0);
        let entries: Vec<&str> = lines.take(count as usize).collect();
        assert_eq!(entries.len(), count as usize);
        for (i, entry) in entries.iter().enumerate() {
            // 20 bytes per entry, but as a line it may be just
            // the visible 20 chars. Parse offset.
            let parts: Vec<&str> = entry.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }
            let offset: usize = parts[0].parse().expect("offset");
            let kind = parts[2];
            if i == 0 {
                assert_eq!(kind, "f", "object 0 must be free");
                continue;
            }
            assert_eq!(kind, "n", "object {i} must be in-use");
            // Sanity: the byte at offset must be the start of the
            // object header "N 0 obj".
            let target = std::str::from_utf8(&bytes[offset..offset + 8])
                .unwrap_or("?");
            assert!(
                target.starts_with(&format!("{i} 0 obj")),
                "object {i} offset {offset} points at {target:?}, not `{i} 0 obj`"
            );
        }
    }

    // Helper to find the *start* of the xref section line (we
    // already know the position of "xref\n" — we just want the
    // line preceding it for "\nxref\n" matching).
    fn ref_xref_pos(_bytes: &[u8], pos: usize) -> usize {
        pos
    }
}
