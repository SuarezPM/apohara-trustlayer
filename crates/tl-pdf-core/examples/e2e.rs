//! `e2e` — generate a sample PDF and write it to `/tmp/test.pdf` for
//! round-tripping with `lopdf::Document::load`. Run with:
//!
//! ```sh
//! cargo run -p tl-pdf-core --example e2e -- /tmp/test.pdf
//! ```

use std::env;
use std::fs;
use std::process::ExitCode;

use tl_pdf_core::{
    BuiltinFont, ContentOps, ImageBuilder, PdfDocumentBuilder, Rgb,
};

fn main() -> ExitCode {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/test.pdf".to_string());

    // ── Page 1: text + filled rects + a small 4×4 grayscale image ──
    let mut page1 = PdfDocumentBuilder::new("e2e").add_page();
    page1
        .content_ops()
        .begin_text()
        .set_font(BuiltinFont::Helvetica, 12.0)
        .text_cursor(10.0, 280.0)
        .show_text("hello world (test) and \\ back")
        .end_text()
        .set_fill_rgb(Rgb(0.0, 0.0, 0.0))
        .rect(10.0, 10.0, 180.0, 5.0);

    // 4×4 grayscale checkerboard.
    let mut px = Vec::with_capacity(16);
    for y in 0..4 {
        for x in 0..4 {
            px.push(if (x + y) % 2 == 0 { 0 } else { 255 });
        }
    }
    let img = ImageBuilder::from_grayscale(px, 4, 4);
    let (doc_after_img, _name) = PdfDocumentBuilder::new("e2e").add_image(img);
    let mut page2 = doc_after_img.add_page();
    page2
        .content_ops()
        .place_image("Im1", 10.0, 10.0, 4.0, 4.0);

    let bytes = PdfDocumentBuilder::new("e2e")
        .with_page(page1)
        .with_page(page2)
        .into_bytes()
        .expect("render");
    fs::write(&path, &bytes).expect("write");
    println!("wrote {} bytes to {path}", bytes.len());
    ExitCode::SUCCESS
}
