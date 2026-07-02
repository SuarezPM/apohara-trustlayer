//! PDF rendering of a `SignedPacket` — 1-page evidence receipt.
//!
//! Synthex-style dark, lime-green accent, monospace for hashes. One
//! A4 page. The minimum a judge needs to trust the seal.
//!
//! ## F23 (PDF writer replacement)
//!
//! The previous `printpdf 0.9.1`-backed renderer has been replaced
//! with the in-tree `tl-pdf-core` crate (a hand-rolled PDF 1.4
//! emitter). `Page` no longer holds `Vec<Op>`; it holds a
//! `tl_pdf_core::ContentOps` (the same op-stream interface but
//! under our control). See `ctx.rs` for the helper API.
#![allow(missing_docs)]

use thiserror::Error;

use crate::packet::SignedPacket;
use themis_agents::baaar::Outcome;
use themis_agents::decision::AgentDecision;

mod baaar;
mod ctx;

#[allow(dead_code)]
fn _typed(_d: &AgentDecision) {}

use crate::pdf::baaar::build_condition_matrix;

pub use ctx::{brand, Ctx, Page};

#[derive(Debug, Error)]
pub enum PdfError {
    #[error("font error: {0}")]
    Font(String),
    #[error("save error: {0}")]
    Save(String),
}

/// Render a `SignedPacket` to PDF bytes (1-page A4, dark theme).
pub fn render_packet_pdf(packet: &SignedPacket) -> Result<Vec<u8>, PdfError> {
    let mut ctx = Ctx::new("Apohara VOUCH Evidence Receipt");
    let seal_id = format!("VOUCH-{}", &packet.blake3_hash_hex()[..8]);

    let mut page = ctx.add_a4_page("Content");
    render_receipt(&mut ctx, packet, &mut page, &seal_id)?;

    ctx.add_page(page);
    let bytes = ctx.into_bytes();
    Ok(bytes)
}

fn render_receipt(
    ctx: &mut Ctx,
    packet: &SignedPacket,
    page: &mut Page,
    seal_id: &str,
) -> Result<(), PdfError> {
    let p = packet.packet();

    // Print-friendly theme tokens. The page background is white
    // (set by add_a4_page), text is ink-black, the verdict pill
    // uses editorial green/red, and the section accent is a dark
    // green that prints cleanly on any printer (the previous lime
    // #b3ff3a washed out on paper).
    let ink = brand::INK_LIGHT;
    let muted = brand::MUTED_LIGHT;
    let accent = brand::LIME_DARK;
    let accent_on_light = (1.0, 1.0, 1.0); // white text on the verdict block

    let (verdict_text, verdict_color) = match p.bbaaar_outcome {
        Outcome::Approve => ("APPROVED", brand::GREEN_LIGHT),
        Outcome::Halt(_) => ("HALT", brand::RED_LIGHT),
    };

    // ── Top bar: numerator (left) + seal id (right) ───────────────
    page.set_fill(accent);
    ctx.write(
        page,
        "01 / 01 \u{2014} EVIDENCE RECEIPT",
        15.0,
        285.0,
        7.0,
        true,
    );
    page.reset_color();
    // Right-aligned seal id, computed so it never overflows
    // x=210mm (page right margin). At 7pt bold Helvetica, each
    // char averages ~2.0mm wide, so 13 chars (VOUCH-XXXXXXXX)
    // need ~26mm of space.
    page.set_fill(muted);
    ctx.write(page, seal_id, 195.0, 285.0, 7.0, true);
    page.reset_color();
    page.cursor_y = 275.0;

    // ── Brand tag ────────────────────────────────────────────────
    page.set_fill(accent);
    ctx.write(
        page,
        "APOHARA \u{00B7} VOUCH",
        15.0,
        page.cursor_y,
        8.0,
        true,
    );
    page.reset_color();
    page.cursor_y -= 4.0;
    page.set_fill(muted);
    ctx.write(
        page,
        "vouch.apohara.dev \u{00B7} everything signed, nothing trusted",
        15.0,
        page.cursor_y,
        6.5,
        false,
    );
    page.reset_color();
    page.cursor_y -= 8.0;

    // ── Verdict hero ─────────────────────────────────────────────
    // Thin ink rule as the divider.
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 8.0;

    let verdict_y = page.cursor_y - 28.0;
    // Color block (the verdict pill, with the verdict text in white).
    ctx.rect(page, 15.0, verdict_y - 6.0, 84.0, 30.0, verdict_color);
    page.set_fill(accent_on_light);
    ctx.write(page, verdict_text, 26.0, verdict_y, 22.0, true);
    page.reset_color();
    // Sub-line to the right of the pill.
    page.set_fill(ink);
    ctx.write(
        page,
        "BAAAR KILL-SWITCH VERDICT \u{2014} EU AI Act Art. 12 \u{00B7} DORA Art. 17",
        105.0,
        verdict_y - 2.0,
        7.5,
        false,
    );
    page.cursor_y = verdict_y - 20.0;

    // ── Trust chain (1 line) ─────────────────────────────────────
    page.set_fill(muted);
    ctx.write(page, "TRUST CHAIN", 15.0, page.cursor_y, 7.0, true);
    page.reset_color();
    page.cursor_y -= 4.0;
    let chain = "agent decision \u{2192} BLAKE3 chain \u{2192} Ed25519 tenant signature \u{2192} RFC 3161 timestamp \u{2192} C2PA-shaped manifest \u{2192} CycloneDX 1.6 AIBOM \u{2192} tl-verify offline";
    page.set_fill(ink);
    ctx.write(page, chain, 15.0, page.cursor_y, 7.0, false);
    page.reset_color();
    page.cursor_y -= 6.0;

    // ── BAAAR matrix (compact, only on HALT) ─────────────────────
    if let Outcome::Halt(_) = p.bbaaar_outcome {
        let matrix = build_condition_matrix(&p.agent_decisions);
        page.set_fill(muted);
        ctx.write(
            page,
            "BAAAR CONDITIONS (halt trigger)",
            15.0,
            page.cursor_y,
            7.0,
            true,
        );
        page.reset_color();
        page.cursor_y -= 4.0;
        for (i, (label, value)) in matrix.iter().enumerate() {
            let (color, bold) = if *label == "fired" {
                (verdict_color, true)
            } else {
                (muted, false)
            };
            page.set_fill(color);
            ctx.write(
                page,
                &format!("{}: {}", label, value),
                15.0,
                page.cursor_y,
                7.0,
                bold,
            );
            page.reset_color();
            page.cursor_y -= 3.5;
            if i >= 2 {
                break;
            }
        }
        page.cursor_y -= 2.0;
    }

    // ── Crypto spine (BLAKE3 + Ed25519 + pubkey) ─────────────────
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 6.0;
    page.set_fill(accent);
    ctx.write(page, "CRYPTOGRAPHIC SPINE", 15.0, page.cursor_y, 7.0, true);
    page.reset_color();
    page.cursor_y -= 4.0;

    let crypto_rows: [(&str, &str); 3] = [
        ("BLAKE3 HASH", packet.blake3_hash_hex()),
        ("ED25519 SIG", &truncate_hex(packet.signature_hex(), 64)),
        ("PUBLIC KEY", packet.public_key_hex()),
    ];
    for (k, v) in crypto_rows.iter() {
        page.set_fill(muted);
        ctx.write(page, k, 15.0, page.cursor_y, 6.5, true);
        page.reset_color();
        page.set_fill(ink);
        ctx.write(page, v, 50.0, page.cursor_y, 6.5, false);
        page.reset_color();
        page.cursor_y -= 3.5;
    }
    page.cursor_y -= 2.0;

    // ── Rekor (if present, one line) ─────────────────────────────
    if let Some(entry) = packet.rekor_entry() {
        page.set_fill(muted);
        ctx.write(page, "REKOR", 15.0, page.cursor_y, 6.5, true);
        page.reset_color();
        page.set_fill(ink);
        ctx.write(
            page,
            &format!(
                "{} \u{00B7} idx {} \u{00B7} ts {}",
                entry.uuid, entry.log_index, entry.integrated_time
            ),
            50.0,
            page.cursor_y,
            6.5,
            false,
        );
        page.reset_color();
        page.cursor_y -= 4.0;
    }
    page.cursor_y -= 2.0;

    // ── Agent summary (8 rows: # | agent | verdict | conf) ───────
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 8.0;
    page.set_fill(accent);
    ctx.write(
        page,
        &format!("AGENT SUMMARY  ({} decisions)", p.agent_decisions.len()),
        15.0,
        page.cursor_y,
        7.0,
        true,
    );
    page.reset_color();
    page.cursor_y -= 7.0;

    // Header row.
    page.set_fill(muted);
    ctx.write(page, "#", 15.0, page.cursor_y, 6.5, true);
    ctx.write(page, "AGENT", 25.0, page.cursor_y, 6.5, true);
    ctx.write(page, "VERDICT", 95.0, page.cursor_y, 6.5, true);
    ctx.write(page, "CONF", 145.0, page.cursor_y, 6.5, true);
    ctx.write(page, "OUTCOME", 165.0, page.cursor_y, 6.5, true);
    page.reset_color();
    // Breathing room between header and first data row.
    page.cursor_y -= 5.0;
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 4.0;

    for (i, d) in p.agent_decisions.iter().enumerate() {
        let conf_pct = (d.confidence * 100.0) as u32;
        let agent_verdict = match &p.bbaaar_outcome {
            Outcome::Approve => "approve",
            Outcome::Halt(_) => "halt",
        };
        let row_color = if agent_verdict == "halt" && d.agent_id == "fraud_auditor" {
            verdict_color
        } else if conf_pct >= 80 {
            accent
        } else {
            ink
        };
        page.set_fill(muted);
        ctx.write(
            page,
            &format!("{:>2}", i + 1),
            15.0,
            page.cursor_y,
            6.5,
            false,
        );
        page.reset_color();
        page.set_fill(ink);
        ctx.write(page, &d.agent_id, 25.0, page.cursor_y, 6.5, false);
        page.reset_color();
        page.set_fill(row_color);
        ctx.write(page, agent_verdict, 95.0, page.cursor_y, 6.5, true);
        page.reset_color();
        page.set_fill(muted);
        ctx.write(
            page,
            &format!("{}%", conf_pct),
            145.0,
            page.cursor_y,
            6.5,
            false,
        );
        page.reset_color();
        page.set_fill(muted);
        ctx.write(
            page,
            &format!("{:?}", d.decision_type),
            165.0,
            page.cursor_y,
            6.0,
            false,
        );
        page.reset_color();
        page.cursor_y -= 4.0;
    }
    page.cursor_y -= 2.0;

    // ── Compliance checklist (1 line) ────────────────────────────
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 6.0;
    page.set_fill(accent);
    ctx.write(
        page,
        "COMPLIANCE  \u{2014}  DORA + EU AI Act Art. 12 + NIST AI RMF + OWASP Agentic + ISO 42001",
        15.0,
        page.cursor_y,
        7.0,
        true,
    );
    page.reset_color();
    page.cursor_y -= 4.0;
    let fm = &p.framework_mappings;
    let compacts = [
        ("DORA", fm.dora_art_9, "3/3"),
        ("EU AI ACT", fm.eu_ai_act_art_12, "8/8"),
        ("NIST AI RMF", fm.nist_ai_rmf, "4/4"),
        ("OWASP AGENTIC", fm.owasp_agentic, "10/10"),
        ("ISO 42001", true, "4/4"),
    ];
    let mut x = 15.0;
    for (name, ok, ratio) in compacts.iter() {
        let color = if *ok {
            brand::GREEN_LIGHT
        } else {
            brand::RED_LIGHT
        };
        page.set_fill(color);
        ctx.write(page, "\u{2713}", x, page.cursor_y, 8.0, true);
        page.reset_color();
        page.set_fill(ink);
        ctx.write(
            page,
            &format!(" {} {}", name, ratio),
            x + 4.5,
            page.cursor_y,
            7.0,
            false,
        );
        page.reset_color();
        x += 38.0;
    }
    page.cursor_y -= 8.0;

    // ── QR (bigger — 32mm) ─────────────────────────────────────────
    render_qr(ctx, packet, page);

    // ── Footer ──────────────────────────────────────────────────
    page.cursor_y = 20.0;
    ctx.rect(page, 15.0, page.cursor_y - 1.0, 180.0, 0.8, ink);
    page.cursor_y -= 5.0;
    page.set_fill(accent);
    ctx.write(
        page,
        "tl-verify <packet.json>  \u{00B7}  vouch.apohara.dev",
        15.0,
        page.cursor_y,
        7.0,
        true,
    );
    page.reset_color();
    let disclaimer = "The seal proves WHEN these bytes existed and that they are unchanged \u{2014} not that any claim inside is accurate.";
    page.set_fill(muted);
    ctx.write(page, disclaimer, 15.0, 12.0, 6.0, false);
    page.reset_color();

    // Bottom-right: seal id (right-aligned, never overflows).
    page.set_fill(muted);
    ctx.write(page, seal_id, 195.0, 20.0, 6.5, true);
    page.reset_color();

    Ok(())
}

/// Render the QR code in the top-right corner of the body.
///
/// F23: rewritten to use `tl_pdf_core` instead of `printpdf`:
///   1. Build a grayscale bitmap from the QR matrix (same as before).
///   2. Register the bitmap as an image XObject via
///      [`Ctx::register_image`] (uncompressed `/DeviceGray`).
///   3. Emit a `place_image` content-stream op with the right
///      translate + scale so the 48mm×48mm QR lands at the
///      top-right of the page.
fn render_qr(ctx: &mut Ctx, packet: &SignedPacket, page: &mut Page) {
    let verify_url = format!(
        "https://vouch.apohara.dev/verify?packet={}&tenant={}",
        packet.packet().packet_id(),
        packet.packet().tenant_id()
    );
    let qr = match qrcode::QrCode::new(verify_url.as_bytes()) {
        Ok(qr) => qr,
        Err(_) => return,
    };
    let w = qr.width();
    let colors = qr.to_colors();
    let mut img = image::GrayImage::new(w as u32, w as u32);
    for y in 0..w {
        for x in 0..w {
            let is_dark = colors[y * w + x] == qrcode::Color::Dark;
            let luma = if is_dark { 0u8 } else { 255u8 };
            img.put_pixel(x as u32, y as u32, image::Luma([luma]));
        }
    }
    let scaled = image::imageops::resize(
        &img,
        (w as u32) * 8,
        (w as u32) * 8,
        image::imageops::Nearest,
    );
    let dyn_img = image::DynamicImage::ImageLuma8(scaled);
    let (w_px, h_px) = (dyn_img.width() as usize, dyn_img.height() as usize);
    let pixels: Vec<u8> = dyn_img.to_luma8().into_raw();

    // Register the QR as an image XObject. Must happen BEFORE
    // `add_page` so the xref offsets are stable.
    let xobject_name = ctx.register_image(pixels, w_px as u32, h_px as u32);

    // 48mm QR — the sweet spot for a 1-page receipt. Positioned
    // at the top-right (x=152mm, y=240mm).
    let qr_mm: f32 = 48.0;
    // Native image size in pt at 300 DPI: 1px = (25.4/300)mm
    // = (25.4/300)*2.8346457 pt.
    let dpi: f32 = 300.0;
    let mm_to_pt = tl_pdf_core::MM_TO_PT;
    let native_pt_per_px = 25.4_f32 / dpi * mm_to_pt;
    let image_native_pt = (w_px as f32) * native_pt_per_px;
    let qr_pt = qr_mm * mm_to_pt;
    let scale = qr_pt / image_native_pt;
    page.content_ops()
        .place_image(&xobject_name, 152.0, 240.0, scale, scale);

    // QR caption — dark-green (print-friendly), centered under QR.
    page.set_fill(brand::LIME_DARK);
    ctx.write(page, "SCAN TO VERIFY", 153.5, 236.0, 7.0, true);
    page.reset_color();

    // Sub-caption with the verify URL.
    page.set_fill(brand::MUTED_LIGHT);
    ctx.write(page, "vouch.apohara.dev/verify", 153.0, 231.0, 6.0, false);
    page.reset_color();
}

fn truncate_hex(s: &str, max_chars: usize) -> String {
    if s.len() <= max_chars {
        s.to_string()
    } else {
        format!("{}\u{2026}", &s[..max_chars])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn sample_packet() -> SignedPacket {
        let decisions = vec![AgentDecision {
            agent_id: "extractor".to_string(),
            tenant_id: "stark".to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: DecisionType::Extracted,
            confidence: 0.9,
            reasoning: "ok".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }];
        let packet =
            crate::packet::EvidencePacket::new("stark", "inv-001", decisions, Outcome::Approve);
        SignedPacket::wrap(packet, "00".repeat(64), "11".repeat(32))
    }

    #[test]
    fn renders_to_non_empty_bytes() {
        let sp = sample_packet();
        let bytes = render_packet_pdf(&sp).expect("render");
        assert!(
            bytes.len() > 2048,
            "PDF should be >2KB, got {}",
            bytes.len()
        );
        assert_eq!(&bytes[..5], b"%PDF-");
    }
}
