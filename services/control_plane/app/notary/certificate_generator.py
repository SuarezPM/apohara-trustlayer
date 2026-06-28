"""CertificateArtifactGenerator — PDF + QR generation for NotaryService.

Single-responsibility module: builds the court-grade PDF certificate
with embedded QR code, 5 sections (Content, Cryptographic Details,
Public Anchors, EU AI Act Art. 50(3) Watermark), and reportlab
graceful degradation (minimal hand-crafted PDF if reportlab is missing).

The helpers (_watermark_stamp_drawing, _kv_table, _write_minimal_pdf)
are now thin wrappers around `app.pdf_helpers` (single source of truth).
"""
from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class CertificateArtifactGenerator:
    """Generate the PDF certificate + verification QR.

    Production wire-up (W8.5.1 — reportlab 5.x). The 8th auditor
    recommended `normordis-pdf` 2.5.1 (pure Rust, PDF/A-1b); that
    crate has no Python wrapper. We use reportlab (the production
    Python PDF library) here and document the deviation. The Rust
    side (`crates/tl-evidence/src/bundle_pdf.rs`) uses printpdf
    0.7 — same Rust-PDF family — for the canonical evidence
    bundle PDF.

    Degraded mode: if reportlab is not importable, the function
    writes a minimal valid PDF with only the cert_id (so the file
    exists) and returns the path. The NotaryService logs the
    degraded state in metadata_json so verifiers know.
    """

    def __init__(self, output_dir: str = "artifacts/notary"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, cert: dict) -> str:
        """Generate the PDF for a certificate. Returns the file path."""
        cert_id = cert.get("cert_id", "unknown")
        pdf_path = self.output_dir / f"{cert_id}.pdf"
        qr_payload = cert.get(
            "qr_payload", f"https://apohara.org/verify/{cert_id}"
        )

        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
            )
            from reportlab.graphics.barcode.qr import QrCodeWidget
            from reportlab.graphics.shapes import Drawing
        except ImportError as imp_err:
            logger.error(
                f"reportlab import failed ({imp_err}); writing degraded PDF."
            )
            self._write_minimal_pdf(pdf_path, cert_id)
            return str(pdf_path)

        # Build the document.
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            title=f"TrustLayer Certificate {cert_id}",
            author="Apohara TrustLayer Notary",
        )
        styles = getSampleStyleSheet()
        h1 = styles["Heading1"]
        h2 = styles["Heading2"]
        body = styles["BodyText"]
        small = ParagraphStyle(
            "small",
            parent=body,
            fontSize=8,
            leading=10,
            textColor=colors.grey,
        )

        story = []

        # Header
        story.append(Paragraph("TrustLayer Notary Certificate", h1))
        story.append(
            Paragraph(
                f"<b>Certificate ID:</b> <font face='Courier'>{cert_id}</font>",
                body,
            )
        )
        story.append(Spacer(1, 0.15 * inch))

        # Section 1: Content
        story.append(Paragraph("1. Content", h2))
        content_rows = [
            ["Content Hash", cert.get("content_hash", "—")],
            ["Content Type", str(cert.get("content_type", "—"))],
            ["AI System", cert.get("ai_system_id", "—")],
            ["Submitted By", cert.get("submitted_by", "—")],
            ["Submitted At", str(cert.get("submitted_at", "—"))],
            ["Notarized At", str(cert.get("notarized_at", "—"))],
        ]
        story.append(self._kv_table(content_rows))
        story.append(Spacer(1, 0.15 * inch))

        # Section 2: Cryptographic details
        story.append(Paragraph("2. Cryptographic Details", h2))
        crypto_rows = [
            [
                "Issuer Key Fingerprint",
                cert.get("primary_key_fingerprint", "—"),
            ],
            [
                "COSE_Sign1 (truncated)",
                (cert.get("cose_sign1_b64", "") or "")[:80]
                + ("…" if len(cert.get("cose_sign1_b64", "") or "") > 80 else ""),
            ],
        ]
        story.append(self._kv_table(crypto_rows))
        story.append(Spacer(1, 0.15 * inch))

        # Section 3: Anchors (TSA + SCITT)
        story.append(Paragraph("3. Public Anchors", h2))
        anchor_rows = [
            [
                "TSA URL",
                cert.get("tsa_url") or "— (degraded mode)",
            ],
            [
                "TSA Token (present?)",
                "yes" if cert.get("tsa_token_b64") else "no (degraded mode)",
            ],
            [
                "SCITT Entry ID",
                cert.get("rekor_entry_id") or "— (degraded mode)",
            ],
            [
                "SCITT Log ID",
                cert.get("rekor_log_id") or "—",
            ],
        ]
        story.append(self._kv_table(anchor_rows))
        story.append(Spacer(1, 0.2 * inch))

        # Section 4: QR code (kept together with the verify URL)
        story.append(Paragraph("4. Verification", h2))
        try:
            qr_widget = QrCodeWidget(qr_payload, barLevel="M", barHeight=1.5 * inch)
            qr_drawing = Drawing()
            qr_drawing.add(qr_widget)
            qr_drawing.width = 2.0 * inch
            qr_drawing.height = 2.0 * inch
            story.append(qr_drawing)
        except Exception as qr_err:  # noqa: BLE001 — QR widget (reportlab); skipping QR is non-fatal for cert PDF
            logger.warning(f"QR widget failed: {qr_err}; skipping")
        story.append(
            Paragraph(
                f"Scan the QR code or visit <b>{qr_payload}</b> to verify this "
                "certificate online.",
                body,
            )
        )
        story.append(Spacer(1, 0.25 * inch))

        # Section 5: EU AI Act Art. 50(3) Watermark Status (Kirchenbauer z-test)
        # Visible stamp overlay + machine-readable k/v row. LLM serving
        # stacks pre-detect via /v1/disclosure/generate (with token_ids)
        # and the z-score is stored in `cert["watermark_result"]`.
        story.append(
            Paragraph("5. EU AI Act Art. 50(3) Watermark Status", h2)
        )
        story.append(self._watermark_stamp_drawing(cert))
        wm = cert.get("watermark_result") or {}
        if wm:
            wm_rows = [
                ["Kirchenbauer z-score", f"{wm.get('z_score', 0.0):.2f}"],
                ["Green tokens / total", f"{wm.get('green_count', 0)}/{wm.get('total_count', 0)}"],
                ["Threshold (one-sided)", str(wm.get("z_threshold", 4.0))],
                [
                    "Status",
                    (
                        "WATERMARK DETECTED (Compliant Art. 50(3))"
                        if wm.get("detected")
                        else "Watermark absent (z below threshold)"
                    ),
                ],
            ]
            story.append(self._kv_table(wm_rows))
        else:
            story.append(
                Paragraph(
                    "Not in scope for this disclosure (no token_ids supplied). "
                    "EU AI Act Art. 50(3) requires machine-readable watermarks on "
                    "<i>AI-generated text content</i>; hashes and binary content "
                    "are out of scope per the Code of Practice on Transparency.",
                    small,
                )
            )
        story.append(Spacer(1, 0.2 * inch))

        # Footer / disclaimers
        story.append(
            Paragraph(
                "TrustLayer Notary v3.0+W8+W9 — court-grade AI compliance "
                "evidence per EU AI Act Art. 50 + DORA + PLD 2024/2853.",
                small,
            )
        )
        story.append(
            Paragraph(
                "PDF/A-1b conformance deferred (Rust normordis-pdf binding "
                "is W8.5.2; current PDF is reportlab, suitable for printing "
                "and human inspection).",
                small,
            )
        )

        try:
            doc.build(story)
        except Exception as build_err:  # noqa: BLE001 — reportlab doc.build; falls back to minimal PDF
            logger.error(f"reportlab build failed: {build_err}; writing minimal PDF.")
            self._write_minimal_pdf(pdf_path, cert_id)

        return str(pdf_path)

    @staticmethod
    def _watermark_stamp_drawing(cert: dict):
        """Build a centered colored Paragraph with the Art. 50(3) watermark stamp.

        Thin wrapper around `app.pdf_helpers.watermark_stamp`: builds the
        label from `cert["watermark_result"]` (populated by
        `kirchenbauer_detect`) and delegates rendering to the shared helper.

        Green = Compliant, Red = watermark absent, Grey = not in scope.
        """
        from app.pdf_helpers import watermark_stamp

        wm = cert.get("watermark_result") or {}
        z = wm.get("z_score")
        detected = wm.get("detected")
        threshold = wm.get("z_threshold", 4.0)
        if detected is True:
            label = (
                f"<b>EU AI Act Art. 50(3) WATERMARK VERIFIED</b><br/>"
                f"<font size='10'>Kirchenbauer z={z:.2f} (above {threshold} "
                f"threshold, p &lt; 0.00003)</font>"
            )
            return watermark_stamp(label, bg_hex="#e8f5e9", text_color_hex="#1b5e20")
        if detected is False:
            label = (
                f"<b>EU AI Act Art. 50(3) Watermark Absent</b><br/>"
                f"<font size='10'>Kirchenbauer z={z:.2f} (below {threshold} "
                f"threshold; submitter should re-generate with a watermarked "
                f"LLM serving stack)</font>"
            )
            return watermark_stamp(label, bg_hex="#ffebee", text_color_hex="#b71c1c")
        label = (
            "<b>EU AI Act Art. 50(3) — Not in Scope</b><br/>"
            "<font size='9'>No token_ids supplied (text/hashes/binary "
            "are out of scope per Code of Practice §3.2). LLM serving "
            "stacks: pre-detect via POST /v1/disclosure/generate.</font>"
        )
        return watermark_stamp(label, bg_hex="#f5f5f5", text_color_hex="#616161")

    @staticmethod
    def _kv_table(rows: list[list[str]]):
        """Render a 2-column key/value table (thin wrapper)."""
        from app.pdf_helpers import kv_table

        return kv_table(rows)

    @staticmethod
    def _write_minimal_pdf(pdf_path: Path, cert_id: str) -> None:
        """Last-resort minimal valid PDF (no reportlab) — thin wrapper."""
        from app.pdf_helpers import write_minimal_pdf

        write_minimal_pdf(pdf_path, cert_id)

# ============================================================================
# 5. NotaryService production (W8.5)
# ============================================================================

