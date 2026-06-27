"""Shared PDF generation helpers for TrustLayer certificate rendering.

Centralised so multiple PDF-generating endpoints (NotaryService
`CertificateArtifactGenerator`, future audit-bundle PDF, etc.) reuse
the same rendering primitives instead of duplicating reportlab glue.

All functions are designed to be:
- **Importable from anywhere**: no app-level state, no NotaryService
  dependency. Pass primitives in, get reportlab objects out.
- **Lazy**: reportlab is only imported when a helper is called (so the
  control plane starts even if reportlab is broken).
- **Defensive**: `_safe_html` escapes user-controlled strings; the
  stamp helpers avoid any rotation / alpha-channel APIs that differ
  across reportlab versions.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


def safe_html(s: Optional[str]) -> str:
    """Minimal HTML escape for Paragraph payloads.

    Used by `kv_table` and `watermark_stamp_drawing` before passing
    user-controlled strings into reportlab.Paragraph.
    """
    if not s:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def kv_table(rows: list[list[str]]):
    """Render a 2-column key/value table.

    Returns a reportlab.platypus.Table styled with grey borders, 1.8"
    / 4.7" column widths (US Letter portrait). Each cell escapes
    via `safe_html` so user-supplied content cannot inject reportlab
    markup.
    """
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, Table, TableStyle

    body_style = getSampleStyleSheet()["BodyText"]
    table = Table(
        [
            [
                Paragraph(f"<b>{k}</b>", body_style),
                Paragraph(safe_html(v), body_style),
            ]
            for k, v in rows
        ],
        colWidths=[1.8 * inch, 4.7 * inch],
    )
    table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.grey),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    return table


def watermark_stamp(label: str, *, bg_hex: str = "#e8f5e9", text_color_hex: str = "#1b5e20"):
    """Build a centred colored Paragraph stamp (no rotation, broadest compat).

    Returns a reportlab.platypus.Paragraph with a coloured background
    + border. Suitable for embedding as a visual section in a PDF.

    Args:
        label: Stamp text (already wrapped in `<b>` / `<br/>` if needed).
        bg_hex: background colour hex string (e.g. `#e8f5e9` for green).
        text_color_hex: foreground / border colour hex string.
    """
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import Paragraph

    style = ParagraphStyle(
        "stamp",
        alignment=1,  # CENTER
        fontSize=12,
        leading=15,
        backColor=colors.HexColor(bg_hex),
        borderColor=colors.HexColor(text_color_hex),
        borderWidth=0.5,
        borderPadding=10,
        spaceAfter=4,
    )
    return Paragraph(label, style)


def write_minimal_pdf(pdf_path: Path, cert_id: str) -> None:
    """Last-resort minimal valid PDF (no reportlab).

    Used when reportlab is not installed or fails. Writes the bare
    minimum PDF that any reader (Adobe Reader, Preview, Chrome) can
    open and display the cert_id text.
    """
    body = (
        f"BT /F1 12 Tf 50 750 Td (TrustLayer Notary (degraded)) Tj "
        f"0 -20 Td (Cert: {cert_id}) Tj "
        f"0 -40 Td (reportlab unavailable; install with: uv add reportlab) Tj ET"
    )
    pdf_content = (
        "%PDF-1.4\n"
        "1 0 obj <<>> endobj\n"
        f"2 0 obj << /Length {len(body)} >> stream\n{body}\nendstream endobj\n"
        "3 0 obj << /Type /Pages /Kids [4 0 R] /Count 1 >> endobj\n"
        "4 0 obj << /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] "
        "/Resources << /Font << /F1 5 0 R >> >> /Contents 2 0 R >> endobj\n"
        "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"
        "xref\n0 6\n0000000000 65535 f \n"
        "0000000010 00000 n \n0000000050 00000 n \n0000000400 00000 n \n"
        "0000000500 00000 n \n0000000550 00000 n \n"
        "trailer << /Size 6 /Root 1 0 R >>\nstartxref\n600\n%%EOF\n"
    ).encode("latin-1")
    with open(pdf_path, "wb") as f:
        f.write(pdf_content)


__all__ = [
    "safe_html",
    "kv_table",
    "watermark_stamp",
    "write_minimal_pdf",
]
