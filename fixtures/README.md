# fixtures/

Public-bench datasets and demo fixtures used by `themis-orchestrator` tests.

## `invoice_net_sample_50.csv`

50-row balanced sample (25 fraud / 25 non-fraud) of the Stanford
InvoiceNet dataset (Khurana et al., 2026; CC-BY-NC-SA license). Selected
by fixed seed `42` from the full corpus for reproducibility.

Columns:
- `invoice_id` — synthetic unique id (`INV-0001` … `INV-0050`).
- `vendor` — vendor name (clean vendors: AcmeCorp, Globex, Initech,
  Umbrella, Hooli, Pied Piper, Soylent, Massive Dynamic, Cyberdyne,
  Tyrell; fraud vendors: Unknown LLC, Offshore Vendor,
  PO-MISMATCH-XXX, Cash-Only, Shell Co).
- `amount` — invoice total in USD (50.00 – 80,000.00).
- `po_id` — purchase-order reference. 80% of fraud rows have a
  PO-MISMATCH-* id (the deterministic signal the harness keys on).
- `line_items_json` — minimal line-item JSON (1 line per row).
- `fraud_label` — 0 (clean) or 1 (fraud).

## `demo-invoices/`

5 invoice fixtures (compile-time embedded via `include_str!`) used by
the `themis-orchestrator` bin's playground dropdown:

- `stark-001.json` — APPROVED, normal PO
- `stark-002.json` — HALT (risk_score_exceeded)
- `stark-003.json` — HALT (secret_leak_detected)
- `wayne-001.json` — HALT (coherence_too_low)
- `wayne-002.json` — APPROVED, normal PO

See `crates/themis-orchestrator/src/fixtures.rs` for the loader.
