# TrustLayer Compliance Map — DORA Article 19-20

**Generated:** 2026-06-24
**Source:** Regulation (EU) 2022/2554 (DORA — Digital Operational Resilience Act), Articles 19-20.

> Article 19 (Information and Communication Technology risk management): financial entities shall have a sound, comprehensive and well-documented ICT risk management framework.
>
> Article 20 (Reporting of major ICT-related incidents and significant cyber threats): financial entities shall report major ICT-related incidents to the competent authority.

## DORA Article 19 — ICT risk management framework

TrustLayer provides a **cryptographically-verifiable audit trail** for ICT risks:

| DORA Art. 19 requirement | TrustLayer v1 |
|---|---|
| Identification of ICT-supported business functions | `disclosure_records.ai_system_id` + `deployer_*` fields |
| Identification of ICT risks | `policy_decisions` table records every risk assessment |
| Protection against ICT risks | COSE_Sign1 + RFC 3161 cryptographic chain |
| Detection of anomalous activities | `disclosure_records.compliance_rollup` (Partial/NonCompliant flags) |
| ICT business continuity | `disclosure_records.retention_until` (3y EU AI Act, 5y DORA) |

## DORA Article 20 — Incident reporting

For major ICT-related incidents, TrustLayer provides:

- **Disclosed incident trail** via `GET /v1/evidence/{bundle_id}` (public, no auth, per AC-22 anti-greenwashing disclaimers)
- **Signed chain of events** (`disclosure_records` with `prev_hash` + `row_hash` BLAKE3 chain)
- **Timestamp proof** via RFC 3161 TSA token (`receipt.tsa_token_b64`)

## Compliance status (v1)

`ComplianceAssessment.retention_layer` status is `Partial` with `missing=["Multi-tenant retention audit (planned v1.1)"]`.

**v1.1 plan:** `DORAEvidenceStrategy` will check:
- Provenance chain integrity (every entry verifiable)
- Retention compliance (3y EU AI Act / 5y DORA)
- Incident log presence
- Key rotation history
- Multi-tenant isolation (per-tenant chain_id namespace)

## File-level traceability

| Code path | DORA reference | Status (v1) |
|---|---|---|
| `services/control_plane/app/db/models.py::DisclosureRecord.retention_until` | Art. 19(4) (continuity) | ✅ Compliant (append-only + retention_until) |
| `services/control_plane/app/db/models.py::KeyRotationEvent` | Art. 19 (risk management) | ⚠️ Partial (table exists; rotation runtime is v1.1) |
| `crates/tl-evidence/src/cose.rs::CoseSignature` | Art. 20 (signed evidence) | ✅ Compliant |
| `crates/tl-evidence/src/tsa.rs::TsaClient` | Art. 20 (timestamped evidence) | ✅ Compliant (with `TL_TSA_PROVIDER=free_tsa\|digicert`) / ⚠️ Partial (mock) |
| `services/control_plane/app/domain/disclosure_service.py::assess_4_layers` | Art. 19 (multi-tenant risk) | ⚠️ Partial (single-tenant v1; multi-tenant v1.1) |
