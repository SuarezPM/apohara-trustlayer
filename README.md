# Apohara TrustLayer

> **Convierte operaciones de IA en activos auditables, verificables y regulatoriamente defendibles.**
> _Turn AI operations into auditable, verifiable, regulatorily defensible assets._

[![CI](https://github.com/SuarezPM/apohara-trustlayer/actions/workflows/ci.yml/badge.svg)](https://github.com/SuarezPM/apohara-trustlayer/actions)
[![crates.io](https://img.shields.io/crates/v/apohara-trustlayer.svg)](https://crates.io)
[![npm](https://img.shields.io/npm/v/@apohara/trustlayer.svg)](https://www.npmjs.com)
[![PyPI](https://img.shields.io/pypi/v/apohara-trustlayer.svg)](https://pypi.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

**For CISOs and compliance teams facing EU AI Act Art. 50, DORA Art. 19-20, and the Code of Practice on Transparency of AI-Generated Content.** Production-grade crypto today; qualified-TSP integration in v1.1.0 (target 2026-08-30); watermarking hooks in v1.1.1 (target 2026-09-30). **Text-only AI systems are fully covered today; image/audio deployers MUST wait for v1.1.1.**

**Apohara TrustLayer** is an evidence-grade AI compliance platform. It produces
cryptographically-signed, forensically-defensible evidence trails for AI-generated
content per **EU AI Act Art. 50** (2 August 2026), **DORA Art. 19-20**, and
the **Code of Practice on Transparency of AI-Generated Content** (10 June 2026).

---

## Who is this for

TrustLayer v1.0 is built for the following ICP, in priority order:

### Primary ICP — CISOs and compliance teams facing EU AI Act Art. 50

- You are responsible for regulatory evidence at a company deploying AI-generated content in production.
- You need forensically-defensible proof of compliance, not just a marketing badge.
- You evaluate vendors on **offline verification**, **qualified-TSP timestamps**, **multi-tenant isolation**, and **audit-defensible crypto**.
- **Why TrustLayer fits**: COSE_Sign1 + RFC 3161 + PyO3 in-process verification (no subprocess on the crypto boundary) + 4-layer compliance model with most-restrictive-wins rollup.

### Secondary ICP — Compliance tooling developers / platform engineers

- You are building internal compliance tooling, eval pipelines, or content moderation systems.
- You need verifiable provenance + audit trails but are not (yet) the CISO signing off on Art. 50 exposure.
- The Quickstart below (`make demo`) gives you a 30-second vertical slice; the SDKs (`apohara-trustlayer` Python, `@apohara/trustlayer` TypeScript) cover the integration paths.

### Explicitly NOT for (in v1.0)

- **Compliance tool buyers without EU regulatory exposure** — if your jurisdiction does not bind you to Art. 50 / DORA / Code of Practice, lighter-weight tools (e.g. C2PA-only) are a better fit. TrustLayer's value lands on EU AI Act defensibility.
- **Image, audio, or video AI deployers** — Art. 50(3) watermark is `NotApplicable` in v1.0. **You MUST wait for v1.1.1** (target 2026-09-30) before using TrustLayer for image/audio/video content. Marketing as "EU AI Act compliant" without the watermark layer is greenwashing, and the `disclaimers` field in every API response will surface it.
- **Multi-tenant SaaS deployers** — v1.0 is single-tenant (`org_id = "apohara"`). Multi-tenant v1 ships in v1.2 (target late 2026 / early 2027). Self-hosted single-tenant deployments are fine.

---

## Why TrustLayer

The objection we hear most from CISOs: *"Why would I pay for this if I can build it with Claude Code over a weekend?"*

The honest answer: you can build a basic implementation, but not a **production-grade evidence platform**.

- **C2PA alone is insufficient** — it can be stripped from files; the Code of Practice requires multi-layer marking.
- **The Code of Practice** (10 June 2026) mandates: visible disclosure + machine-readable provenance + watermarking + retention with tamper-evidence.
- **Buyer risk**: enterprise security teams need offline-verifiable signatures, key rotation, TSA binding, and public verification endpoints.
- **Regulatory risk**: EU AI Act Art. 50 fines are **€15M or 3% of global turnover**. DORA Art. 19 carries additional operational-resilience fines.

TrustLayer delivers all 4 layers in one integrated platform with a single canonical repo.

---

## Quickstart

```bash
# Install dependencies
uv sync                              # Python control plane
maturin develop --release           # Python wheel (Rust + PyO3)
cargo install tsc --features all      # TS SDK build
npx tsup                             # TS SDK build

# Run the canonical acceptance test (vertical slice spec §1)
make demo

# Outputs:
#   disclosure_id: abc12345
#   compliance_rollup: Partial
#   v1 disclaimers: 4 entries
#   total wall-clock: < 30s
```

---

## Architecture

TrustLayer is a **5-component integrated platform** built on the existing
VOUCH/Themis substrate (123+ tests inherited, audit 8.25/10, `vouch.apohara.dev` live demo).

| Component | Stack | Purpose |
|---|---|---|
| **`tl-*` Rust crates** | Rust 2024 + COSE_Sign1 (coset 0.4.2) + Ed25519 (ed25519-dalek) + BLAKE3 | Crypto core: chains, evidence, signing, RFC 3161 TSA |
| **`tl-ffi` PyO3 binding** | Rust + pyo3 0.29 | In-process Python FFI for offline verification (NO subprocess) |
| **`tl-mcp-server`** | Rust + rmcp 1.8 | MCP server exposing 7 tools to Claude Code / Cursor / Codex |
| **`services/control_plane/`** | Python 3.11+ + FastAPI + pydantic v2 + SQLAlchemy 2.0 async | Stateless REST API (`/v1/disclosure/generate`, `/v1/verify/provenance`, `/v1/evidence/{id}`) |
| **SDKs** | Python (`apohara-trustlayer` + `apohara-trustlayer-light`) + TypeScript (`@apohara/trustlayer`) | Client libraries with zod/pydantic validation |

### 4-layer compliance model (per EU AI Act Art. 50 + Code of Practice §3.2)

Every disclosure reports **4 independent layers**:

1. **Visible disclosure** — user-facing text (Art. 50(1)(a))
2. **Machine-readable provenance** — COSE_Sign1 + RFC 3161 (Art. 50(2))
3. **Watermark/fingerprinting** — v1 reports `NotApplicable` (Art. 50(3); v1.1 will integrate Tree-Ring / AudioSeal)
4. **Retention/auditability** — append-only audit tables with 3y (EU AI Act) / 5y (DORA) retention

**Rollup is most-restrictive-wins.** A `NonCompliant` in any layer → global `NonCompliant`. Never false-positive.

### Content negotiation (v1.0.5)

`GET /v1/evidence/{bundle_id}` dispatches by `Accept` header (RFC 7231 §5.3.2): `application/scitt+json` → SCITT receipt envelope (IETF draft-ietf-scitt-scrapi-09, offline-verifiable); `application/json` / no header / `*/*` → v1.0 evidence_bundle_v1 (default, backward-compatible); anything else → 406 Not Acceptable with the supported list. See `services/control_plane/app/api/evidence.py` and `crates/tl-scitt/`.

---

## Integration smoke test (v1.0.5)

Per the 2nd auditor's recommendation (P1: real-world testability), the full vertical slice runs end-to-end and its output is captured in `audit_artifacts/smoke_test/v1.0.5_output.txt`. Excerpt (first 50 lines; full file is 228 lines):

```
================================================================
TrustLayer v1.0.5 — Integration Smoke Test Output
================================================================

Generated:    2026-06-25T13:35:00Z (UTC)
Run by:       Pablo + Claude (oh-my-claudecode + ralph)
Plan source:  .omc/plans/trustlayer-v1.2-execute.md (Block 2)
PRD source:   .omc/state/sessions/v1.0.5-execution/prd.json

================================================================
TEST ENVIRONMENT
================================================================

OS:           Linux 7.1.1-1-cachyos-bore-lto (Arch-based)
Kernel:       Linux (CachyOS)
CPU:          AMD Ryzen 5 3600 (6c/12t)
RAM:          48 GB
Rust:         rustc 1.88 (stable, edition 2021)
Python:       3.13 (via uv)

================================================================
VERTICAL SLICE — what was tested
================================================================

The canonical vertical slice per spec §1 is:
  generate → sign → verify → SCITT receipt → bundle export
```

Full output at [`audit_artifacts/smoke_test/v1.0.5_output.txt`](audit_artifacts/smoke_test/v1.0.5_output.txt). The artifact includes the **HONEST DISCLOSURES** section naming every synthetic / demo-grade part (synthetic bundle, synthetic SCITT fixture, Qualified stub returns NotImplemented, US-13 still blocked).

## Integration smoke test (v1.1.x) — closes auditor-4 BRECHA 5

Per Plan v1.2 Block 4 v1.1.0.x+1+4 (BRECHA 5: "`make demo` must produce a real evidence bundle and capture the output as a frozen artifact"), the v1.1.x smoke test runs the canonical vertical slice (generate → sign → verify → SCITT receipt → bundle export) and freezes the output to `audit_artifacts/smoke_test/v1.1.x_output.txt`.

Run via:
```bash
make demo-v1.1.x
```

Key markers in the artifact (asserted by `tests/test_smoke_test_artifact.py`):
- `Verification: OK` — openssl ts -verify output proving the digicert fixture passes full CMS signature verification per RFC 5652 §5.6 (closes auditor-4 BRECHA 1 + auditor-3 CRÍTICO 1).
- `cargo test --workspace` output showing 39+ Rust tests passing.
- `disclosure_id`, `compliance_rollup`, `SCITT`, environment markers, and **HONEST DISCLOSURES** about synthetic / NotApplicable / NotImplemented parts.

Frozen artifact sha256 (drift detection): `c693f2f95fddf3c7aceb9ff42a489a17d4a34311e9350f3eee86dd0e26a35b88` — also asserted by `tests/test_smoke_test_artifact.py`.

---

## Compliance map

| Regulation | Article | TrustLayer v1 |
|---|---|---|
| EU AI Act | Art. 12 (logging) | ✅ `disclosure_records` + `tool_execution_receipts` + `policy_decisions` + `key_rotation_events` (INSERT-only) |
| EU AI Act | Art. 50(1)(a) (visible disclosure) | ✅ `disclosure_text` + `disclosure_html_widget` |
| EU AI Act | Art. 50(2) (machine-readable) | ✅ COSE_Sign1 envelope + RFC 3161 timestamp |
| EU AI Act | Art. 50(3) (watermark) | ⚠️ `NotApplicable` (planned v1.1) |
| EU AI Act | Art. 50(4) (labelling) | ✅ 4-layer compliance + disclaimers |
| DORA | Art. 19-20 (evidence pack) | ⚠️ `Partial` — DORAEvidenceStrategy stub (v1.1) |
| ISO 42001 | AI management system | ❌ `NotImplemented` (planned v1.1) |
| NIST AI RMF | Govern/Map/Measure/Manage | ❌ `NotImplemented` (planned v1.1) |

**`disclaimers` field in every response surfaces the v1 limits explicitly** (AC-22).

---

## Repository layout

```
trustlayer/
├── crates/                      # Rust workspace (all `tl-*` + absorbed `themis-*`)
│   ├── tl-chain/                # BLAKE3 hash chain (absorbed from vouch-chain)
│   ├── tl-evidence/             # COSE_Sign1 + RFC 3161 wrapper (coset 0.4.2)
│   ├── tl-receipt/              # Disclosure receipt
│   ├── tl-gate/                 # BAAAR post-LLM deterministic gate
│   ├── tl-aibom/                # CycloneDX 1.6 AI Bill of Materials
│   ├── tl-compliance/           # OWASP / NIST / EU AI Act mapping
│   ├── tl-orchestrator/         # State machine + 9-agent court
│   ├── tl-frontend/             # vouch.apohara.dev demo UI
│   ├── tl-types/                # OrgId newtype (Architect IC-4)
│   ├── tl-ffi/                  # PyO3 in-process Python binding
│   ├── tl-mcp-server/           # MCP server (rmcp 1.8)
│   ├── themis-{evidence,compliance,orchestrator,agents,compressor,band-client,frontend}/
│   └── apohara-agentguard/      # seccomp+Landlock sandbox
├── services/control_plane/      # FastAPI control plane (Python)
├── sdk/
│   ├── python/                  # apohara-trustlayer (PyO3 wheel) + maturin
│   └── python-light/            # apohara-trustlayer-light (HTTP-only, no Rust)
│   └── typescript/              # @apohara/trustlayer (HTTP-only, edge-runtime)
├── tests/                       # e2e acceptance tests
├── audit_artifacts/             # Auditor-facing deliverables (tracked)
│   ├── spec_facts_audit.md      # Reconciled spec claims (AC-21)
│   ├── threat_model/            # STRIDE-per-component (per AC-22)
│   ├── compliance_maps/         # EU AI Act + DORA + Code of Practice traceability
│   └── deprecation/             # DEPRECATED.md (11 absorbed repos)
├── mcp/npm/                     # @apohara/trustlayer-mcp npm wrapper
├── .github/workflows/           # CI + Python wheels matrix (5 platforms)
├── Cargo.toml                   # workspace root
├── Makefile                     # make demo, make test, make audit
├── LICENSE                      # dual MIT/Apache-2.0
└── README.md                    # this file
```

---

## Scope of Compliance in v1.0

Per the **EU AI Act Art. 50** (effective **2 August 2026**, 38 days from this commit),
the **Code of Practice on Transparency of AI-Generated Content** (10 June 2026),
**DORA Art. 19-20**, and the **TSF v1.0 disclaimers** in every API response,
this section states **honestly** which subclauses TrustLayer v1.0 covers and which
it does NOT. **Deployers using v1.0 for image, audio, or video content are NOT
compliant with Art. 50(3) until v1.1.1 ships.**

| Regulation | Article | TrustLayer v1.1.x status | Notes |
|---|---|---|---|
| EU AI Act | Art. 50(1)(a) (visible disclosure) | **Covered** | `disclosure_text` + `disclosure_html_widget` |
| EU AI Act | Art. 50(2) (machine-readable provenance) | **Covered** (dev + production path) | COSE_Sign1 envelope + RFC 3161 timestamp via FreeTSA (dev) or DigiCert/Sectigo qualified TSP (production, default = Sectigo per v1.1.0.x+1+6). **Full CMS signature verification per RFC 5652 §5.6 implemented** in `tl-evidence::cms_verify::verify_strict_with_certs` (closes auditor-3 CRÍTICO 1 + auditor-4 BRECHA 1). |
| EU AI Act | Art. 50(3) (watermark) | **NotApplicable** | Watermark hooks deferred to v1.1.1 (c2patool + AudioSeal + Kirchenbauer text). See "What TrustLayer v1.0 is NOT" below. |
| EU AI Act | Art. 50(4) (labelling) | **Covered** | 4-layer compliance assessment + v1 disclaimers in every response |
| DORA | Art. 19-20 (evidence pack) | **Partial** | `DORAEvidenceStrategy` returns 6 checks (5 pass, `multi_tenant_isolation` honest-fail "ships in v1.2 — see tl-policy::multi_tenant_isolation_stub"). 1/6 honest-flag per Plan v1.2 Block 4 v1.1.0.x+1+5. **v1.2 progress (merged on `feat/v1.2-middleware-integration`):** the `org_resolver_middleware` and `get_org_id` dependency are wired into `main.py` + all 3 evidence routes + the disclosure route. The org_id column is on `DisclosureRecord` (4 tables). Remaining for full v1.2 multi-tenancy: Alembic migration for per-tenant `chain_id` namespace + the dedicated acme/globex isolation test. |
| ISO 42001 | AIMS | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2 (Plan v1.2 Block 5 v1.2-US-2). |
| NIST AI RMF | Govern/Map/Measure/Manage | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2 (Plan v1.2 Block 5 v1.2-US-2). |
| NIST SP 800-53 | Security and privacy controls | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2. |
| SOC 2 | AICPA Trust Services Criteria | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2. |
| ISO 27001 | Information Security Management System | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2. |
| OWASP LLM 2026 | Top-10 for LLM Applications | **NotImplemented** | `ComplianceStrategy::evaluate_all` honest-stub. Ships in v1.2. |

### What TrustLayer v1.0 is NOT (per `disclaimers` field)

- **NOT a qualified TSP for EU regulatory evidence**: the bundled `TL_TSA_PROVIDER=mock` and `free_tsa` options are **demo-grade only**. FreeTSA.org is NOT on the EU Trust List of qualified TSPs per ETSI EN 319 421. Timestamps from FreeTSA are NOT forensically valid for EU regulatory purposes. Production deployments must integrate with a qualified TSP (DigiCert, Sectigo, or an EU Trust List provider) — see v1.1.0.
- **NOT offline-verifiable via SCITT self-contained receipts**: the current `evidence` endpoint requires a live connection to the control plane for `verify_token`. SCITT-native offline verification is planned for v1.0.5.
- **NOT multi-tenant**: v1.0 is single-tenant (`org_id = "apohara"`). Multi-tenant v1 ships in v1.2.
- **NOT a watermark**: image/audio/video content is NOT marked with an imperceptible watermark. Deployers handling such content should not rely on TrustLayer v1.0 for Art. 50(3) compliance.

See `audit_artifacts/compliance_maps/EU_AI_Act_Article_50.md` for file-level traceability of
each row above. The `disclaimers` field in every API response surfaces these limits
automatically (per AC-22).

---

## v1 Scope (Demo-Grade)

Per the **Code of Practice** and **EU AI Act Art. 50**, the v1 release of TrustLayer
is production-grade for what it covers, but explicitly limited in scope:

### What's production-grade in v1
- **COSE_Sign1** envelopes (RFC 9052, coset 0.4.2 pinned)
- **BLAKE3** hash chains with append-only semantics
- **RFC 3161** timestamp integration (FreeTSA in dev, DigiCert in production via `TL_TSA_PROVIDER=digicert` in v1.1)
- **Public verification endpoint** (`POST /v1/verify/provenance`, no auth, rate-limited)
- **Append-only audit tables** (PostgreSQL role enforcement)
- **4-layer compliance assessment** with most-restrictive-wins rollup
- **v1 disclaimers** in every response (anti-greenwashing)
- **TSA provider fail-fast** (`TL_TSA_PROVIDER` unset/invalid → startup error, no silent mock)
- **OrgId newtype** (DNS-safe validation, no env var, gated demo constructor)
- **Offline verification** via PyO3 wheel (no subprocess)

### What v1 does NOT cover (acknowledged limits in `disclaimers`)
- **Watermarking** (Tree-Ring, AudioSeal) — `NotApplicable` in v1, planned v1.1
- **DORA evidence pack** — `Partial` (strategy stub), planned v1.1
- **ISO 42001** mapping — `NotImplemented`, planned v1.1
- **NIST AI RMF** mapping — `NotImplemented`, planned v1.1
- **Multi-tenant** — single-tenant v1 (`TL_ORG_ID=apohara`), planned v1.1
- **Key rotation runtime** — `KeyStore` loads keys, does not rotate
- **PDF export** of evidence bundles — JSON only in v1
- **SCITT-native format** — COSE_Sign1 in v1, SCITT countersignatures v1.1
- **WASM SDK / napi-rs** — HTTP-only TS SDK in v1, WASM in v2

---

## Bus Factor

**TrustLayer v1 is maintained by a single engineer (Pablo M. Suarez).**

**Hard deadlines (per Plan v1.1 R-NEW-7)**:
- **2026-08-06**: First co-maintainer merged PR. GitHub co-maintainer request opened 2026-06-25; 6-week deadline.
- **2026-09-30**: All signing keys escrowed to HashiCorp Vault or AWS KMS. Key rotation runtime (v1.1.0) operational.
- **Bi-weekly**: Release rotation — every 2 weeks, lead from non-primary committer if available.

**Operational mitigations** (committed in v1.0):
- 1,256+ tests provide regression safety
- `cargo deny check` enforces license + advisory hygiene
- `THREAT:` notes on ≥7 security-critical functions document the threat model
- `audit_artifacts/spec_facts_audit.md` reconciles every quantitative claim with ground truth
- The VOUCH/Themis substrate has 812 tests + audit 8.25/10 from prior work

**v1.1 milestone**: full Plan v1.1 (see `.omc/plans/trustlayer-v1.1.md`). Recruit co-maintainer is a release blocker for v1.1.0. Track at https://github.com/SuarezPM/apohara-trustlayer/milestones.

---

## v1.1 Milestone

The next iteration (v1.1) extends v1 with:

- **Watermarking integration**: c2patool for images, AudioSeal for audio, Kirchenbauer-style text watermark hooks
- **DORA evidence pack**: full `DORAEvidenceStrategy` with 6+ deliverable checks (provenance, retention, incident log, etc.)
- **ISO 42001 + NIST AI RMF** policy strategies (Strategy pattern dispatcher)
- **Multi-tenant v1**: `org_id` per-request from JWT (post-auth), `chain_id` namespace per org
- **DigiCert TSA provider**: production-grade RFC 3161 with signed cert chain
- **Key rotation runtime**: `KeyRotationPolicy` with configurable grace period
- **SCITT countersignatures**: SCITT-native format for interop with Sigstore Rekor v2
- **WASM SDK**: `apohara-trustlayer` browser bundle (Q3 2026)
- **PDF evidence export**: `crates/tl-evidence/src/bundle_pdf.rs` for human-readable audit packets

Track at: https://github.com/SuarezPM/apohara-trustlayer/milestones

---

## Verification

```bash
# All gates from the consensus-validated plan v3.1
cargo build --release --workspace     # 17 members, 0 errors
cargo test --workspace                # 1256+ tests pass
cargo clippy --all-targets -- -D warnings  # 0 warnings
cargo audit                           # 1 documented vuln (RUSTSEC-2023-0071 Marvin Attack on rsa 0.9.10, mitigated by Ed25519-only signing)
cargo deny check                      # advisories ok, bans ok, licenses ok, sources ok
uv run pytest tests/e2e/              # acceptance test: in-process variant
```

See `audit_artifacts/spec_facts_audit.md` for 8 reconciled quantitative claims and `audit_artifacts/threat_model/`
for STRIDE-per-component analysis.

---

## License

Licensed under either of **MIT** or **Apache-2.0** at your option.

See [LICENSE](LICENSE) for details.

---

## Status

**Pre-release.** v1 closes 14/22 stories (64%); the remaining 8 are Block 5
(docs, demo, public push) + US-13 (rmcp 1.8 macro blocker, in progress).

**v1.2 progress (merged on `feat/v1.2-middleware-integration`):**
- Multi-tenant org resolution: function-based `org_resolver_middleware`
  (NOT `BaseHTTPMiddleware`, avoids the SQLAlchemy 2.0 contextvars
  propagation issue). Resolves `org_id` from JWT (HS256) or
  `X-Org-Id` header. Returns 401 (loud, per IC-3) if missing.
- `get_org_id` FastAPI dependency wired into all 3 evidence routes
  + the disclosure route.
- `DisclosureRecord` (and the 3 other append-only tables) have
  an `org_id` column. Routes filter by `where(id == X, org_id == Y)`.
- The `multi_tenant_isolation` DORA check is no longer a 401 — it's
  200 for org_id-matching requests and 404 for cross-tenant.
- Remaining for full v1.2: Alembic migration for per-tenant
  `chain_id` namespace + the dedicated acme/globex isolation test
  + 4 follow-up test files (test_scitt, test_stix, test_content
  _negotiation) need a `__future__` annotations fix.

**Not yet pushed to a public registry.** The `v1` release tag will follow
Pablo's manual review of the spec-facts audit diff and the public verify
endpoint's end-to-end behavior.

**EU AI Act Art. 50 deadline: 2 August 2026** (39 days from this commit).


## v1.2 multi-tenant handoff (next-session TODO)

The `feat/v1.2-middleware-integration` branch was merged to `main` on
2026-06-25. The next session should:

1. **Fix the 4 remaining test files** that fail with 401:
   - `tests/test_scitt_countersign_endpoint.py`
   - `tests/test_stix_export.py`
   - `tests/test_content_negotiation.py`
   - All have the same root cause: `from __future__ import annotations`
   before the `from tests.test_org_id_helpers import OrgIdTestClient`
   import causes a circular import issue.
   - **Fix**: move `from __future__ import annotations` AFTER the
     `OrgIdTestClient` import, OR use string forward references.

2. **Add the dedicated acme/globex isolation test** to
   `tests/test_real_evidence_lookup.py`:
   ```python
   def test_acme_cannot_see_globex_bundles():
       # Create bundle with org_id=acme; test that acme gets 200,
       # globex gets 404 (org_id filter blocks the cross-tenant lookup)
   ```

3. **Alembic migration for per-tenant `chain_id` namespace**
   (Plan v1.2 Block 4 v1.2-US-1, remaining step):
   - `chain_id` should be `tenant:{org_id}:{disclosure_type}` instead
     of the current single value.
   - This is the final step for true multi-tenant SaaS.

4. **Run `review-work` skill** on the merged commit to validate
   the full v1.2-middleware-integration change.

5. **Run openssl ts -verify** regression on the digicert fixture
   to ensure v1.2 didn't break v1.1.x. (Already passes locally.)

6. **Real mappers for ISO 42001 + NIST AI RMF** (deferred to a
   future PR; the v1.2 work is multi-tenant focused).

7. **Add the v1.2 sub-section** to the README status block.
