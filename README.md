# Apohara TrustLayer

> **Convierte operaciones de IA en activos auditables, verificables y regulatoriamente defendibles.**
> _Turn AI operations into auditable, verifiable, regulatorily defensible assets._

[![CI](https://github.com/SuarezPM/apohara-trustlayer/actions/workflows/ci.yml/badge.svg)](https://github.com/SuarezPM/apohara-trustlayer/actions)
[![crates.io](https://img.shields.io/crates/v/apohara-trustlayer.svg)](https://crates.io)
[![npm](https://img.shields.io/npm/v/@apohara/trustlayer.svg)](https://www.npmjs.com)
[![PyPI](https://img.shields.io/pypi/v/apohara-trustlayer.svg)](https://pypi.org)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

**Apohara TrustLayer** is an evidence-grade AI compliance platform. It produces
cryptographically-signed, forensically-defensible evidence trails for AI-generated
content per **EU AI Act Art. 50** (2 August 2026), **DORA Art. 19-20**, and
the **Code of Practice on Transparency of AI-Generated Content** (10 June 2026).

---

## Why TrustLayer

The objection we hear most: *"Why would I pay for this if I can build it with Claude Code over a weekend?"*

The honest answer: you can build a basic implementation, but not a **production-grade evidence platform**.

- **C2PA alone is insufficient** — it can be stripped from files; the Code of Practice requires multi-layer marking.
- **The Code of Practice** (10 June 2026) mandates: visible disclosure + machine-readable provenance + watermarking + retention with tamper-evidence.
- **Buyer risk**: enterprise security teams need offline-verifiable signatures, key rotation, TSA binding, and public verification endpoints.
- **Regulatory risk**: EU AI Act Art. 50 fines are **€15M or 3% of global turnover**.

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

This is **acknowledged risk, not silent risk**. The plan mitigates via:
- `audit_artifacts/spec_facts_audit.md` reconciles every quantitative claim with ground truth
- `THREAT:` notes on ≥7 security-critical functions document the threat model
- 1,256+ tests provide regression safety
- `cargo deny check` enforces license + advisory hygiene
- The VOUCH/Themis substrate has 812 tests + audit 8.25/10 from prior work

**v1.1 milestone**: recruit a co-maintainer, freeze the public API surface, and publish a "contributing" guide. Track this as a release blocker for v1.1.

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

**Not yet pushed to a public registry.** The `v1` release tag will follow
Pablo's manual review of the spec-facts audit diff and the public verify
endpoint's end-to-end behavior.

**EU AI Act Art. 50 deadline: 2 August 2026** (39 days from this commit).
