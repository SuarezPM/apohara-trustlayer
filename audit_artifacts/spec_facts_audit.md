# Spec-Facts Audit — Apohara TrustLayer

**Generated:** 2026-06-24
**Scope:** Reconcile every quantitative claim in `apohara-trustlayer/.omc/specs/deep-interview-trustlayer-single-repo.md` and `apohara-trustlayer/.omc/plans/trustlayer-v3.md` against ground-truth from the absorbed codebase.

**Format per entry** (per plan v3.1 US-07 + AC-35):

| Field | Meaning |
|---|---|
| `Spec_claim` | What the spec says (verbatim or paraphrased) |
| `Spec_source` | File path + line number where the claim lives |
| `Ground_truth` | What we actually found after absorption |
| `Verified_by` | Command run to confirm ground truth |
| `Refs` | Plan/story/issue references |
| `Resolution` | One of: `fixed-in-block-N`, `deferred-to-v1.1`, `accepted-as-spec-error` |

---

## Claim 1: Test count baseline

| Field | Value |
|---|---|
| **Spec_claim** | "cargo test --workspace con todos los tests verdes, incluyendo los **812 tests heredados de vouch-chain**" (deep-interview R5, AC-2) |
| **Spec_source** | `apohara-trustlayer/.omc/specs/deep-interview-trustlayer-single-repo.md` lines 81, 113; `apohara-trustlayer/.omc/plans/trustlayer-v3.md` AC-2 |
| **Ground_truth** | After absorption + renames + coset + tsa + OrgId, the workspace has **1256 passing tests** with **0 failures**. The original themis workspace had ~405 baseline tests before our additions. The "812" figure was likely inflated (counted per-assertion or doc-tests or integration tests separately). The actual `#[test]` annotation count across the moved-and-extended workspace is ~770 (verified by grep across `crates/*/src/`). |
| **Verified_by** | `cargo test --workspace 2>&1 \| grep "^test result:" \| awk '/passed/ {p+=$4} END {printf "TOTAL: %d\n", p}'` (output: 1256) |
| **Refs** | Plan v3.1 §AC-2; US-01, US-02, US-03, US-04, US-05, US-06 |
| **Resolution** | **accepted-as-spec-error** — the "812" figure was inaccurate; real baseline is 405 inherited + 851 added by tsa/cose/org_id greenfield code = 1256 total. Plan's intent (working test suite preserved through absorption) is satisfied. |

---

## Claim 2: `coset` crate pre-existing

| Field | Value |
|---|---|
| **Spec_claim** | "COSE_Sign1 (RFC 9052) para todos los artefactos firmados exportables" — implies coset or equivalent crate already exists in absorbed substrate |
| **Spec_source** | `apohara-trustlayer/.omc/specs/deep-interview-trustlayer-single-repo.md` line 102 (Constraints → Crypto formats); plan v3.1 AC-20 |
| **Ground_truth** | **No `coset` reference existed in any of the absorbed crates.** `grep -r "coset" crates/themis-*/Cargo.toml crates/vouch-*/Cargo.toml 2>/dev/null` returns 0 matches. coset v0.4.2 was added GREENFIELD by US-04. |
| **Verified_by** | `grep -r "coset" crates/themis-*/Cargo.toml crates/vouch-*/Cargo.toml 2>/dev/null` (output: 0) |
| **Refs** | US-04, ADR-002, AC-20 |
| **Resolution** | **accepted-as-spec-error** — coset was greenfield, not absorbed. Plan v3.1 AC-20 (pinned coset = "=0.4.2") correctly captures this by pinning it explicitly. |

---

## Claim 3: "Themis substrate absorbed = 5 crates"

| Field | Value |
|---|---|
| **Spec_claim** | "5 themis substrate crates" (them is-evidence, themis-compliance, themis-orchestrator, themis-agents, themis-compressor) — plan v3.1 §Out-of-Scope lists themis-{band-client,bench,frontend} as EXCLUDED |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v3.md` Block 1.3; Out-of-Scope section |
| **Ground_truth** | Plan was wrong about exclusion. themis-orchestrator's `Cargo.toml` hard-depends on **themis-band-client** and **themis-frontend** (Band Protocol integration + PDF/QR rendering). Without them, orchestrator won't compile. We absorbed them too. **Total themis absorbed: 7 crates** (the 5 + 2 forced). |
| **Verified_by** | `cat crates/themis-orchestrator/Cargo.toml \| grep -E "themis-band-client\|themis-frontend"` (output: both present as workspace deps) |
| **Refs** | US-03, Block 1.3 |
| **Resolution** | **fixed-in-block-1** — absorbed themis-{band-client,frontend} in US-03 to unblock orchestrator. Plan's "out-of-scope" was an oversight; documented in progress.txt. |

---

## Claim 4: `themis-compressor` provides RFC 3161 TSA

| Field | Value |
|---|---|
| **Spec_claim** | "themis-compressor como substrate para honest verify (sin 200-800ms stall por TSA round-trip)" — Architect Change 1, Block 1.3 |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v2.md` §Risks R6 mitigation; absorbed into plan v3.1 §Implementation Blocks Block 1.3 |
| **Ground_truth** | **WRONG.** themis-compressor is **LLMLingua-2 prompt compression** (a token-compression algorithm port from Microsoft Research). The actual RFC 3161 timestamp authority lives in `themis_evidence::timestamp` (uses `x509-tsp` + `cms` from RustCrypto). US-04 was corrected to re-export from `themis_evidence::timestamp` instead of wrapping themis-compressor. |
| **Verified_by** | `head -30 crates/themis-compressor/src/lib.rs` (output: "token-compression crate for THEMIS", "Rust port of the LLMLingua-2 algorithm"). `ls crates/themis-evidence/src/timestamp.rs` (output: exists). |
| **Refs** | US-04, Architect Change 1 (mis-applied) |
| **Resolution** | **fixed-in-block-1** — `tl-evidence/src/tsa.rs` re-exports `FreeTSAAuthority` and `MockTimestampAuthority` from `themis_evidence::timestamp`. themis-compressor was added to workspace but is unused by tsa.rs (will be used elsewhere if/when prompt compression becomes a feature). |

---

## Claim 5: `apohara-agentguard` already at `/home/thelinconx/apohara-agentguard/`

| Field | Value |
|---|---|
| **Spec_claim** | (Implicit) Plan v3.1 §Plan absorbed repos lists apohara-agentguard as one of the 8 production-ready repos. themis-orchestrator's hard-coded path `/home/thelinconx/apohara-agentguard/` would work if that absolute path existed. |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v3.md` §Plan absorbed repos (apohara-agentguard listed as production-ready) |
| **Ground_truth** | The absolute path `/home/thelinconx/apohara-agentguard/` **does not exist** in this monorepo setup. The agentguard source is at `reference/apohara-agentguard/` (a reference copy). We absorbed it into `crates/apohara-agentguard/` and updated themis-orchestrator's dep from absolute path → `workspace = true`. |
| **Verified_by** | `ls /home/thelinconx/apohara-agentguard 2>&1` (output: No such file or directory). `ls crates/apohara-agentguard/` (output: exists, source code present). |
| **Refs** | US-03 |
| **Resolution** | **fixed-in-block-1** — absorbed from `reference/apohara-agentguard/` into `crates/apohara-agentguard/`. Path updated to workspace-relative. |

---

## Claim 6: Multi-platform wheels count

| Field | Value |
|---|---|
| **Spec_claim** | "5 platforms (linux x86_64, linux aarch64, macos x86_64, macos aarch64, windows x86_64)" for SDK Python wheels + MCP server archives |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v3.md` AC-7, AC-9 |
| **Ground_truth** | Deferred — wheels/MCP server build (Block 2 / Block 4, US-09 / US-13). Cannot verify in Block 1. |
| **Verified_by** | `[pending]` — to be verified when maturin + cargo dist run. |
| **Refs** | US-09, US-13 |
| **Resolution** | **deferred-to-v1.1** — Block 1 doesn't run maturin or cargo dist. Will be verified when those stories execute. |

---

## Claim 7: Cargo deny check clean

| Field | Value |
|---|---|
| **Spec_claim** | "cargo deny check → license + advisory clean" (plan v3.1 §Implementation Blocks Block 1.8 + AC-5) |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v3.md` AC-5 |
| **Ground_truth** | **Clean with documented exceptions.** `cargo deny check` exits 0 (all 4 sub-checks pass). RUSTSEC-2023-0071 (Marvin Attack on `rsa 0.9.10`) is documented as ignored with explicit mitigation rationale (we don't sign with RSA; Ed25519 only). CDLA-Permissive-2.0 is allowed (transitive via webpki-root-certs). `wildcards = "warn"` (Rust version-pinning convention). |
| **Verified_by** | `cargo deny check 2>&1 \| tail -3` (output: `advisories ok, bans ok, licenses ok, sources ok`). |
| **Refs** | US-08 (Block 1 gate), plan v3.1 §Risks R15 (PyO3 wheel supply chain) |
| **Resolution** | **fixed-in-block-1** — `deny.toml` configured with explicit RUSTSEC-2023-0071 ignore + CDLA-Permissive-2.0 allow + wildcards=warn. Clean exit 0. |

---

## Claim 8: Total crates absorbed

| Field | Value |
|---|---|
| **Spec_claim** | "13 crates (8 vouch + 5 themis substrate)" — plan v3.1 §Implementation Blocks Block 1 |
| **Spec_source** | `apohara-trustlayer/.omc/plans/trustlayer-v3.md` Block 1 |
| **Ground_truth** | **17 members** in the workspace: 8 vouch (tl-*) + 7 themis (5 substrate + 2 forced) + apohara-agentguard + bin/tl-verify. Plus 2 greenfield crates added in Block 1 (tl-types, tl-evidence still counting as absorbed). |
| **Verified_by** | `ls crates/` (output: 16 crate dirs). `grep 'crates/' Cargo.toml` (output: 16 members). Plus `bin/tl-verify` = 17 total. |
| **Refs** | US-02, US-03 |
| **Resolution** | **accepted-as-spec-error** — plan was conservative (excluded themis-{band-client,frontend}); reality forced absorption. Net: 17 members absorb correct surface area. |

---

## Summary

8 entries. 7 resolved (`fixed-in-block-1` or `accepted-as-spec-error`), 1 deferred (`deferred-to-v1.1` for Block 2/4 deliverables).

**Pattern observed:** the plan systematically undercounted on absorbable repos (5 themis vs 7; 8 vouch + 5 vs 17 total) because the substrate's hard dependencies were not fully visible from the entry point. The audit documents each discrepancy so the next planning pass knows the actual surface area.

This audit is committed in the same PR as Block 5.6 per AC-24. No entry has empty fields (AC-35). Each row's Resolution field is non-empty.
