# Apohara TrustLayer — Series A Deck Outline (W7.3)

> Target: €2-5M seed round, Q4 2026 close. Lead investor: Singular (Tsuga) or Infinity Ventures (Flagright). Target ARR at 18 months: $1M. Target close at 24 months: $5M ARR → $50M exit (10x multiple).

## Slide 1 — Title

**Apohara TrustLayer**
*AI operations as court-grade evidence assets*

CEO: Pablo M. Suarez | Founded 2024
Lead: Singer-class in AI compliance infrastructure
Q4 2026 seed target: €2-5M

[Logo, contact info, single sentence value prop]

## Slide 2 — Traction teaser

- **1,287 tests passing** in CI (0 regressions across 9 months)
- **36 MCP tools** for AI agent compliance (vs Attestix's 47)
- **22 commits** shipped in one day during the v3.0 milestone
- **PQC hybrid Ed25519+ML-DSA-65** (FIPS 204, June 2026, Attestix-compatible)
- **COSE_Sign1 receipts** with RFC 3161 QTSP + SCITT Merkle inclusion
- **6 compliance frameworks** mapped (EU AI Act, DORA, PLD, ISO 42001, NIST AI 600-1, ZTNA)
- **3 standalone SDKs** (Rust native, TypeScript WASM, Go pure-Go)
- **2 published DOI papers** (INV-15 Z3 proof, 4-layer compliance model)

## Slide 3 — Problem

**The 7th compliance crisis** (2024-2026):
1. **EU AI Act** Art. 14 enforcement: Aug 2, 2026 (37 days from pitch). Fines: **€35M or 7% of global revenue**.
2. **DORA** Art. 10 enforcement: Jan 17, 2025 (already in force). 22,000+ EU financial entities.
3. **PLD 2024/2853**: Member state transposition by Dec 9, 2026 (166 days).
4. **ISO/IEC 42001:2023**: BS EN adopted March 25, 2026.
5. **NIST PQC migration**: Priority systems by 2030, RSA/ECC disallowed by 2035.
6. **NIST AI 600-1** GenAI Profile: Published July 26, 2024.

The blocker: existing tools (Vanta, Drata, Credo AI, Delve, Zania) handle *policy* and *evidence collection* but produce no **court-grade** evidence. They can tell you "you're compliant" but cannot produce a COSE_Sign1 + SCITT + RFC 3161 artifact a plaintiff's lawyer would accept.

## Slide 4 — Solution

**Apohara TrustLayer is the only open-source substrate that produces court-grade cryptographic evidence for AI operations.**

Three layers:
1. **Discovery Layer** — automated 4-layer compliance model with
   most-restrictive-wins rollup (Disclosure / Provenance / Watermark
   / Operational).
2. **Notary Layer** — `POST /v1/notarize` produces a signed COSE_Sign1
   certificate (Ed25519+ML-DSA-65 hybrid) per AI content with RFC 3161
   QTSP timestamp + SCITT Merkle inclusion proof.
3. **Substrate Layer** — 36-tool MCP server + 3 SDKs (Rust, TypeScript WASM,
   Go) pluggable into any AI agent framework.

## Slide 5 — Traction (in-depth)

Not revenue metrics. For OSS infrastructure, the metrics that matter:
- **1,287 tests** across 9 Rust crates + Python control plane + 2 SDKs
- **36 MCP tools** in v3.0 (was 7 in v2.0, +29 in one day)
- **22 atomic commits** shipped during the v3.0 milestone
- **PQC parity with Attestix v0.4.1** (signed, no independent audit)
- **6 compliance frameworks** mapped (auto-generator code)
- **3 SDKs** (Rust, TypeScript WASM 53.6KB gzipped, Go zero-CGO)
- **2 academic papers** (DOI minted, INV-15 Z3 proof + 4-layer model)
- **0 regressions** across the 22-commit v3.0 sprint

## Slide 6 — Market

Total addressable market (2026):
- AI governance platform: **$3.09B in 2026 → $7.29B by 2030** (24% CAGR) [Research and Markets]
- Agentic AI security: **$1.65B → $13.52B by 2032** (42% CAGR) [Markets and Markets]
- DORA compliance software: **$0.8B by 2026** (Euromonitor)
- AI compliance tools (Vanta, Drata, Credo AI, Delve, Zania, Norm Ai): **$20-35M Series A 2024-2026**

Penetration assumption: 0.1% of AI governance by 2027. TAM at our
wedge (court-grade AI evidence) is **$300M by 2028**.

## Slide 7 — Competition

| Wedge | TrustLayer | Attestix | Vanta | Drata | Credo AI | Delve |
|-------|------------|----------|-------|-------|----------|-------|
| **COSE_Sign1 + ML-DSA-65 + SCITT** | ✅ | partial | ❌ | ❌ | ❌ | ❌ |
| **PLD Art. 10 rebuttable presumption pack** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **PQC hybrid Ed25519+ML-DSA-65** | ✅ | ✅ v0.4.1 | ❌ | ❌ | ❌ | ❌ |
| **Open source** | ✅ MIT | ✅ Apache | ❌ | ❌ | ❌ | ❌ |
| **CordonEnforcer (verdict synthesis isolation)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Z3 formal proof integration** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Pricing** | Free (OSS) | Free (OSS) | $20K+/yr | $15K+/yr | $50-500K/yr | Custom |
| **Funding** | Pre-seed | $0 | $75M+ | $200M+ | $27M+ | $32M+ |

**Our edge**: PQC + COSE_Sign1 + SCITT + PLD rebuttable + open source. The combination is not found in any competitor, proprietary or open source.

## Slide 8 — Vision

**In 24 months**: every AI agent operation in production EU companies is accompanied by a COSE_Sign1 receipt that can be presented in court. PLD Art. 10 rebuttable presumption becomes routine.

**In 36 months**: TrustLayer is the default attestation substrate for EU AI agent frameworks. Acquisition target for Vanta, Drata, or a Big4 consultancy (similar to Deductive AI → Elastic $85M trajectory).

## Slide 9 — Team

- Pablo M. Suarez — Founder. Single-engineer bus factor (target: co-maintainer by Aug 6, 2026).
- 22 atomic commits in 24 hours during v3.0 milestone demonstrates execution velocity.
- Academic credibility: 2 DOI papers (INV-15 Z3 proof, 4-layer compliance model), Z3 formal verification.

Advisors needed: cryptographic audit credibility, regulatory testimony (former CISO from EU financial services), Series A B2B SaaS operator.

## Slide 10 — Use of Funds (€3M target)

| Use | % | € |
|-----|---|----|
| Engineering (2 senior + 1 junior) | 50% | €1.5M |
| Cryptographic audit (NCC Group, Trail of Bits, Cure53) | 15% | €450K |
| Sales & GTM (EU regulatory vertical) | 20% | €600K |
| Compliance & legal (GDPR, PLD, EU AI Act) | 10% | €300K |
| Runway buffer (15 months) | 5% | €150K |

## Slide 11 — Ask

**Seeking €3M seed** (18-month runway to $1M ARR, then €5-10M Series A at $20-30M valuation).

Lead investor: **Singular** (led Tsuga $35M, same category, same window) or **Infinity Ventures** (led Flagright $12.5M, EU compliance focus).

## Slide 12 — Appendix (linked)

- A. Technical architecture (COSE_Sign1 → SCITT → RFC 3161 → COSE Receipt with Merkle proof)
- B. Compliance framework matrix (EU AI Act Art. 14/50, DORA Art. 10, PLD Art. 9/10, ISO 42001:2023, NIST AI 600-1, NIST PQC FIPS 203/204/205)
- C. Attestix v0.4.1 cross-validation report (RustCrypto ml-dsa 0.1.0 GA + 3 advisories + cross-implementation tests with CIRCL, BouncyCastle, ACVP)
- D. References: RFC 9943, draft-emirdag-scitt-ai-agent-execution-00, IETF SCITT drafts, ml-dsa FIPS 204, Attestix v0.4.1, edpool patent analysis, Ghostwriter, CoT-Self-Instruct evaluation
