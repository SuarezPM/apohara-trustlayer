# TrustLayer Design Partner Program

> **Status**: ACTIVE (launched 2026-06-26)
> **Target**: 5 EU-regulated firms before 2 August 2026 (EU AI Act Art. 50 deadline)
> **Contact**: pablo@apohara.org (or open an issue)

## What is this?

TrustLayer is the open-source multi-tenant SaaS substrate for EU AI Act + DORA + PLD + ISO 42001 compliance evidence. We are looking for **5 design partners** who will use TrustLayer v2.0 + v3.0 in production for 6 months, free of charge, in exchange for feedback that shapes our roadmap.

## Who should apply?

You should apply if you are:

- **EU-based** (or EU-regulated) with an AI system that needs compliance evidence
- Building or operating **AI systems covered by EU AI Act Art. 50** (transparency obligations) or **Art. 12** (logging obligations), or
- Operating in **EU financial services** subject to **DORA Art. 9-13** (ICT third-party risk), or
- Subject to **PLD 2024/2853** product liability for AI-driven products (the new PLD specifically includes AI systems as "products"), or
- Pursuing **ISO/IEC 42001:2023** certification for your AI management system

**Industry verticals**: Financial services, healthcare, automotive (embedded AI), employment/HR tech, education tech, biometric systems, critical infrastructure, media/content generation.

## What you get (free for 6 months)

- **TrustLayer v2.0 + v3.0 SaaS** hosted by Apohara, with **multi-tenant isolation** for your org
- **Full EU Trust List validation** for your TSA providers (eIDAS Art. 67 + ETSI EN 319 421)
- **SCITT-native evidence receipts** for every AI decision (RFC 9943 compliant)
- **PDF evidence exports** for auditors (printpdf 0.7 multi-section A4)
- **WASM SDK** for browser-based verification
- **Kirchenbauer text watermarking** (real z-test detection, z > 4.0 threshold)
- **Key rotation runtime** (NIST SP 800-57 baseline, 90d rotation, 30d grace)
- **DORA evidence pack auto-generator** (W2.2 deliverable, available Q4 2026)
- **PLD defect rebuttal pack** (W2.2 deliverable, available Q4 2026)
- **ISO/IEC 42001 SoA auto-generator** (W2.3 deliverable, available Q4 2026)
- **PQC hybrid signer** (ML-DSA-65 + Ed25519 composite, Attestix-compatible cryptosuites) — W1.1 deliverable
- **Direct access to Pablo (founder)** via shared Slack channel for bug reports, roadmap input, and architectural questions
- **Co-marketing**: your logo on our homepage, joint case study published post-pilot

## What we ask in return

- **Use it in production** for at least one AI workflow that generates audit-relevant evidence
- **Monthly 1-hour feedback call** for 6 months (6 calls total)
- **Public case study** at the end of the pilot (anonymized if you prefer)
- **Bug reports with reproducer scripts** (within 48h of discovery)
- **One reference call** with a prospect who asks about TrustLayer

## What this is NOT

- **Not a free-tier SaaS** — this is a structured pilot with feedback obligations
- **Not custom development** — you use the v2.0/v3.0 product as-is; custom features go on the post-pilot roadmap
- **Not an SLA** — best-effort support during the pilot; production SLAs are a separate commercial agreement

## Timeline

| Date | Milestone |
|---|---|
| **2026-06-26** | Program opens (this document) |
| **2026-07-10** | Application deadline (14 days) |
| **2026-07-17** | Selection announced (5 partners) |
| **2026-07-24** | Onboarding kickoff (each partner gets a Slack channel + sandbox org) |
| **2026-08-02** | EU AI Act Art. 50 deadline (compliance pack live for partners) |
| **2027-01-24** | Pilot ends (6 months from kickoff) |
| **2027-02-15** | Joint case studies published |

## Application form

Copy-paste this into an email to pablo@apohara.org:

```
Subject: TrustLayer Design Partner Application — [Your Company Name]

1. Company name + URL:
2. Primary contact (name, role, email):
3. EU member state(s) where you operate:
4. Which regimes apply to you? (EU AI Act Art. 50, Art. 12, DORA, PLD, ISO 42001, other)
5. What AI system(s) would you generate evidence for? (1-2 sentences)
6. Estimated disclosure events per month:
7. Current compliance tooling (if any): Vanta, Drata, custom GRC, none
8. Why TrustLayer? (1-2 sentences)
9. Willing to commit to monthly feedback calls for 6 months? (Y/N)
10. Public case study OK? (Y/N/anonymized)
```

We respond within 48h with a 30-min discovery call.

## Why we're doing this

The honest reason: **TrustLayer has production-grade code but zero paying customers.** The technical audit confirmed our stack is sound, but the gap between "the code is right" and "people use it" is a non-technical problem that requires user feedback to close. The EU AI Act deadline creates urgency that aligns with our engineering velocity. Five design partners is the smallest number that gives us credible market signal; it's also the largest number we can support as a solo founder without burning out.

If you read this far and you're in the ICP: **apply.** The worst that happens is a 30-min call and a clear answer about whether we're a fit.

— Pablo M. Suarez, founder (single-engineer, Montevideo → Tucumán → wherever the next design partner is)
