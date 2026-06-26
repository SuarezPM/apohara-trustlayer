# TrustLayer 4-Layer Compliance Model: A Reference Architecture for EU AI Act + DORA + ISO 42001

> **Working paper for DOI submission to Zenodo (post-v3.0 release, target Q4 2026).**
> **Authors**: Pablo M. Suarez (Independent Researcher)
> **License**: CC-BY-4.0
> **Status**: Draft for v3.0 — implements all 4 layers as code in TrustLayer v2.0

---

## Abstract

The EU AI Act (Regulation 2024/1689), DORA (Regulation 2022/2554), ISO/IEC 42001:2023, and PLD 2024/2853 each impose overlapping but distinct compliance obligations on AI system operators. Most existing GRC platforms (Vanta, Drata, Credo AI, Holistic AI) treat these as separate workflows, generating redundant evidence and forcing compliance teams to reconcile conflicting taxonomies. This paper proposes a **4-layer compliance model** in which every AI evidence artifact is simultaneously evaluated against all four regimes via independent layers, producing a single cryptographically-sealed artifact that satisfies the most-restrictive-wins requirement across regimes. We describe the implementation in TrustLayer v2.0 (production, MIT/Apache-2.0, 24 Rust crates + Python control plane, 88 Python + 585 Rust tests passing as of 2026-06-26), report on the first 5 design partners (target Q4 2026), and discuss extensions for PQC migration (FIPS 204 ML-DSA-65) and cross-jurisdiction compliance (UK AI Bill, US EO 14110, China GenAI Measures).

## 1. The compliance fragmentation problem

A regulated AI operator faces, in 2026, at least four distinct compliance regimes:

1. **EU AI Act (2024/1689)** — Article 12 (record-keeping for high-risk AI), Article 50 (transparency for AI-generated content), Annex III (high-risk use cases).
2. **DORA (2022/2554)** — Articles 9-13 (ICT third-party risk management, incident reporting, operational resilience testing, third-party risk register).
3. **ISO/IEC 42001:2023** — Clauses 6.3 (change management), 8 (operational planning and control), 9 (performance evaluation), Annex A.6.2 (logging and traceability).
4. **PLD 2024/2853** — Article 7 (defectiveness criteria for AI systems), Article 10 (rebuttable presumptions of defect/causation when disclosure fails).

These regimes have **incompatible taxonomies** (DORA uses ICT risk vocabulary, ISO 42001 uses AIMS vocabulary, PLD uses product liability vocabulary) and **incompatible evidence formats** (DORA expects structured ICT incident logs, ISO 42001 expects audit logs, PLD expects technical documentation).

Existing GRC platforms solve this with **horizontal workflows**: one workflow per regime, with manual reconciliation. This creates three problems:
- **Evidence duplication**: the same AI decision must be captured 4 times in 4 formats
- **Reconciliation drift**: 4 independent captures of the same event diverge over time
- **Liability gaps**: when one regime's evidence is incomplete, the other regimes don't compensate (per PLD Art. 10, incomplete disclosure creates a presumption of defect)

## 2. The 4-layer model

We propose a **4-layer compliance model** in which every AI evidence artifact is simultaneously evaluated against the four regimes via independent layers, with **most-restrictive-wins** semantics:

```
                    ┌─────────────────────────────────────────────┐
                    │         AI EVIDENCE ARTIFACT (Sealed)       │
                    │  COSE_Sign1 + RFC 3161 TSA + tenant_id     │
                    └─────────────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
        ┌───────────▼────────────┐           ┌────────────▼────────────┐
        │ LAYER 1: Disclosure    │           │ LAYER 2: Provenance     │
        │ (EU AI Act Art. 50)   │           │ (EU AI Act Art. 12)    │
        │                        │           │                         │
        │ - Article 50(2) marker│           │ - Start/end time        │
        │ - Article 50(4) deep- │           │ - Input data hash       │
        │   fake label           │           │ - Decision reference    │
        │ - Article 50(5) first- │           │ - Hash chain prev       │
        │   interaction notice   │           │ - Policy version        │
        │ - AI system ID          │           │ - Natural person ID     │
        │ Status: Compiant/      │           │ Status: Logged (audit   │
        │   Partial/NonCompliant │           │   trail present)        │
        └────────────────────────┘           └─────────────────────────┘
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
        ┌───────────▼────────────┐           ┌────────────▼────────────┐
        │ LAYER 3: Watermark     │           │ LAYER 4: Operational    │
        │ (EU AI Act Art. 50(3)) │           │ Resilience (DORA Art.   │
        │                        │           │ 9-13 + ISO 42001 Cl. 8)  │
        │ - Kirchenbauer text    │           │                         │
        │   (z > 4.0 threshold)  │           │ - ICT incident log       │
        │ - AudioSeal audio       │           │ - Third-party risk       │
        │ - C2PA image/video      │           │   register               │
        │ - SCITT countersig      │           │ - Key rotation history  │
        │ Status: Present/        │           │ - Multi-tenant chain    │
        │   Absent/Adversarial-  │           │   isolation             │
        │   removed              │           │ - Append-only audit     │
        │                        │           │ Status: Compliant/      │
        │                        │           │   NonCompliant          │
        └────────────────────────┘           └─────────────────────────┘
```

### 2.1 Layer 1: Disclosure (EU AI Act Art. 50)

This layer ensures the artifact satisfies the **transparency obligations** under EU AI Act Article 50. At disclosure time, the system must:

- Mark AI-generated content in a machine-readable format (Art. 50(2))
- Label deepfakes as artificially generated (Art. 50(4))
- Provide a clear first-interaction notice (Art. 50(5))

The most-restrictive-wins semantic: if any of these three sub-requirements is `Partial` or `NonCompliant`, the overall layer status is the most-restrictive value (Compliant < Partial < NonCompliant < Unknown).

### 2.2 Layer 2: Provenance (EU AI Act Art. 12)

This layer captures the **event log** required by EU AI Act Art. 12 for high-risk AI systems. The mandatory fields per Art. 12(2):

- Start time and end time of each event
- Reference database consulted
- Input data hash
- Decision reference (id of the decision taken)
- Natural person ID (operator)
- Hash chain link to previous event (tamper evidence)

Plus the policy version active at the time (for audit trail of compliance evolution).

### 2.3 Layer 3: Watermark (EU AI Act Art. 50(3))

This layer provides the **machine-readable detection marker** required by EU AI Act Art. 50(3). We implement three detection modalities:

- **Kirchenbauer text watermark** (Kirchenbauer et al., 2023) — z-test on token distribution, threshold z > 4.0 (one-sided p < 0.00003). Status: Present / Absent / Adversarial-removed.
- **AudioSeal audio watermark** — speech-specific watermarking.
- **C2PA image/video** — Content Credentials manifest embedding.
- **SCITT countersignature** — offline-verifiable cryptographic receipt per IETF SCITT SCRAPI.

The most-restrictive semantic: if the watermark was removed (e.g., by the UnMarker attack [Zhang et al., 2024]), the layer status is `Adversarial-removed` and the artifact's overall compliance is downgraded.

### 2.4 Layer 4: Operational Resilience (DORA Art. 9-13 + ISO 42001 Cl. 8)

This layer captures the **operational evidence** required by both DORA (for financial sector AI systems) and ISO/IEC 42001 (for AIMS-certified organizations):

- **ICT incident log** (DORA Art. 10): every AI-related incident, with severity, root cause, resolution time
- **Third-party risk register** (DORA Art. 13): every AI vendor, with risk rating, contractual clauses, audit cadence
- **Key rotation history** (NIST SP 800-57 baseline, 90-day rotation, 30-day grace): every signing key, with creation, rotation, retirement timestamps
- **Multi-tenant chain isolation**: per-tenant chain_id namespace, ensuring one tenant's evidence cannot leak to another
- **Append-only audit**: the sealed artifact is append-only (no deletion, no mutation), with BLAKE3 hash chain integrity

## 3. Most-restrictive-wins semantics

When the four layer statuses are aggregated to an overall artifact compliance status, we apply **most-restrictive-wins**:

```
def overall_status(layers: List[LayerStatus]) -> Rollup:
    if any(l == NonCompliant for l in layers):
        return NonCompliant
    elif any(l == AdversarialRemoved for l in layers):
        return NonCompliant  # watermarks cannot be defended as crypto guarantees
    elif any(l == Partial for l in layers):
        return Partial
    elif any(l == Unknown for l in layers):
        return Unknown
    else:
        return Compliant
```

This is the **opposite** of "any layer passes" semantics used by most compliance tools. The justification: per PLD Art. 10, incomplete disclosure in any one regime creates a presumption of defect. Most-restrictive-wins is the only safe aggregation under product liability law.

## 4. Cryptographic binding

The four layers are bound into a single artifact via:

1. **COSE_Sign1** (RFC 9052) — payload is the canonical JSON serialization of all four layer statuses
2. **Ed25519** (RFC 8032) — signature key per tenant (multi-tenant isolation via org_id binding)
3. **RFC 3161 TSA** — trusted timestamp from a QTSP for legal-weight evidence (eIDAS Art. 42)
4. **PQC migration** (FIPS 204) — planned for TrustLayer v3.0 (target Q3 2026): ML-DSA-65 + Ed25519 composite signing

The artifact is **independently offline-verifiable**: any third party can verify all four layers without calling any Apohara endpoint, using only the public key and the QTSP's certificate.

## 5. Implementation status (TrustLayer v2.0)

| Layer | Component | Crate | Status |
|---|---|---|---|
| 1. Disclosure | EU AI Act Art. 50 mapper | `tl-policy/src/article_50.rs` (via ISO 42001 mapper) | ✅ shipped |
| 2. Provenance | 8-field Art. 12 evidence log | `tl-receipt/src/packet.rs` | ✅ shipped |
| 3. Watermark | Kirchenbauer + AudioSeal + C2PA + SCITT | `tl-watermark` + `tl-scitt` + `tl-evidence/src/tsa/` | ✅ shipped |
| 4. Operational | DORA evidence pack + NIST SP 800-57 key rotation + multi-tenant | `tl-policy/src/lib.rs` + `tl-evidence/src/key_rotation.rs` + ASGI middleware | ✅ shipped |
| Cryptographic binding | COSE_Sign1 + Ed25519 + RFC 3161 | `tl-evidence/src/cose.rs` + `tl-evidence/src/hmac_chain.rs` + `tl-evidence/src/tsa/` | ✅ shipped |
| EU Trust List validation | eIDAS Art. 67 + ETSI EN 319 421 | `tl-evidence/src/tsa/eu_trust_list.rs` | ✅ shipped |
| PQC migration | ML-DSA-65 + Ed25519 composite | planned v3.0 W1.1 | 🔄 in progress |

**Test coverage**: 88 Python tests + 585 Rust tests passing. 3 dedicated multi-tenant isolation tests in `tests/test_real_evidence_lookup.py` (acme/globex bidirectional).

## 6. Design partner program

We are launching a 5-partner pilot program (target Q3 2026, closes 2027-01-24) to validate the model with EU-regulated AI operators across financial services, healthcare, automotive (embedded AI), employment/HR tech, and biometric systems. Application: [`docs/design-partners/README.md`](design-partners/README.md).

## 7. Limitations and future work

- **PQC migration** (FIPS 204 ML-DSA-65) — target Q3 2026 (v3.0)
- **Cross-jurisdiction** (UK AI Bill, US EO 14110, China GenAI Measures) — target 2027 (v4.0)
- **PLD defect rebuttal pack** — auto-generation of evidence pack rebutting PLD Art. 10 presumption — target Q4 2026 (v3.0 W2.2)
- **Adversarial watermark defense** — UnMarker (Zhang et al., 2024) demonstrates 79% ASR against SynthID. Our watermark layer surfaces this as `Adversarial-removed` status rather than claiming cryptographic guarantee. Future work: probabilistic watermarking + multi-modal redundancy.
- **Scalability of cross-org federation** — SCITT federation (W5.2) addresses multi-org supply chain evidence; not yet validated at scale.

## 8. Conclusion

The 4-layer compliance model provides a single, cryptographically-sealed artifact that satisfies the most-restrictive-wins requirement across EU AI Act, DORA, ISO 42001, and PLD. TrustLayer v2.0 implements all four layers in production code under MIT/Apache-2.0. The PQC migration in v3.0 will make the cryptographic binding quantum-safe. The 5-partner pilot program will validate the model with real EU-regulated operators before the EU AI Act Art. 50 enforcement deadline of 2 August 2026.

---

## References (will be expanded in final paper)

- EU AI Act (Regulation 2024/1689) — https://eur-lex.europa.eu/eli/reg/2024/1689/oj
- DORA (Regulation 2022/2554) — enforced since 17 January 2025
- PLD 2024/2853 — entry into force 8 December 2024; transposition deadline 9 December 2026
- ISO/IEC 42001:2023 — published 18 December 2023; BS EN ISO/IEC 42001:2026 published 25 March 2026
- RFC 9052 — COSE_Sign1
- RFC 8032 — Ed25519
- RFC 3161 — Trusted Timestamping
- RFC 8785 — JSON Canonicalization Scheme (JCS)
- RFC 9943 — SCITT Architecture (April 2026)
- FIPS 204 — ML-DSA (Module-Lattice Digital Signature Algorithm, August 2024)
- COSE / SCITT SCRAPI drafts — IETF SCITT Working Group
- Kirchenbauer et al. (2023) — "A Watermark for Large Language Models"
- Zhang et al. (2024) — "UnMarker" — adversarial watermark removal
- Liang et al. (2026) — "When KV Cache Reuse Fails in Multi-Agent Systems" (arXiv:2601.08343)
- Suarez, P.M. (2026) — "INV-15: A Formal Safety Invariant for KV-Cache Reuse in Multi-Agent Judge Pipelines" (Zenodo DOI 10.5281/zenodo.20412807)

---

## Submission plan

1. **Q3 2026**: Post to arXiv (cs.CR primary, cs.AI secondary)
2. **Q3 2026**: Submit to USENIX Security 2027 workshop on AI compliance (deadline typically October)
3. **Q3 2026**: Submit to IEEE S&P 2027 workshop on AI governance
4. **Q4 2026**: DOI via Zenodo (cc-by-4.0)

Target venues where this paper fits:
- USENIX Security 2027 — AI/ML Security track
- IEEE S&P 2027 — Workshops (AI Governance)
- ACM CCS 2027 — AI Safety workshop
- NDSS 2027 — AI compliance track (if offered)

The paper is **engineering-driven** (implemented in production code, validated by tests and design partners), which differentiates it from purely-conceptual compliance frameworks.
