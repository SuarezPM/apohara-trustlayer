"""W10 Cross-jurisdiction compliance profiles.

Single-responsibility module: the data constant
`CROSS_JURISDICTION_PROFILES` (dict, one per jurisdiction:
EU AI Act, UK AI Bill, US EO 14110, PRC GenAI Measures).
Consumed by `assess_cross_jurisdiction()` in `app.compliance`."""

# ============================================================================


CROSS_JURISDICTION_PROFILES: dict[str, dict] = {
    "EU_AI_ACT": {
        "name": "EU AI Act",
        "jurisdiction": "European Union",
        "in_force_date": "2024-08-01",
        "key_articles": [
            "Art. 50(1)(a) — Visible disclosure",
            "Art. 50(2) — Machine-readable provenance",
            "Art. 50(3) — Watermark",
            "Art. 12 — Logging",
        ],
        "trustlayer_implementation": [
            "services/control_plane/app/middleware/article50.py (Art. 50 disclosure)",
            "services/control_plane/app/notary_production.py (Art. 50(2) COSE_Sign1)",
            "services/control_plane/app/watermark_strategy.py (Art. 50(3) z-test)",
        ],
        "compliance_status": "Compliant for text content (with token_ids); image/audio deferred to v1.1.1",
    },
    "UK_AI_BILL": {
        "name": "UK AI (Regulation) Bill",
        "jurisdiction": "United Kingdom",
        "in_force_date": "Royal assent expected Q3 2026",
        "key_articles": [
            "AI risk management (HM Treasury & DSIT AI White Paper March 2023)",
            "Frontier AI safety testing (AI Safety Institute)",
            "Voluntary transparency commitments",
        ],
        "trustlayer_implementation": [
            "Notary Layer (transparency by design)",
            "PLD rebuttable-presumption rebutter (also applies UK Consumer Rights Act 2015)",
            "Multi-tenant org_id (UK GDPR + Data Protection Act 2018)",
        ],
        "compliance_status": "Compliant (UK framework largely voluntary + DSIT AI principles)",
    },
    "US_EO_14110": {
        "name": "US Executive Order 14110 (Safe, Secure, Trustworthy AI)",
        "jurisdiction": "United States",
        "in_force_date": "2023-10-30 (revoked 2025-01; NIST AI RMF 1.0 + NIST AI 600-1 remain)",
        "key_articles": [
            "Section 4.1(a) — Safety standards (NIST AI 600-1)",
            "Section 7 — AI-generated content provenance (C2PA)",
            "Section 10 — Federal AI use (NIST RMF)",
        ],
        "trustlayer_implementation": [
            "NIST AI RMF 1.0 mapper (this file)",
            "NIST AI 600-1 GenAI Profile (12 risks)",
            "C2PA JUMBF manifest (apohara.* namespace assertions)",
        ],
        "compliance_status": "Compliant (NIST AI RMF 1.0 + 600-1 still authoritative)",
    },
    "CHINA_GENAI_MEASURES": {
        "name": "PRC Interim Measures for Management of Generative AI Services",
        "jurisdiction": "People's Republic of China",
        "in_force_date": "2023-08-15",
        "key_articles": [
            "Art. 4 — Pre-training data compliance (data sources, IP)",
            "Art. 7 — Content moderation + socialist core values",
            "Art. 9 — User labels + traceability",
        ],
        "trustlayer_implementation": [
            "C2PA JUMBF manifest (apohara.* provenance)",
            "BLAKE3 hash chain (data source fingerprints)",
            "Per-step Catalyst receipts (decisional traceability)",
        ],
        "compliance_status": "Partial — content moderation requires LLM-side alignment",
    },
}


# ============================================================================
# 5. W11 Federated SCITT evidence pattern (multi-org trust domains)
