"""ISO/IEC 42001:2023 Annex A - 38 reference control objectives.

Single-responsibility module: the data constant
`ISO_42001_ANNEX_A_CONTROLS` (list of dicts, one per Annex A control).
Consumed by `assess_iso_42001_aims()` in `app.compliance`."""

ISO_42001_ANNEX_A_CONTROLS: list[dict] = [
    # A.2 Policies related to AI (3 controls)
    {
        "control_id": "A.2.1",
        "area": "Policies related to AI",
        "name": "AI policy",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md", "TRUSTLAYER_ADR.md"],
        "notes": (
            "TrustLayer's 4-layer compliance model is the AI policy. "
            "Per ISO 42001 §6.2: top-level AI policy for the organization."
        ),
    },
    {
        "control_id": "A.2.2",
        "area": "Policies related to AI",
        "name": "Alignment with other policies",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["TRUSTLAYER_ADR.md", "crates/tl-argus/src/audit_event.rs"],
        "notes": (
            "AI policy aligned with security, privacy, and data policies. "
            "AuditEvent GDPR-safe fingerprints + ARGUS slop firewall."
        ),
    },
    {
        "control_id": "A.2.3",
        "area": "Policies related to AI",
        "name": "Policy review",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["docs/ROADMAP_v3.md"],
        "notes": (
            "Reviewed at each major release (v1.0, v1.1, v1.2, v2.0, v3.0, "
            "W7). Quarterly cadence planned W6.5."
        ),
    },
    # A.3 Internal organization (2 controls)
    {
        "control_id": "A.3.1",
        "area": "Internal organization",
        "name": "AI roles and responsibilities",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md#bus-factor"],
        "notes": (
            "Single-engineer (bus factor 1) today. Co-maintainer target "
            "2026-08-06 per Plan v1.1 R-NEW-7."
        ),
    },
    {
        "control_id": "A.3.2",
        "area": "Internal organization",
        "name": "Reporting concerns",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/themis-orchestrator/src/honesty_auditor.rs"],
        "notes": "Honesty auditor + ethics escalation per 9-agent court.",
    },
    # A.4 Resources for AI systems (5 controls)
    {
        "control_id": "A.4.1",
        "area": "Resources for AI systems",
        "name": "Data resources",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-evidence/src/hmac_chain.rs"],
        "notes": "BLAKE3 hash chain captures every data fingerprint.",
    },
    {
        "control_id": "A.4.2",
        "area": "Resources for AI systems",
        "name": "Tooling resources",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md#repository-layout", "Cargo.toml", "pyproject.toml"],
        "notes": "Full dependency manifest committed + reproducible builds.",
    },
    {
        "control_id": "A.4.3",
        "area": "Resources for AI systems",
        "name": "Compute resources",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["docs/SERIES_A_DECK.md"],
        "notes": (
            "Local dev: Apple silicon / Linux. Production: AWS + Azure "
            "confidential VMs (W6.5)."
        ),
    },
    {
        "control_id": "A.4.4",
        "area": "Resources for AI systems",
        "name": "Human resources",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["docs/SERIES_A_DECK.md"],
        "notes": "Bus factor 1 today. Hiring plan in Series A deck.",
    },
    {
        "control_id": "A.4.5",
        "area": "Resources for AI systems",
        "name": "System resources (HW/SW)",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/apohara-agentguard/src/sandbox/"],
        "notes": (
            "apohara-agentguard sandboxing + cargo deny license/advisory "
            "hygiene."
        ),
    },
    # A.5 Assessing impacts of AI systems (4 controls)
    {
        "control_id": "A.5.1",
        "area": "Assessing impacts of AI systems",
        "name": "AI impact assessment process",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/api/pld.py"],
        "notes": (
            "POST /v1/pld/disclosure/response + /v1/pld/rebuttal implement "
            "Art. 9 + Art. 10 impact assessment."
        ),
    },
    {
        "control_id": "A.5.2",
        "area": "Assessing impacts of AI systems",
        "name": "Documentation of AI impacts",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/api/pld.py"],
        "notes": "All impact assessments return machine-readable evidence bundle.",
    },
    {
        "control_id": "A.5.3",
        "area": "Assessing impacts of AI systems",
        "name": "Impacts on individuals",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/api/pld.py", "crates/tl-argus/src/"],
        "notes": "apohara-argus PII scrubbing + impact category mapping per Art. 27.",
    },
    {
        "control_id": "A.5.4",
        "area": "Assessing impacts of AI systems",
        "name": "Societal impacts",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["docs/SERIES_A_DECK.md", "docs/8th-auditor-research-2026-06-26.md"],
        "notes": "Societal impact assessment scaffolded; full methodology W6.4.",
    },
    # A.6 AI system life cycle (9 controls)
    {
        "control_id": "A.6.1.1",
        "area": "AI system life cycle",
        "name": "Objectives for AI system life cycle",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md#repository-layout"],
        "notes": (
            "15 Rust crates covering chain → evidence → receipt → gate → "
            "aibom → compliance → orchestrator."
        ),
    },
    {
        "control_id": "A.6.1.2",
        "area": "AI system life cycle",
        "name": "Processes for AI lifecycle",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md", "docs/"],
        "notes": "Quickstart + runbooks in docs/.",
    },
    {
        "control_id": "A.6.2.1",
        "area": "AI system life cycle",
        "name": "Requirements specification",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-receipt/src/packet.rs"],
        "notes": "8-field Art. 12 evidence packet (per AC-22).",
    },
    {
        "control_id": "A.6.2.2",
        "area": "AI system life cycle",
        "name": "Design and development documentation",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["docs/pqc-design.md", "TRUSTLAYER_ADR.md"],
        "notes": "ADR-001 through ADR-020+ committed.",
    },
    {
        "control_id": "A.6.2.3",
        "area": "AI system life cycle",
        "name": "Verification and validation",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-evidence/src/cms_verify.rs", "tests/"],
        "notes": "Full CMS signature verification per RFC 5652 §5.6.",
    },
    {
        "control_id": "A.6.2.4",
        "area": "AI system life cycle",
        "name": "Deployment procedures",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["Makefile", ".github/workflows/ci.yml"],
        "notes": "CI/CD pipeline + `make demo-full` vertical slice.",
    },
    {
        "control_id": "A.6.2.5",
        "area": "AI system life cycle",
        "name": "Operation and monitoring",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/api/health.py"],
        "notes": "FastAPI /health + structlog monitoring + cost drift detection.",
    },
    {
        "control_id": "A.6.2.6",
        "area": "AI system life cycle",
        "name": "AI system logging and traceability",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": [
            "crates/tl-receipt/src/packet.rs",
            "crates/tl-evidence/src/hmac_chain.rs",
            "services/control_plane/app/middleware/article50.py",
        ],
        "notes": "BLAKE3 hash chain + 8-field Art. 12 evidence log + Art. 50 disclosure.",
    },
    {
        "control_id": "A.6.2.7",
        "area": "AI system life cycle",
        "name": "Technical documentation",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md", "docs/"],
        "notes": "Architecture docs + ADR + runbooks in docs/.",
    },
    # A.7 Data for AI systems (5 controls)
    {
        "control_id": "A.7.1",
        "area": "Data for AI systems",
        "name": "Data management",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-evidence/src/hmac_chain.rs"],
        "notes": "BLAKE3 hash-chained audit log of all data.",
    },
    {
        "control_id": "A.7.2",
        "area": "Data for AI systems",
        "name": "Data acquisition",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/apohara-agentguard/src/credential_scrubber.rs"],
        "notes": "apohara-aegis credential scrub on data ingestion.",
    },
    {
        "control_id": "A.7.3",
        "area": "Data for AI systems",
        "name": "Data quality",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["crates/tl-evidence/src/hmac_chain.rs"],
        "notes": "Hash-chained provenance captured; statistical quality metrics planned.",
    },
    {
        "control_id": "A.7.4",
        "area": "Data for AI systems",
        "name": "Data provenance",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-evidence/src/hmac_chain.rs", "services/control_plane/app/domain/chains.py"],
        "notes": "Every receipt has a content_hash + BLAKE3 chain link.",
    },
    {
        "control_id": "A.7.5",
        "area": "Data for AI systems",
        "name": "Data preparation",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/watermark_strategy.py"],
        "notes": "Tokenization keys pinned (TL_TEXT_WATERMARK_KEY).",
    },
    # A.8 Information for interested parties (4 controls)
    {
        "control_id": "A.8.1",
        "area": "Information for interested parties",
        "name": "System documentation for users",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md", "docs/"],
        "notes": "Quickstart, Architecture, Compliance map.",
    },
    {
        "control_id": "A.8.2",
        "area": "Information for interested parties",
        "name": "External reporting",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["audit_artifacts/"],
        "notes": "8+ auditor reports in audit_artifacts/.",
    },
    {
        "control_id": "A.8.3",
        "area": "Information for interested parties",
        "name": "Incident communication",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["services/control_plane/app/api/pld.py"],
        "notes": "PLD disclosure order response + DORA ICT incident log scaffold.",
    },
    {
        "control_id": "A.8.4",
        "area": "Information for interested parties",
        "name": "Information to interested parties",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/api/pld.py", "services/control_plane/app/notary_production.py"],
        "notes": "PLD rebuttal pack + Notary verify URL.",
    },
    # A.9 Use of AI systems (3 controls)
    {
        "control_id": "A.9.1",
        "area": "Use of AI systems",
        "name": "Processes for responsible use",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["crates/tl-gate/", "services/control_plane/app/catalyst_production.py"],
        "notes": "BAAAR post-LLM gate + Catalyst per-step receipts.",
    },
    {
        "control_id": "A.9.2",
        "area": "Use of AI systems",
        "name": "Objectives for responsible use",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md", "docs/SERIES_A_DECK.md"],
        "notes": "3-layer GTM (Discovery, Notary, Substrate).",
    },
    {
        "control_id": "A.9.3",
        "area": "Use of AI systems",
        "name": "Intended use of AI systems",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["README.md#who-is-this-for"],
        "notes": "3 explicit `not for` exclusions + ICP gate.",
    },
    {
        "control_id": "A.9.4",
        "area": "Use of AI systems",
        "name": "AI system performance evaluation",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["crates/tl-frontend/src/cost_drift.rs"],
        "notes": "Cost drift detection implemented. Full ML metrics planned.",
    },
    # A.10 Third-party and customer relationships (3 controls)
    {
        "control_id": "A.10.1",
        "area": "Third-party and customer relationships",
        "name": "Allocating responsibilities",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/domain/disclosure_service.py"],
        "notes": "Deployer + provider + customer fields in DisclosureGenerateRequest.",
    },
    {
        "control_id": "A.10.2",
        "area": "Third-party and customer relationships",
        "name": "Suppliers",
        "applicable": True,
        "implementation_status": "partial",
        "evidence_refs": ["docs/SERIES_A_DECK.md"],
        "notes": "Actalis (Italy / QTSP), Sectigo (backup), Digicert (US).",
    },
    {
        "control_id": "A.10.3",
        "area": "Third-party and customer relationships",
        "name": "Customers",
        "applicable": True,
        "implementation_status": "implemented",
        "evidence_refs": ["services/control_plane/app/notary_production.py", "services/control_plane/app/verification_page.py"],
        "notes": "Notary certificate + public verify URL.",
    },
]


