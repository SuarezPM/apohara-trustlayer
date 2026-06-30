"""DORA Evidence Pack - 7 deliverable checks (Regulation (EU) 2022/2554).

Single-responsibility module: the data constant
`DORA_EVIDENCE_CHECKS` (list of dicts, one per Art. 9-21 check).
Consumed by `assess_dora_evidence_pack()` in `app.compliance`."""

# ============================================================================

DORA_EVIDENCE_CHECKS: list[dict] = [
    {
        "check_id": "DORA-01",
        "article": "Art. 9",
        "name": "ICT risk management framework",
        "description": (
            "Financial entities must maintain an ICT risk management "
            "framework with strategies, policies, procedures, and "
            "protocols."
        ),
        "trustlayer_evidence": [
            "ISO/IEC 42001 mapper (this file)",
            "TRUSTLAYER_ADR.md (architecture decisions)",
            "BLAKE3 hash chain (data integrity)",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-02",
        "article": "Art. 10",
        "name": "ICT incident reporting",
        "description": (
            "Financial entities must report major ICT-related incidents "
            "to competent authorities within strict timelines."
        ),
        "trustlayer_evidence": [
            "AuditEvent 16-field Art. 12 log (crates/tl-argus)",
            "BLAKE3 hash chain integrity for incident records",
            "PLD disclosure order response (services/control_plane/app/api/pld.py)",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-03",
        "article": "Art. 11",
        "name": "Digital operational resilience testing",
        "description": (
            "Annual DOR testing programme covering vulnerability "
            "assessments, penetration testing, and scenario-based tests."
        ),
        "trustlayer_evidence": [
            "1,287 tests passing (1,137 Rust + 113 Python + 21 TS + 16 Go)",
            "End-to-end smoke test in audit_artifacts/smoke_test/",
            "PLD rebuttal pack validation",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-04",
        "article": "Art. 12",
        "name": "ICT third-party risk management",
        "description": (
            "Financial entities must manage third-party ICT risk "
            "(supply chain, vendor selection, exit strategies)."
        ),
        "trustlayer_evidence": [
            "Actalis Italia as primary QTSP (eIDAS Art. 41 presumption)",
            "Sectigo as backup QTSP (US fallback)",
            "Supplier register in ISO 42001 A.10.2",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-05",
        "article": "Art. 13",
        "name": "Critical ICT third-party providers (CTPPs)",
        "description": (
            "Designation of critical ICT third-party providers and "
            "oversight framework (ESAs joint framework)."
        ),
        "trustlayer_evidence": [
            "Notary Layer with SCITT counter-signatures (third-party-anchored evidence)",
            "PLD rebuttable-presumption rebutter (defect-anchored liability)",
            "Federated SCITT evidence (W11) for cross-org trust domains",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-06",
        "article": "Art. 19-20",
        "name": "Information register and reporting obligations",
        "description": (
            "Financial entities must maintain a register of information "
            "on all contractual arrangements with ICT third-party providers."
        ),
        "trustlayer_evidence": [
            "NotaryDB (SQLite, append-only audit table)",
            "BLAKE3 hash chain (immutable contract fingerprints)",
            "PLD rebuttal pack (court-defensible evidence bundle)",
        ],
        "applicable_to_trustlayer": True,
    },
    {
        "check_id": "DORA-07",
        "article": "Art. 21",
        "name": "Cooperation with competent authorities",
        "description": (
            "Financial entities must cooperate with competent authorities "
            "and ESAs, including information disclosure on demand."
        ),
        "trustlayer_evidence": [
            "Public verify endpoint (services/control_plane/app/verification_page.py)",
            "PDF certificate export (reportlab)",
            "SCITT transparency log inclusion proofs",
        ],
        "applicable_to_trustlayer": True,
    },
]


# ============================================================================
# 4. W10 Cross-jurisdiction mappers (UK AI Bill, US EO 14110, China Measures)
