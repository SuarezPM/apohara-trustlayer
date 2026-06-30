"""Backwards-compat shim — re-exports from `app.compliance` split modules.

W9.2 refactor moved the 968-line god file into 5 focused submodules
under `app.compliance.*`. This shim preserves the legacy import
path for 9.1-era callers (api/dora.py, tests).
"""

from app.compliance import (
    CROSS_JURISDICTION_PROFILES,
    DORA_EVIDENCE_CHECKS,
    ISO_42001_ANNEX_A_CONTROLS,
    NIST_AI_600_1_RISKS,
    NIST_AI_RMF_FUNCTIONS,
    assess_cross_jurisdiction,
    assess_dora_evidence_pack,
    assess_iso_42001_aims,
    assess_nist_ai_600_1_risks,
    assess_nist_ai_rmf,
    federate_scitt_evidence,
)

__all__ = [
    "CROSS_JURISDICTION_PROFILES",
    "DORA_EVIDENCE_CHECKS",
    "ISO_42001_ANNEX_A_CONTROLS",
    "NIST_AI_600_1_RISKS",
    "NIST_AI_RMF_FUNCTIONS",
    "assess_cross_jurisdiction",
    "assess_dora_evidence_pack",
    "assess_iso_42001_aims",
    "assess_nist_ai_600_1_risks",
    "assess_nist_ai_rmf",
    "federate_scitt_evidence",
]
