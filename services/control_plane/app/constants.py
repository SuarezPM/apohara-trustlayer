"""Centralised magic constants for the Apohara TrustLayer control plane.

These values were previously scattered across `notary_production.py`,
`qes_adapter.py`, `watermark_strategy.py`, `schemas.py`, etc. as
inline literals. Centralising them:

1. Makes the codebase greppable: `grep "ACTALIS_TSA_URL" .` finds every
   reference instead of `grep "http://timestamp.actalis.com" .`
2. Enables env-var overrides in one place (production can set
   `TL_TSA_URL=https://timestamp.actalis.com:443` without forking).
3. Documents the regulatory references (ETSI EN 319 422, eIDAS Art. 41)
   inline so auditors can trace every OID back to its source standard.

Magic constants live here ONLY if they are:
- Cross-module (used in 2+ files), or
- Regulatory/standards-referenced (OIDs, thresholds), or
- Configurable in production (default URLs, vocab sizes)
"""

from __future__ import annotations

import os
from typing import Final

# ============================================================================
# Notary Service defaults
# ============================================================================

# Default QTSP endpoint. Actalis Italia (eIDAS-qualified per EU Trust
# List). Override via `TL_TSA_URL` env var. Used in:
# - notary_production.QTSPClient (default TSA URL)
# - qes_adapter.qtsp_qualified_for_jurisdiction (known qualified TSAs)
DEFAULT_TSA_URL: Final[str] = "http://timestamp.actalis.com"

# Default issuer DID for the NotaryService. The DID format follows
# the did:web method (apohara.org resolves to https://apohara.org/.well-known/did.json).
DEFAULT_ISSUER_DID: Final[str] = "did:web:apohara.org"

# Default key ID embedded in COSE_Sign1 protected headers.
DEFAULT_KEY_ID: Final[str] = "notary-key-1"

# Default org_id for single-tenant dev. Production uses the multi-tenant
# `X-Org-Id` header / JWT `org_id` claim.
DEFAULT_ORG_ID: Final[str] = "apohara"

# Default output directory for certificate PDFs (NotaryService).
DEFAULT_NOTARY_OUTPUT_DIR: Final[str] = "artifacts/notary"

# Default SQLite path for NotaryDB (dev only — production uses PG via Alembic).
DEFAULT_NOTARY_DB_PATH: Final[str] = "notary.db"


# ============================================================================
# LLM watermark defaults (Kirchenbauer et al. 2023)
# ============================================================================

# Green-list fraction γ per Kirchenbauer §3.1. Higher γ → more biased
# but easier to detect; lower γ → less visible watermark. Default 0.25.
DEFAULT_GAMMA: Final[float] = 0.25

# One-sided z-score threshold per Kirchenbauer §4 (z > 4.0 → p < 0.00003).
DEFAULT_Z_THRESHOLD: Final[float] = 4.0

# GPT-2/3/4 BPE vocabulary size (used as default when caller doesn't
# pass `vocab_size` to the watermark detector).
DEFAULT_BPE_VOCAB_SIZE: Final[int] = 50257


# ============================================================================
# eIDAS Art. 41 — Qualified Electronic Time-Stamp (QES) validation
# ============================================================================

# Per RFC 9162 §8.19 DER encoding. ETSI EN 319 422 v1.1.1 Annex B.
#
#   id-etsi-tsts
#       OBJECT IDENTIFIER ::= { itu-t(0) identified-organization(4)
#                                 etsi(0) id-tst-profile(19422) 1 }
#       -- 0.4.0.19422.1
#
#   id-etsi-tsts-EuQCompliance
#       OBJECT IDENTIFIER ::= { id-etsi-tsts 1 }
#       -- 0.4.0.19422.1.1
#
#   esi4-qtstStatement-1
#       QC-STATEMENT ::= { IDENTIFIED BY id-etsi-tsts-EuQCompliance }
#       -- "By inclusion of this statement the issuer claims that this
#       --  time-stamp token is issued as a qualified electronic
#       --  time-stamp according to the REGULATION (EU) No 910/2014."
OID_ETSI_TSTS: Final[str] = "0.4.0.19422.1"
OID_ES_I4_QTST_STATEMENT_1: Final[str] = "0.4.0.19422.1.1"

# Per ETSI EN 319 412-5 v2.6.1 Annex A — qcStatements profile for QTS.
OID_QC_TSTS: Final[str] = "0.4.0.194112.1.2"
OID_QC_TSTS_ARCH: Final[str] = "0.4.0.194112.1.3"

# Per RFC 3739 §3.2.6 — qcStatements X.509v3 extension OID.
OID_QC_STATEMENTS: Final[str] = "1.3.6.1.5.5.7.1.3"

# EU Trust List root CA fingerprints (SHA-1, hex, uppercase, no colons).
# Per Reg (EU) 2025/1929.
EU_TRUST_LIST_FINGERPRINTS: Final[dict[str, str]] = {
    "actalis_eu_qualified_ts_ca_g1": "23207BF8C3D6275E24F665B4D950CE0D3EC6AA43",
    "sectigo_eidas_qualified": "65396F09DFA1B2DA989C4B0D9C95E22708D0B99C",
    "digicert_eidas_qualified": "A03198AD1D4676E29EBC79C28F41CC75784B3B0F",
}


# ============================================================================
# Helpers — env-var overrides for production tuning
# ============================================================================


def env_tsa_url(default: str = DEFAULT_TSA_URL) -> str:
    """Resolve the TSA URL with `TL_TSA_URL` env-var override."""
    return os.environ.get("TL_TSA_URL", default)


def env_text_watermark_key() -> bytes:
    """Resolve the 32-byte watermark detection key.

    Returns the all-zero key in dev/test (deterministic). Production
    MUST set `TL_TEXT_WATERMARK_KEY` to a 32-byte secret per-deployment.
    """
    env = os.environ.get("TL_TEXT_WATERMARK_KEY", "")
    if env:
        b = env.encode("utf-8")[:32]
        return b + b"\x00" * (32 - len(b)) if len(b) < 32 else b
    return b"\x00" * 32


__all__ = [
    "DEFAULT_BPE_VOCAB_SIZE",
    "DEFAULT_GAMMA",
    "DEFAULT_ISSUER_DID",
    "DEFAULT_KEY_ID",
    "DEFAULT_NOTARY_DB_PATH",
    "DEFAULT_NOTARY_OUTPUT_DIR",
    "DEFAULT_ORG_ID",
    "DEFAULT_TSA_URL",
    "DEFAULT_Z_THRESHOLD",
    "EU_TRUST_LIST_FINGERPRINTS",
    "OID_ES_I4_QTST_STATEMENT_1",
    "OID_ETSI_TSTS",
    "OID_QC_STATEMENTS",
    "OID_QC_TSTS",
    "OID_QC_TSTS_ARCH",
    "env_text_watermark_key",
    "env_tsa_url",
]
