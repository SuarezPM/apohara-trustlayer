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

# Green-list fraction γ per Kirchenbauer §3.1. Higher γ → more biased  # noqa: RUF003
# but easier to detect; lower γ → less visible watermark. Default 0.25.  # noqa: RUF003
DEFAULT_GAMMA: Final[float] = 0.25

# Number of bytes used for both the watermark detection key and the SHA-256 /
# BLAKE3 hash output. Matches the BLAKE3 default output size; the watermark
# key is padded/truncated to this length. Per Kirchenbauer §3.1 and RFC 9162
# §2.1 (SHA-256 Merkle tree leaf hash). Used in:
# - watermark_strategy._normalise_key (key32 padding)
# - watermark_strategy._score_tokens / _bias_logits
# - domain.disclosure_service.assess_4_layers
# - notary.service.detect_watermark
# - rfc9162_verifier.verify_inclusion / _parse_signed_tree_head
# - constants.env_text_watermark_key
HASH_OUTPUT_BYTES: Final[int] = 32

# Maximum size of the internal `internal_evidence` payload accepted by the
# RFC 9162 inclusion verifier. Above this we reject to bound decode cost and
# avoid feeding multi-MB blobs into hashlib.sha256. Per rfc9162_verifier.py.
MAX_INTERNAL_EVIDENCE_BYTES: Final[int] = 1024

# Maximum characters shown in the COSE_Sign1 preview row of the notary
# certificate PDF (truncates with ellipsis if longer).
COSE_PREVIEW_CHARS: Final[int] = 80

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
# ISO/IEC 23894:2023 risk register — band thresholds + field validation
# ============================================================================

# Residual-risk score → band mapping (5x5 heatmap, post-control):
#   >= 16 → critical (top-right of 5x5 matrix)
#   >=  9 → high
#   >=  4 → medium
#   <   4 → low
# Per ISO/IEC 23894:2023 Clause 6.4 + NIST AI RMF 1.0 severity tiers.
RESIDUAL_BAND_CRITICAL: Final[int] = 16
RESIDUAL_BAND_HIGH: Final[int] = 9
RESIDUAL_BAND_MEDIUM: Final[int] = 4

# Per-field validation range for ISO 23894 Risk dataclass (1-5 likelihood /
# impact scale per Clause 6.3).
RISK_LIKELIHOOD_MAX: Final[int] = 5
RISK_IMPACT_MAX: Final[int] = 5


# ============================================================================
# Regulatory deadline warning threshold (W2 PLD compliance endpoints)
# ============================================================================

# If days remaining until a regulatory deadline is below this, the
# /v1/pld/deadline endpoint returns `"status": "urgent"`. Operators use
# this to escalate pacing before the EU AI Act / PLD transposition dates.
REGULATORY_URGENT_DAYS: Final[int] = 30


# ============================================================================
# Adversarial scaffold minimum defense-layer threshold
# ============================================================================

# Minimum number of independent defense-layer audit entries required for
# an AD-* / AML.T*-* scenario check to be considered PASS. Two layers is
# the engineering baseline (defense-in-depth per commit c11ccc9).
MIN_DEFENSE_LAYERS_REQUIRED: Final[int] = 2


# ============================================================================
# COSE / CMS structural-validation thresholds (verification page UI)
# ============================================================================

# Minimum decoded-byte length for a COSE_Sign1 envelope to be considered
# structurally valid (RFC 9052 §4.4 array must contain >= protected + payload).
COSE_SIGN1_MIN_BYTES: Final[int] = 2

# DER SEQUENCE identifier (X.690 §8.1). The first byte of a valid CMS
# ContentInfo (RFC 5652 §3) must be 0x30. Used as a quick structural check
# for the TSA token in the verification page.
ASN1_SEQUENCE_TAG: Final[int] = 0x30


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
        b = env.encode("utf-8")[:HASH_OUTPUT_BYTES]
        return b + b"\x00" * (HASH_OUTPUT_BYTES - len(b)) if len(b) < HASH_OUTPUT_BYTES else b
    return b"\x00" * HASH_OUTPUT_BYTES


__all__ = [
    "ASN1_SEQUENCE_TAG",
    "COSE_PREVIEW_CHARS",
    "COSE_SIGN1_MIN_BYTES",
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
    "HASH_OUTPUT_BYTES",
    "MAX_INTERNAL_EVIDENCE_BYTES",
    "MIN_DEFENSE_LAYERS_REQUIRED",
    "OID_ES_I4_QTST_STATEMENT_1",
    "OID_ETSI_TSTS",
    "OID_QC_STATEMENTS",
    "OID_QC_TSTS",
    "OID_QC_TSTS_ARCH",
    "REGULATORY_URGENT_DAYS",
    "RESIDUAL_BAND_CRITICAL",
    "RESIDUAL_BAND_HIGH",
    "RESIDUAL_BAND_MEDIUM",
    "RISK_IMPACT_MAX",
    "RISK_LIKELIHOOD_MAX",
    "env_text_watermark_key",
    "env_tsa_url",
]
