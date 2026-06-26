"""TrustLayer C2PA sealchain-core re-exports (W1.2 of v3.0 roadmap).

Per Plan v3.0 W1.2, this module unifies the C2PA implementation in
TrustLayer. Before W1.2, TrustLayer had two divergent C2PA paths:
1. apohara-sealchain-core: JUMBF with `apohara.*` custom assertion
   namespace, self-signed in v0.1, full 5-layer profile (HMAC + Ed25519
   + C2PA + RFC 3161 + Rekor v2).
2. c2pa-rs 0.36 subprocess mode in tl-watermark: standard C2PA via
   c2patool subprocess, no custom namespace.

After W1.2, there is ONE C2PA implementation: tl-sealchain-core
(re-exported from apohara-sealchain). The c2pa-rs 0.36 subprocess mode
in tl-watermark is deprecated (see W3.1 absorption roadmap).

This Python module is the configuration surface for the control plane:
trust profile selection, C2PA spec version, TSA/Rekor endpoints, and
named profile presets (offline-basic, transparency, legal-grade, full).
"""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# Trust profile identifier (matches apohara-sealchain
# packaging/trust-profile.json::id). Changing this is a breaking change
# for any C2PA-aware consumer.
TRUST_PROFILE_ID: str = "apohara-sealchain-5layer-v1"

# Human-readable profile name.
TRUST_PROFILE_NAME: str = (
    "Apohara Sealchain 5-Layer (HMAC + Ed25519 + C2PA + RFC 3161 + Rekor v2)"
)

# C2PA assertion namespace used by apohara-sealchain. Standard C2PA uses
# c2pa.* assertions; apohara-sealchain uses apohara.* as a custom namespace
# for TrustLayer-specific assertions (e.g., apohara.disclosure,
# apohara.threat_model).
C2PA_ASSERTION_PREFIX: str = "apohara."

# C2PA spec version targeted by sealchain 5-layer profile.
C2PA_SPEC_VERSION: str = "2.4"

# C2PA hash algorithm (FIPS 180-4).
C2PA_HASH_ALG: str = "SHA-256"

# C2PA signature algorithm (RFC 8032).
C2PA_SIG_ALG: str = "Ed25519"

# C2PA manifest store type (JUMBF per C2PA spec section 5).
C2PA_STORE_TYPE: str = "JUMBF"

# TrustLayer sealchain-core layer order (per apohara-sealchain
# docs/TRUST-PROFILE.md). Each layer verifies independently; a pass bar
# is required for each layer. If any layer's bar is not met, the seal
# is invalid.
LAYER_ORDER: list[str] = [
    "hmac",      # local integrity (HMAC-SHA-256)
    "ed25519",   # authorship (Ed25519 per RFC 8032)
    "c2pa",      # provenance (C2PA JUMBF manifest)
    "tsa",       # temporal attestation (RFC 3161 TSA)
    "rekor",     # transparency log (Sigstore Rekor v2)
]


class SealProfile(str, Enum):
    """Named C2PA trust profile per apohara-sealchain packaging/trust-profile.json.

    Each profile is a different combination of layers. Operators select
    a profile per TrustLayer deployment based on the audit/regulatory
    requirements.
    """
    OFFLINE_BASIC = "offline-basic"
    TRANSPARENCY = "transparency"
    LEGAL_GRADE = "legal-grade"
    FULL = "full"

    @property
    def layers(self) -> list[str]:
        """Get the list of layers required by this profile."""
        layer_map = {
            SealProfile.OFFLINE_BASIC: ["hmac", "ed25519"],
            SealProfile.TRANSPARENCY: ["ed25519", "rekor"],
            SealProfile.LEGAL_GRADE: ["ed25519", "tsa"],
            SealProfile.FULL: LAYER_ORDER,
        }
        return layer_map[self]

    @classmethod
    def from_name(cls, name: str) -> "Optional[SealProfile]":
        """Parse a profile from its name (case-insensitive). Returns
        None if the name doesn't match any known profile."""
        try:
            return cls(name.lower())
        except ValueError:
            return None


class SealchainCoreConfig(BaseModel):
    """TrustLayer sealchain-core configuration.

    Per apohara-sealchain packaging/trust-profile.json, with defaults
    suitable for EU AI Act + DORA compliance evidence (legal-grade
    profile, FreeTSA for dev, QTSP for prod).
    """
    profile: SealProfile = Field(
        default=SealProfile.LEGAL_GRADE,
        description="Named C2PA trust profile (offline-basic/transparency/legal-grade/full)",
    )
    c2pa_assertion_prefix: str = Field(
        default=C2PA_ASSERTION_PREFIX,
        description="C2PA assertion namespace (default: 'apohara.')",
    )
    c2pa_spec_version: str = Field(
        default=C2PA_SPEC_VERSION,
        description="C2PA spec version (default: '2.4')",
    )
    c2pa_hash_alg: str = Field(
        default=C2PA_HASH_ALG,
        description="C2PA hash algorithm (default: 'SHA-256')",
    )
    c2pa_sig_alg: str = Field(
        default=C2PA_SIG_ALG,
        description="C2PA signature algorithm (default: 'Ed25519')",
    )
    c2pa_store_type: str = Field(
        default=C2PA_STORE_TYPE,
        description="C2PA manifest store type (default: 'JUMBF')",
    )
    tsa_url: str = Field(
        default="https://freetsa.org/tsr",
        description="RFC 3161 TSA provider URL. For EU AI Act + DORA compliance, "
                   "MUST be a QTSP per eIDAS Article 42. FreeTSA is dev-only.",
    )
    rekor_url: str = Field(
        default="https://rekor.sigstore.dev",
        description="Sigstore Rekor v2 transparency log URL. "
                   "WARNING: URL changes on shard rotation per Sigstore docs.",
    )
