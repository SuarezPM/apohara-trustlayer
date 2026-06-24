"""Apohara TrustLayer Python SDK — full wheel with PyO3 bindings.

Per plan v3.1 §Vertical Slice Spec + Block 2: this is the heavy
SDK that includes the Rust extension (PyO3) for offline verification.

The light sibling (apohara-trustlayer-light) is HTTP-only for callers
that don't want the Rust dependency.

Boundary contract (Architect IC-2 strict):
- `sign_*` is NEVER exposed. Private key material never enters the
  Python process (plan v3.1 §Risks R10).
- `verify_*` and `hash_*` are exposed for offline verification.
"""

# Re-export the Rust extension as a submodule.
from apohara_trustlayer._apohara_trustlayer import (
    blake3_hash_hex,
    issuer_v1,
    verify_provenance_manifest,
    verify_receipt_offline,
    version,
)

__version__ = version()
__all__ = [
    "blake3_hash_hex",
    "issuer_v1",
    "verify_provenance_manifest",
    "verify_receipt_offline",
    "version",
    "__version__",
]
