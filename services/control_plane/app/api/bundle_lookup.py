"""Concrete `BundleLookup` implementations.

Per Plan v1.2 Block 3 v1.1.0-US-12:
- `DbBundleLookup` queries the real `disclosure_records` table via
  SQLAlchemy 2.0 async. This is the production path; it's wired
  to `app.state.bundle_lookup` at startup.
- `InMemoryBundleLookup` is the test path (defined in evidence.py).

The returned dict schema matches `EvidenceBundleResponse` in
`app/schemas.py` so the API contract is identical between prod
and test.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

# BundleLookup is defined in app.api.evidence to keep the abstract
# interface alongside the route that uses it. Importing it at the
# top of this module would create a circular import (evidence
# imports _record_to_bundle_dict from here). We use a lazy import
# inside the class body instead.
from app.db.models import DisclosureRecord


class DbBundleLookup:
    """Real bundle lookup via the `disclosure_records` table.

    Per Plan v1.2 Block 3 v1.1.0-US-12 AC-2: when the id exists in
    the table, the response is the real bundle (cose_sign1_b64,
    tsa_token_b64, etc.) with status 200. When the id does not
    exist, returns None (the route maps this to 404).

    Note: v1.1.0.x-US-3 replaced the v1.1.0 sync `lookup()` method
    with the canonical async `lookup_async(bundle_id, session)`
    method. The async path is what the route uses in production
    (via `Depends(get_async_session_dep)`).

    This class deliberately does NOT inherit from BundleLookup
    (the abstract interface in app.api.evidence) to avoid the
    circular import. It implements the same surface contract
    (a `lookup_async` method) and is structurally compatible.
    """
    """Real bundle lookup via the `disclosure_records` table.

    Per Plan v1.2 Block 3 v1.1.0-US-12 AC-2: when the id exists in
    the table, the response is the real bundle (cose_sign1_b64,
    tsa_token_b64, etc.) with status 200. When the id does not
    exist, returns None (the route maps this to 404).

    Usage (in `main.py` startup):
        app.state.bundle_lookup = DbBundleLookup(session_factory)
    """

    def __init__(self, session_factory) -> None:
        """`session_factory` is an async SQLAlchemy sessionmaker
        (`async_sessionmaker[AsyncSession]`). Stored as a closure
        so each request gets a fresh session."""
        self._session_factory = session_factory

    def lookup(self, bundle_id: str) -> dict | None:
        """Synchronous wrapper for the abstract interface. The
        actual DB query is async; we run it via `asyncio.run` ONLY
        if no event loop is running (defensive). For the production
        path, callers should use `lookup_async` directly.

        For the v1.1.0 PR scope, we expose both: the sync `lookup`
        for compatibility with the abstract interface, and
        `lookup_async` as the canonical async path.
        """
        import asyncio
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            # No event loop running; safe to use asyncio.run.
            return asyncio.run(self.lookup_async(bundle_id))
        # Event loop is running; the sync wrapper cannot block.
        # The FastAPI route uses Depends() with the async path
        # directly; this branch is unreachable in production.
        raise RuntimeError(
            "DbBundleLookup.lookup called from an async context; "
            "use lookup_async() instead"
        )

    async def lookup_async(self, bundle_id: str) -> dict | None:
        """The canonical async path. Returns the bundle dict or None."""
        async with self._session_factory() as session:  # type: AsyncSession
            stmt = select(DisclosureRecord).where(DisclosureRecord.id == bundle_id)
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()
            if record is None:
                return None
            return _record_to_bundle_dict(record)


def _record_to_bundle_dict(record: DisclosureRecord) -> dict[str, Any]:
    """Convert a `DisclosureRecord` row to the evidence_bundle_v1 dict.

    Schema matches `EvidenceBundleResponse` in `app/schemas.py`:
    - `bundle_id` (str)
    - `created_at` (ISO 8601 str)
    - `disclosures` (list of dicts with the 4 compliance layers)
    - `key_chain` (dict with active_key_id + algorithm + rotated_at)
    - `signature` (dict with cose_sign1_b64 + row_hash)
    - `tsa_token` (dict or None)
    - `verification_instructions` (str)
    - `disclaimers` (list of str)
    """
    compliance_layers = record.compliance_layers or {}
    # created_at may be a datetime (from the real DB) or a string
    # (from the test adapter). Be defensive: convert to string if
    # it's a datetime, pass through otherwise.
    created_at_str = ""
    if record.created_at:
        if hasattr(record.created_at, "isoformat"):
            created_at_str = record.created_at.isoformat()
        else:
            created_at_str = str(record.created_at)
    return {
        "bundle_id": str(record.id),
        "created_at": created_at_str,
        "disclosures": [
            {
                "disclosure_id": str(record.id),
                "ai_system_id": record.ai_system_id,
                "compliance_rollup": record.compliance_rollup,
                "deployer": {
                    "name": record.deployer_name,
                    "country": record.deployer_country,
                    "sector": record.deployer_sector,
                },
                "compliance_layers": compliance_layers,
                "v1_disclaimers": [
                    "watermark layer: NotApplicable in v1.0",
                    "FreeTSA timestamp: dev-only, not forensically valid",
                ],
            }
        ],
        "key_chain": {
            "active_key_id": (record.row_hash or "")[:16],  # stable per-record identifier
            "algorithm": "Ed25519",
            "rotated_at": created_at_str,
        },
        "signature": {
            "cose_sign1_b64": record.cose_sign1_b64 or "",
            "row_hash": record.row_hash or "",
            "prev_hash": record.prev_hash or "",
        },
        "tsa_token": (
            {
                "tsa_token_b64": record.tsa_token_b64,
                "tsa_url": record.tsa_url,
            }
            if record.tsa_token_b64
            else None
        ),
        "verification_instructions": (
            "POST /v1/verify/provenance with the bundle_id. "
            "v1.1.0: real bundle retrieved from disclosure_records."
        ),
        "disclaimers": [
            "v1.1.0: this bundle was retrieved from disclosure_records; "
            "v1.0.5 synthetic disclaimers no longer apply.",
        ],
    }
