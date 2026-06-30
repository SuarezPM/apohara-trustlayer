"""Async NotaryDB — P5.1: SQLite (dev, aiosqlite) → PostgreSQL (prod, asyncpg).

This module replaces the old sync SQLite-only `NotaryDB` (which used
the stdlib `sqlite3` driver and was unsuitable for production). The
public API surface is identical — `save_certificate`, `get_certificate`,
`list_certificates` — but all methods are now `async def` and the
backing store is a SQLAlchemy 2.0 `AsyncSession` over the engine from
`app.db.session`. The schema is defined declaratively in
`app.db.models.CertificateRecord`.

Dev fallback: when `database_url` starts with `sqlite+aiosqlite://` (the
pytest default) the engine still works the same way but creates an
in-memory or file-backed SQLite via aiosqlite. The migration script
`scripts/migrate_notary_sqlite_to_pg.py` reads from the legacy
`notary.db` (if it exists) and inserts rows here.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from app.db.models import CertificateRecord
from app.db.session import get_async_session

if TYPE_CHECKING:
    from collections.abc import Iterable


class NotaryDB:
    """Async NotaryDB — P5.1. Backed by SQLAlchemy 2.0 + Postgres (prod) /
    SQLite via aiosqlite (dev/CI). One row per notarized certificate.

    Schema mirrors the legacy `notary.db` SQLite table 1:1 — see
    `CertificateRecord` in `app.db.models` for the typed shape. The
    migration script (`scripts/migrate_notary_sqlite_to_pg.py`) reads
    rows from the old `notary.db` and inserts them here.
    """

    def __init__(self, db_path: str | None = None) -> None:
        """Construct a NotaryDB. `db_path` is preserved for back-compat
        with the old SQLite `NotaryDB(db_path=...)` constructor
        signature; when the underlying `database_url` is SQLite-typed,
        this is the on-disk file (used by the migration script's
        `from_sqlite()` helper); when it's Postgres-typed, it's ignored
        and the SQLAlchemy session engine is used directly.
        """
        self._db_path = db_path

    @staticmethod
    async def save_certificate(cert: dict[str, Any]) -> str:
        """Insert a certificate row. Returns the `cert_id`.

        The dict shape matches the legacy SQLite NotaryDB columns.
        Optional fields default to `None` (TSA / Rekor absent in
        degraded mode). `created_at` is filled by the server.
        """
        async for session in get_async_session():
            row = CertificateRecord(
                cert_id=cert["cert_id"],
                content_hash=cert["content_hash"],
                content_type=cert["content_type"],
                ai_system_id=cert["ai_system_id"],
                submitted_by=cert["submitted_by"],
                submitted_at=_parse_dt(cert["submitted_at"]),
                notarized_at=_parse_dt(cert["notarized_at"]),
                cose_sign1_b64=cert["cose_sign1_b64"],
                cwt_claims_json=cert["cwt_claims_json"],
                primary_key_fingerprint=cert.get("primary_key_fingerprint"),
                tsa_token_b64=cert.get("tsa_token_b64"),
                tsa_url=cert.get("tsa_url"),
                tsa_fetched_at=(
                    _parse_dt(cert["tsa_fetched_at"]) if cert.get("tsa_fetched_at") else None
                ),
                rekor_entry_id=cert.get("rekor_entry_id"),
                rekor_log_id=cert.get("rekor_log_id"),
                rekor_entry_json=cert.get("rekor_entry_json"),
                pdf_path=cert.get("pdf_path"),
                qr_payload=cert.get("qr_payload"),
                metadata_json=cert.get("metadata_json"),
            )
            session.add(row)
            await session.commit()
            return row.cert_id
        return None

    @staticmethod
    async def get_certificate(cert_id: str) -> dict[str, Any] | None:
        """Look up a certificate by id. Returns the row as a dict
        (matching the legacy SQLite NotaryDB.get_certificate shape) or
        `None` when the cert does not exist.
        """
        async for session in get_async_session():
            stmt = select(CertificateRecord).where(CertificateRecord.cert_id == cert_id)
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()
            return _row_to_dict(row) if row is not None else None
        return None

    @staticmethod
    async def list_certificates(
        submitted_by: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List recent certificates, optionally filtered by submitter
        org_id. Newest first. `limit` caps the result count (matches
        the legacy `LIMIT 100` default).
        """
        async for session in get_async_session():
            stmt = select(CertificateRecord).order_by(CertificateRecord.notarized_at.desc())
            if submitted_by is not None:
                stmt = stmt.where(CertificateRecord.submitted_by == submitted_by)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            rows: Iterable[CertificateRecord] = result.scalars().all()
            return [_row_to_dict(r) for r in rows]
        return None


def _row_to_dict(row: CertificateRecord) -> dict[str, Any]:
    """Convert a CertificateRecord ORM instance to the legacy SQLite
    dict shape that `verification_page.py` and `notary/service.py`
    already consume (no behavioral change at the boundary).
    """
    return {
        "cert_id": row.cert_id,
        "content_hash": row.content_hash,
        "content_type": row.content_type,
        "ai_system_id": row.ai_system_id,
        "submitted_by": row.submitted_by,
        "submitted_at": row.submitted_at.isoformat(),
        "notarized_at": row.notarized_at.isoformat(),
        "cose_sign1_b64": row.cose_sign1_b64,
        "cwt_claims_json": row.cwt_claims_json,
        "primary_key_fingerprint": row.primary_key_fingerprint,
        "tsa_token_b64": row.tsa_token_b64,
        "tsa_url": row.tsa_url,
        "tsa_fetched_at": (row.tsa_fetched_at.isoformat() if row.tsa_fetched_at else None),
        "rekor_entry_id": row.rekor_entry_id,
        "rekor_log_id": row.rekor_log_id,
        "rekor_entry_json": row.rekor_entry_json,
        "pdf_path": row.pdf_path,
        "qr_payload": row.qr_payload,
        "metadata_json": row.metadata_json,
    }


def _parse_dt(value: str | datetime) -> datetime:
    """Parse an ISO-8601 timestamp (or pass through a `datetime`).

    The legacy SQLite NotaryDB stored timestamps as `datetime.now()`
    objects; the new schema uses `DateTime(timezone=False)` (naive UTC)
    so the wire format must remain ISO-8601 in UTC and the value must
    be tz-stripped regardless of whether the caller passes a string or
    an offset-aware `datetime`. Postgres rejects `INSERT` with a
    offset-aware datetime into a `TIMESTAMP WITHOUT TIME ZONE` column
    (SQLSTATE 22007 / asyncpg DataError).
    """
    if isinstance(value, datetime):
        return value.replace(tzinfo=None)
    # Parse ISO-8601; tolerate trailing 'Z' (UTC).
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
