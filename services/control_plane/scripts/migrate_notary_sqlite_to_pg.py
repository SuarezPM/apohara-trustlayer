"""Migration script: legacy `notary.db` (SQLite) → SQLAlchemy `certificates` table (P5.1).

Reads every row from the legacy SQLite `notary.db` (the schema used by
the pre-P5.1 `NotaryDB` class in `app/notary/db.py`) and inserts each
row into the new `certificates` SQLAlchemy table via the new async
`NotaryDB`. Safe to run multiple times — rows whose `cert_id` already
exists are SKIPPED (idempotent). Run from the repo root:

    PYTHONPATH=services/control_plane \
      uv run --no-project --with pydantic --with 'pydantic[email]' \
              --with pydantic-settings --with sqlalchemy --with asyncpg \
              --with python-dotenv \
      python services/control_plane/scripts/migrate_notary_sqlite_to_pg.py

The script requires the destination Postgres to already exist (run
the dev-fallback DDL in `main.py` first, or the Alembic migration
`0003_create_certificates.py` in production). The legacy `notary.db`
must be readable (default path: `./notary.db` in the repo root).

The migration is the one-way sync point for the P5.1 transition; once
the new SQLAlchemy table is populated and the application is running
against Postgres, the legacy `notary.db` can be archived/deleted.
"""

from __future__ import annotations

import asyncio
import sqlite3
import sys
from pathlib import Path
from typing import Any

# Allow `python services/control_plane/scripts/migrate_notary_sqlite_to_pg.py`
# from the repo root without setting PYTHONPATH manually.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "services" / "control_plane"))


from app.config import get_settings  # noqa: E402
from app.db.models import Base, CertificateRecord  # noqa: E402
from app.db.session import _get_engine, _get_sessionmaker  # noqa: E402
from app.notary.db import NotaryDB, _row_to_dict  # noqa: E402
from sqlalchemy import select  # noqa: E402

# Mirror of the legacy SQLite `certificates` table column order
# (see app/notary/db.py::SCHEMA). Must match the SELECT below.
_LEGACY_COLUMNS = [
    "cert_id",
    "content_hash",
    "content_type",
    "ai_system_id",
    "submitted_by",
    "submitted_at",
    "notarized_at",
    "cose_sign1_b64",
    "cwt_claims_json",
    "tsa_token_b64",
    "tsa_url",
    "tsa_fetched_at",
    "rekor_entry_id",
    "rekor_log_id",
    "pdf_path",
    "qr_payload",
    "metadata_json",
    "primary_key_fingerprint",
]


def _legacy_row_to_dict(row: tuple) -> dict[str, Any]:
    """Convert a legacy SQLite `certificates` row tuple to the
    `CertificateRecord`-shaped dict that `NotaryDB.save_certificate`
    consumes (P5.1: single-dict API).
    """
    out = dict(zip(_LEGACY_COLUMNS, row))
    # Parse the legacy timestamp strings to `datetime` so the SQLAlchemy
    # `DateTime(timezone=False)` columns receive naive-UTC values.
    from datetime import datetime as _dt
    for key in ("submitted_at", "notarized_at", "tsa_fetched_at"):
        if out.get(key):
            # Legacy rows are stored as 'YYYY-MM-DD HH:MM:SS.ffffff'
            # or ISO-8601 depending on sqlite3 version. Accept both.
            try:
                out[key] = _dt.fromisoformat(out[key])
            except ValueError:
                out[key] = _dt.strptime(out[key], "%Y-%m-%d %H:%M:%S.%f")
        else:
            out[key] = None
    return out


def _read_legacy(sqlite_path: Path) -> list[dict[str, Any]]:
    """Open the legacy SQLite DB read-only and yield all certificate rows."""
    if not sqlite_path.exists():
        print(f"[migrate] no legacy DB at {sqlite_path} — nothing to migrate")
        return []
    conn = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='certificates'")
        if cur.fetchone() is None:
            print(f"[migrate] {sqlite_path} has no `certificates` table — nothing to migrate")
            return []
        cur.execute(f"SELECT {', '.join(_LEGACY_COLUMNS)} FROM certificates ORDER BY notarized_at")
        rows = cur.fetchall()
        print(f"[migrate] read {len(rows)} rows from {sqlite_path}")
        return [_legacy_row_to_dict(r) for r in rows]
    finally:
        conn.close()


async def _already_present_ids(sessionmaker) -> set[str]:
    """Return the set of `cert_id` already in the new table so the
    migration is idempotent (skips rows that have already been copied).
    """
    async with sessionmaker() as session:
        stmt = select(CertificateRecord.cert_id)
        result = await session.execute(stmt)
        return {row[0] for row in result.all()}


async def migrate() -> int:
    """Run the migration. Returns the number of rows inserted."""
    settings = get_settings()
    legacy_path = Path(settings.notary_db_path)
    if not legacy_path.is_absolute():
        legacy_path = _REPO_ROOT / legacy_path

    legacy_rows = _read_legacy(legacy_path)
    if not legacy_rows:
        return 0

    # P5.1.1 production path: Alembic 0003_create_certificates.py
    # runs this DDL. The dev fallback is in `main.py` lifespan; we
    # ALSO run it here so the migration script is self-contained.
    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(
                bind=sync_conn, tables=[CertificateRecord.__table__]
            )
        )

    sessionmaker = _get_sessionmaker()
    already = await _already_present_ids(sessionmaker)
    print(f"[migrate] {len(already)} rows already in destination")

    db = NotaryDB(db_path=str(legacy_path))
    inserted = 0
    skipped = 0
    for row in legacy_rows:
        if row["cert_id"] in already:
            skipped += 1
            continue
        await db.save_certificate(row)
        inserted += 1
    print(f"[migrate] inserted {inserted} rows, skipped {skipped} duplicates")
    return inserted


def main() -> int:
    inserted = asyncio.run(migrate())
    print(f"[migrate] done — {inserted} rows migrated to PostgreSQL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
