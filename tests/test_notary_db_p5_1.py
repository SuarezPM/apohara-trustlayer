"""P5.1: NotaryDB SQLite→Postgres round-trip + idempotent migration.

These tests validate the new async `NotaryDB` (SQLAlchemy 2.0 over
the engine from `app.db.session`) independently from the FastAPI
TestClient — the watermarking integration tests in
`test_notary_watermark_integration.py` exercise the full HTTP path
but suffer pre-existing test pollution (shared global `_db` /
sessionmaker across tests). These focused tests:
- Round-trip `save_certificate` → `get_certificate` for the
  legacy 18-column SQLite shape.
- Verify `list_certificates` ordering (newest first) + the
  `submitted_by` filter.
- Verify idempotent migration: running `migrate()` twice does NOT
  create duplicate rows (the second run skips all `cert_id`s already
  present).
- Verify the `_parse_dt` helper strips tzinfo so offset-aware
  `datetime`s don't fail Postgres' naive-TIMESTAMP column.
"""
from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

from app.notary.db import NotaryDB, _parse_dt


# ============================================================================
# Fixtures: a fresh SQLite-typed engine per test (isolated from the global)
# ============================================================================


@pytest.fixture
def fresh_aio_sqlite_url(monkeypatch) -> str:
    """Override `database_url` to an isolated in-memory aiosqlite DB.

    The NotaryDB + sessionmaker module globals cache the engine, so we
    reset them via `reset_engine_for_tests()` before each test. This
    isolates tests from each other and from the default Postgres URL.
    """
    url = f"sqlite+aiosqlite:///{tempfile.mktemp(suffix='.sqlite')}"
    from app.config import get_settings
    from app.db import session as _sess

    # Override the cached Settings instance so `_get_engine()` builds
    # against our aio_sqlite URL instead of the default Postgres.
    get_settings.cache_clear()
    monkeypatch.setattr(
        "app.db.session.get_settings",
        lambda: type("S", (), {"database_url": url})(),
    )
    _sess.reset_engine_for_tests()
    yield url
    _sess.reset_engine_for_tests()


@pytest_asyncio.fixture
async def notary_db(fresh_aio_sqlite_url) -> NotaryDB:
    """A NotaryDB whose underlying engine is the fresh aio_sqlite DB
    (per-test isolated). The `certificates` table is created lazily on
    the first call (via the dev-fallback DDL in `main.py`, replicated
    here for self-containment).
    """
    from app.db.models import Base, CertificateRecord
    from app.db.session import _get_engine

    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(
                bind=sync_conn, tables=[CertificateRecord.__table__]
            )
        )
    return NotaryDB(db_path=None)


def _make_cert_dict(**overrides: Any) -> dict[str, Any]:
    """Build a 18-column cert dict matching the legacy SQLite NotaryDB
    shape (used for round-trip tests).
    """
    now = datetime.now(timezone.utc)
    base = {
        "cert_id": f"cert_{uuid.uuid4().hex[:8]}_{uuid.uuid4().hex[:8]}",
        "content_hash": "sha256:" + uuid.uuid4().hex,
        "content_type": "text",
        "ai_system_id": "deepseek-v4",
        "submitted_by": "acme-corp",
        "submitted_at": now.isoformat(),
        "notarized_at": now.isoformat(),
        "cose_sign1_b64": "eyJhbGciOiJERUNTIn0.payload.sig",
        "cwt_claims_json": '{"ai_system_id": "deepseek-v4"}',
        "primary_key_fingerprint": "ed25519:" + uuid.uuid4().hex,
        "tsa_token_b64": None,
        "tsa_url": None,
        "tsa_fetched_at": None,
        "rekor_entry_id": None,
        "rekor_log_id": None,
        "pdf_path": f"artifacts/notary/cert_{uuid.uuid4().hex[:8]}.pdf",
        "qr_payload": f"apohara.org/verify/cert_{uuid.uuid4().hex[:8]}",
        "metadata_json": '{"test": "p5.1-roundtrip"}',
    }
    base.update(overrides)
    return base


# ============================================================================
# _parse_dt
# ============================================================================


def test_parse_dt_strips_tzinfo_from_aware_datetime() -> None:
    aware = datetime(2026, 6, 28, 22, 0, 0, tzinfo=timezone.utc)
    naive = _parse_dt(aware)
    assert naive.tzinfo is None
    assert naive == datetime(2026, 6, 28, 22, 0, 0)


def test_parse_dt_strips_tzinfo_from_string() -> None:
    iso = "2026-06-28T22:00:00+00:00"
    naive = _parse_dt(iso)
    assert naive.tzinfo is None
    assert naive == datetime(2026, 6, 28, 22, 0, 0)


def test_parse_dt_handles_z_suffix() -> None:
    naive = _parse_dt("2026-06-28T22:00:00Z")
    assert naive.tzinfo is None
    assert naive == datetime(2026, 6, 28, 22, 0, 0)


# ============================================================================
# Round-trip
# ============================================================================


@pytest.mark.asyncio
async def test_save_and_get_roundtrip(notary_db: NotaryDB) -> None:
    cert = _make_cert_dict()
    returned_id = await notary_db.save_certificate(cert)
    assert returned_id == cert["cert_id"]

    loaded = await notary_db.get_certificate(cert["cert_id"])
    assert loaded is not None
    assert loaded["cert_id"] == cert["cert_id"]
    assert loaded["content_hash"] == cert["content_hash"]
    assert loaded["submitted_by"] == cert["submitted_by"]
    assert loaded["ai_system_id"] == cert["ai_system_id"]
    # Timestamps: stored as naive UTC, read back as ISO-8601.
    assert loaded["submitted_at"] == cert["submitted_at"].replace("+00:00", "")
    # Created_at is server-managed; we don't expose it in the dict
    # but the row IS persisted (cert visible via get_certificate).


@pytest.mark.asyncio
async def test_get_certificate_unknown_returns_none(notary_db: NotaryDB) -> None:
    loaded = await notary_db.get_certificate("cert_does_not_exist")
    assert loaded is None


@pytest.mark.asyncio
async def test_list_certificates_orders_newest_first(notary_db: NotaryDB) -> None:
    base_time = datetime.now(timezone.utc)
    # Insert 3 certs with monotonically increasing notarized_at.
    certs = []
    for i in range(3):
        c = _make_cert_dict(
            notarized_at=(base_time + timedelta(seconds=i)).isoformat()
        )
        await notary_db.save_certificate(c)
        certs.append(c)

    listed = await notary_db.list_certificates(limit=100)
    assert len(listed) == 3
    # Newest first: certs[2] > certs[1] > certs[0].
    assert listed[0]["cert_id"] == certs[2]["cert_id"]
    assert listed[1]["cert_id"] == certs[1]["cert_id"]
    assert listed[2]["cert_id"] == certs[0]["cert_id"]


@pytest.mark.asyncio
async def test_list_certificates_filters_by_submitted_by(
    notary_db: NotaryDB,
) -> None:
    for sub in ("acme-corp", "acme-corp", "other-corp"):
        await notary_db.save_certificate(_make_cert_dict(submitted_by=sub))

    acme = await notary_db.list_certificates(submitted_by="acme-corp", limit=100)
    other = await notary_db.list_certificates(submitted_by="other-corp", limit=100)
    assert len(acme) == 2
    assert len(other) == 1
    assert all(c["submitted_by"] == "acme-corp" for c in acme)


# ============================================================================
# Idempotent migration
# ============================================================================


@pytest.mark.asyncio
async def test_migrate_is_idempotent_when_destination_already_populated(
    fresh_aio_sqlite_url,
) -> None:
    """Running the migration twice must NOT create duplicate rows.

    We pre-populate the destination by writing 1 row, then call
    `migrate()` against an empty legacy SQLite DB — the pre-populated
    row must be preserved, and no new rows are added.
    """
    from app.db.models import Base, CertificateRecord
    from app.db.session import _get_engine
    from scripts.migrate_notary_sqlite_to_pg import (  # noqa: F401
        migrate,
    )

    engine = _get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(
            lambda sync_conn: Base.metadata.create_all(
                bind=sync_conn, tables=[CertificateRecord.__table__]
            )
        )

    # Pre-populate the destination with 1 cert (simulates a partial
    # previous migration or a fresh insert from the running app).
    pre = _make_cert_dict(submitted_by="pre-existing")
    db = NotaryDB(db_path=None)
    await db.save_certificate(pre)

    # Point the migration at an EMPTY legacy DB so the second run is a
    # no-op (the one existing row should not be touched, and zero new
    # rows should be added).
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        empty_sqlite = Path(tf.name)
    sqlite3.connect(str(empty_sqlite)).close()  # create empty file
    from app.config import get_settings
    get_settings.cache_clear()
    from unittest.mock import patch
    with patch("app.config.get_settings") as m:
        m.return_value = type(
            "S",
            (),
            {
                "database_url": fresh_aio_sqlite_url,
                "notary_db_path": str(empty_sqlite),
            },
        )()
        inserted = await migrate()

    assert inserted == 0, (
        f"migrate() should be a no-op when the legacy DB is empty, "
        f"got {inserted} inserts"
    )
    # The pre-existing row is still there.
    loaded = await db.get_certificate(pre["cert_id"])
    assert loaded is not None
    empty_sqlite.unlink()


@pytest.mark.asyncio
async def test_migrate_copies_legacy_sqlite_rows_into_destination(
    tmp_path: Path, fresh_aio_sqlite_url
) -> None:
    """Round-trip: legacy SQLite → new SQLAlchemy table via migrate()."""
    from scripts.migrate_notary_sqlite_to_pg import migrate  # noqa: F401

    # 1. Build a legacy `notary.db` with 2 rows.
    legacy = tmp_path / "notary.db"
    conn = sqlite3.connect(str(legacy))
    try:
        conn.executescript("""
            CREATE TABLE certificates (
                cert_id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                content_type TEXT NOT NULL,
                ai_system_id TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                submitted_at TIMESTAMP NOT NULL,
                notarized_at TIMESTAMP NOT NULL,
                cose_sign1_b64 TEXT NOT NULL,
                cwt_claims_json TEXT NOT NULL,
                tsa_token_b64 TEXT,
                tsa_url TEXT,
                tsa_fetched_at TIMESTAMP,
                rekor_entry_id TEXT,
                rekor_log_id TEXT,
                pdf_path TEXT,
                qr_payload TEXT,
                metadata_json TEXT,
                primary_key_fingerprint TEXT
            )
        """)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        for i in range(2):
            cid = f"cert_legacy_{i}"
            conn.execute(
                "INSERT INTO certificates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    cid,
                    f"sha256:legacy_{i}",
                    "text",
                    "deepseek-v4",
                    "legacy-corp",
                    now, now,
                    "eyJ.payload.sig",
                    '{"legacy": true}',
                    None, None, None,
                    None, None,
                    f"artifacts/{cid}.pdf",
                    f"apohara.org/verify/{cid}",
                    f'{{"legacy": {i}}}',
                    "ed25519:legacy",
                ),
            )
        conn.commit()
    finally:
        conn.close()

    # 2. Migrate into the fresh aio_sqlite destination.
    from app.config import get_settings
    get_settings.cache_clear()
    from unittest.mock import patch
    with patch("app.config.get_settings") as m:
        m.return_value = type(
            "S",
            (),
            {
                "database_url": fresh_aio_sqlite_url,
                "notary_db_path": str(legacy),
            },
        )()
        inserted = await migrate()

    assert inserted == 2

    # 3. Verify the rows are queryable from the new API.
    db = NotaryDB(db_path=None)
    for i in range(2):
        loaded = await db.get_certificate(f"cert_legacy_{i}")
        assert loaded is not None
        assert loaded["submitted_by"] == "legacy-corp"
        assert loaded["content_hash"] == f"sha256:legacy_{i}"

    # 4. Re-run migration — must be a no-op (idempotent).
    with patch("app.config.get_settings") as m:
        m.return_value = type(
            "S",
            (),
            {
                "database_url": fresh_aio_sqlite_url,
                "notary_db_path": str(legacy),
            },
        )()
        inserted_again = await migrate()
    assert inserted_again == 0
