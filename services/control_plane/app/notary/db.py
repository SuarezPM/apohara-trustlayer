"""NotaryDB — SQLite-backed NotaryService persistence.

Single-responsibility module: owns the schema and the connection
pool, no other concerns. Production replaces with PostgreSQL via
SQLAlchemy (W3.0 W3.2 deferred).
"""
from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class NotaryDB:
    """SQLite-backed NotaryService persistence.

    Schema:
        certificates (
            cert_id TEXT PRIMARY KEY,       -- "cert_{uuid4}_{hash8}"
            content_hash TEXT NOT NULL,
            content_type TEXT NOT NULL,
            ai_system_id TEXT NOT NULL,
            submitted_by TEXT NOT NULL,      -- org_id
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
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS certificates (
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
        primary_key_fingerprint TEXT,
        UNIQUE (content_hash, submitted_by)
    );
    CREATE INDEX IF NOT EXISTS idx_certs_submitted_by ON certificates(submitted_by);
    CREATE INDEX IF NOT EXISTS idx_certs_submitted_at ON certificates(submitted_at);
    """

    def __init__(self, db_path: str = "notary.db"):
        self.db_path = db_path
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(self.SCHEMA)

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        # Use sqlite3.Row so cursors expose column names via .keys().
        # Without this, fetchall() returns plain tuples and the callers
        # below (list_certificates, get_certificate) can't build dicts.
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save_certificate(
        self,
        cert_id: str,
        content_hash: str,
        content_type: str,
        ai_system_id: str,
        submitted_by: str,
        submitted_at: datetime,
        notarized_at: datetime,
        cose_sign1_b64: str,
        cwt_claims: dict,
        tsa_token_b64: Optional[str],
        tsa_url: Optional[str],
        rekor_entry_id: Optional[str],
        rekor_log_id: Optional[str],
        pdf_path: Optional[str],
        qr_payload: Optional[str],
        metadata: dict,
        primary_key_fingerprint: str,
    ) -> None:
        """Save a certificate. Idempotent on (content_hash, submitted_by)."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO certificates (
                    cert_id, content_hash, content_type, ai_system_id,
                    submitted_by, submitted_at, notarized_at,
                    cose_sign1_b64, cwt_claims_json,
                    tsa_token_b64, tsa_url, tsa_fetched_at,
                    rekor_entry_id, rekor_log_id,
                    pdf_path, qr_payload, metadata_json,
                    primary_key_fingerprint
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cert_id, content_hash, content_type, ai_system_id,
                    submitted_by, submitted_at.isoformat(),
                    notarized_at.isoformat(),
                    cose_sign1_b64, json.dumps(cwt_claims, sort_keys=True),
                    tsa_token_b64, tsa_url,
                    datetime.now(timezone.utc).isoformat() if tsa_token_b64 else None,
                    rekor_entry_id, rekor_log_id,
                    pdf_path, qr_payload, json.dumps(metadata, sort_keys=True),
                    primary_key_fingerprint,
                ),
            )

    def get_certificate(self, cert_id: str) -> Optional[dict]:
        """Retrieve a certificate by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE cert_id = ?", (cert_id,)
            ).fetchone()
            if not row:
                return None
            # row is a sqlite3.Row; use its `.keys()` to build a dict.
            return dict(zip(row.keys(), row))

    def list_certificates(
        self, submitted_by: Optional[str] = None, limit: int = 100
    ) -> list:
        """List certificates, optionally filtered by tenant."""
        with self._connect() as conn:
            if submitted_by:
                rows = conn.execute(
                    "SELECT cert_id, content_hash, content_type, "
                    "ai_system_id, submitted_by, notarized_at "
                    "FROM certificates WHERE submitted_by = ? "
                    "ORDER BY notarized_at DESC LIMIT ?",
                    (submitted_by, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT cert_id, content_hash, content_type, "
                    "ai_system_id, submitted_by, notarized_at "
                    "FROM certificates ORDER BY notarized_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            # sqlite3.Row iterates as VALUES (not key-value pairs), so
            # `dict(r)` fails. Use `dict(zip(r.keys(), r))` instead.
            return [dict(zip(r.keys(), r)) for r in rows]

