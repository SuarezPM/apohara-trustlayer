"""SQLAlchemy 2.0 async models for append-only audit tables.

Per plan v3.1 §Risks R5 (append-only audit tables) and AC-3 (compliance
gate): these tables are INSERT-only at the application level.
The Postgres role used by the control plane has INSERT but NOT UPDATE
or DELETE privileges on these tables (enforced at the DB layer,
not just application code).

Soft-deletion via `status` column with values `{Active, Retired, Superseded}`.
Retention via `retention_until` column (3 years EU AI Act, 5 years DORA,
whichever is longer).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum as PyEnum
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""


class RecordStatus(str, PyEnum):
    """Soft-delete status (no hard delete — see plan v3.1 §Risks R5)."""

    ACTIVE = "Active"
    RETIRED = "Retired"
    SUPERSEDED = "Superseded"


class DisclosureRecord(Base):
    """One disclosure = one signed receipt + one compliance assessment.

    INSERT-only. UPDATE/DELETE blocked at DB role level.
    """

    __tablename__ = "disclosure_records"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    # v1.2-US-1: tenant isolation. Default "apohara" for backward compat
    # with v1.0.x single-tenant deployments; production MUST run the
    # `0002_reassign_org_id.py` migration to set per-tenant values.
    # See Plan v1.2 Block 4 v1.2-US-1 (multi-tenant schema + JWT middleware).
    org_id: Mapped[str] = mapped_column(
        String(128), nullable=False, default="apohara", index=True,
    )
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    row_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    ai_system_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    deployer_name: Mapped[str] = mapped_column(String(256), nullable=False)
    deployer_country: Mapped[str] = mapped_column(String(2), nullable=False)
    deployer_sector: Mapped[str] = mapped_column(String(128), nullable=False)
    artifact_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    artifact_content: Mapped[str | None] = mapped_column(String, nullable=True)

    disclosure_text: Mapped[str] = mapped_column(String(4096), nullable=False)
    compliance_rollup: Mapped[str] = mapped_column(String(32), nullable=False)

    cose_sign1_b64: Mapped[str] = mapped_column(String(8192), nullable=False)
    tsa_token_b64: Mapped[str | None] = mapped_column(String(4096), nullable=True)
    tsa_url: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Compliance (JSON for forward-compat)
    compliance_layers: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    # Retention + audit
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="record_status"),
        nullable=False,
        default=RecordStatus.ACTIVE,
        server_default=RecordStatus.ACTIVE.value,
    )

    __table_args__ = (
        Index("ix_disclosure_chain_row", "chain_id", "row_number", unique=True),
        Index("ix_disclosure_status_created", "status", "created_at"),
    )


class ToolExecutionReceipt(Base):
    """One tool execution = one agent invocation before/after receipt pair.

    INSERT-only. Pairs are linked via `pair_id`. Future v1.1 will use
    these for sandbox audit trail.
    """

    __tablename__ = "tool_execution_receipts"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    row_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    pair_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # before | after
    tool_name: Mapped[str] = mapped_column(String(256), nullable=False)
    args_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    output_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    sandbox_profile_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cose_sign1_b64: Mapped[str] = mapped_column(String(8192), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="record_status"),
        nullable=False,
        default=RecordStatus.ACTIVE,
        server_default=RecordStatus.ACTIVE.value,
    )

    __table_args__ = (
        Index("ix_tool_receipt_chain_row", "chain_id", "row_number", unique=True),
    )


class PolicyDecision(Base):
    """One policy evaluation = one decision per strategy per disclosure."""

    __tablename__ = "policy_decisions"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    row_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    strategy_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    strategy_version: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str] = mapped_column(String(4096), nullable=False)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="record_status"),
        nullable=False,
        default=RecordStatus.ACTIVE,
        server_default=RecordStatus.ACTIVE.value,
    )


class KeyRotationEvent(Base):
    """Audit trail of signing key rotations."""

    __tablename__ = "key_rotation_events"

    id: Mapped[str] = mapped_column(UUID(as_uuid=False), primary_key=True)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    row_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    row_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)

    old_key_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    new_key_id: Mapped[str] = mapped_column(String(128), nullable=False)
    old_public_key_fp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    new_public_key_fp: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    grace_period_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cose_sign1_b64: Mapped[str] = mapped_column(String(8192), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    retention_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[RecordStatus] = mapped_column(
        Enum(RecordStatus, name="record_status"),
        nullable=False,
        default=RecordStatus.ACTIVE,
        server_default=RecordStatus.ACTIVE.value,
    )


class CertificateRecord(Base):
    """One notarized certificate (P5.1: migrated from SQLite `notary.db`).

    Schema mirrors the legacy SQLite `certificates` table 1:1 — see
    `app/notary/db.py` SCHEMA for the original. The migration script
    `scripts/migrate_notary_sqlite_to_pg.py` reads rows from the old
    `notary.db` (if present) and inserts them here.

    Append-only (per Plan v3.1 §Risks R6 — audit table posture). The
    Postgres role used in production has INSERT but not UPDATE/DELETE
    on this table. Soft-deletion would require a status column +
    retired_at + retention_until — not added in P5.1 (the existing
    SQLite table didn't have them either); a future P5.1.1 could add
    a parallel retirement path.

    Tenant isolation (Plan v1.2 Block 4 v1.2-US-1): `submitted_by` is
    the org_id of the submitter. Production must run the
    `0002_reassign_org_id.py` migration if upgrading from a pre-v1.2
    single-tenant deployment.
    """

    __tablename__ = "certificates"

    cert_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    # Identity / provenance (3 NOT NULL columns that index the cert).
    content_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    submitted_by: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    # Timestamps (UTC, stored as TIMESTAMP WITHOUT TIME ZONE for SQLite
    # compatibility; the application always reads/writes UTC).
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    notarized_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    # Crypto material.
    cose_sign1_b64: Mapped[str] = mapped_column(Text, nullable=False)
    cwt_claims_json: Mapped[str] = mapped_column(Text, nullable=False)
    primary_key_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Optional TSA + transparency-log evidence (NULL when degraded mode).
    tsa_token_b64: Mapped[str | None] = mapped_column(Text, nullable=True)
    tsa_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    tsa_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=False), nullable=True)
    rekor_entry_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rekor_log_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # P5.5: full Rekor/SCITT inclusion-proof payload as JSON. The ID column
    # above is enough for the audit trail; this column carries the
    # leaf_hash + log_index + tree_size + audit_path so the verify
    # page can call rfc9162_verifier.verify_inclusion_proof() locally
    # (no fetch from the SCITT log at verify time). NULL when the SCITT
    # client doesn't return inclusion proofs (mock SCITT + dev).
    rekor_entry_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # On-disk artifact paths (relative to notary_output_dir; computed at write time).
    pdf_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    qr_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Free-form JSON for forward-compatibility (extended claims, payload
    # metadata, etc.). Per Plan v3.1 §Risks R6 this is APPEND-only — no
    # silent in-place mutation by the application.
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Auto-managed timestamps (audit trail).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
