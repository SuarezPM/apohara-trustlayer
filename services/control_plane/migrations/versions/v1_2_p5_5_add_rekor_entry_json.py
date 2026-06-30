"""P5.5: add `rekor_entry_json` column to `certificates`.

Per Plan P5.5 SCITT inclusion-proof verification:
`rekor_entry_id` carries the Rekor log ID alone; `rekor_entry_json`
carries the full inclusion-proof payload (leaf_hash + log_index +
tree_size + audit_path) as JSON so the verify page can call
`rfc9162_verifier.verify_inclusion_proof()` locally without
re-fetching from the SCITT log at verify time.

The column was added to `app.db.models.CertificateRecord` (model
revision P5.5) but the live PostgreSQL `certificates` table was
bootstrapped by `Base.metadata.create_all` in the FastAPI lifespan
before the model gained this column. `create_all` is a no-op for
existing tables, so the column was never propagated to already-
deployed instances. This migration closes the gap.

Idempotent: inspects `information_schema.columns` first and only
ALTERs when the column is missing (matches the pattern used by
`v1_2_multi_tenant_chain_namespace.py`).

Revision ID: v1_2_p5_5_add_rekor_entry_json
Revises: v1_2_multi_tenant_chain_namespace
Create Date: 2026-06-30
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "v1_2_p5_5_add_rekor_entry_json"
down_revision: str | None = "v1_2_multi_tenant_chain_namespace"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add `rekor_entry_json TEXT NULL` to `certificates` if missing."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("certificates"):
        # Fresh deployment: the lifespan `create_all` will create the
        # table with the full model schema including this column, so
        # nothing to do here.
        return
    existing_cols = {c["name"] for c in inspector.get_columns("certificates")}
    if "rekor_entry_json" in existing_cols:
        # Already applied (idempotent re-run).
        return
    op.add_column(
        "certificates",
        sa.Column("rekor_entry_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Reverse the migration: drop `rekor_entry_json` from `certificates`.

    Best-effort: only drops the column when it exists. The column is
    nullable so the DROP is safe (no default to backfill).
    """
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if not inspector.has_table("certificates"):
        return
    existing_cols = {c["name"] for c in inspector.get_columns("certificates")}
    if "rekor_entry_json" in existing_cols:
        op.drop_column("certificates", "rekor_entry_json")
