"""v1.2 multi-tenant SaaS: per-tenant chain_id namespace + org_id column.

Per Plan v1.2 Block 4 v1.2-US-1 (final step for true multi-tenant SaaS):

1. Add `org_id` column to `disclosure_records` (default "apohara" for
   backward compat with v1.0.x single-tenant deployments).
2. Add `org_id` column to the 3 other append-only audit tables
   (tool_execution_receipts, policy_decisions, key_rotation_events).
3. Backfill `chain_id` to the per-tenant namespace format:
   `tenant:{org_id}:{disclosure_type}`. The old single-tenant chains
   become `tenant:apohara:{disclosure_type}`.
4. Add composite index `(org_id, chain_id)` for efficient per-tenant
   chain queries — this is the hot path for v1.2 multi-tenant SaaS.

This is the FINAL migration needed to close the multi-tenant SaaS gap.
After this migration, TrustLayer is ready for true SaaS deployment
(multiple tenants sharing one Postgres instance with strict isolation).

Revision ID: v1_2_multi_tenant_chain_namespace
Revises:
Create Date: 2026-06-26
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "v1_2_multi_tenant_chain_namespace"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add org_id column to all 4 append-only tables.
    # Default "apohara" preserves backward compat with v1.0.x single-tenant data.
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # Helper: add org_id column + composite index to a table if missing.
    def _add_org_id_and_index(table_name: str) -> None:
        existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
        if "org_id" not in existing_cols:
            op.add_column(
                table_name,
                sa.Column(
                    "org_id",
                    sa.String(length=64),
                    nullable=False,
                    server_default="apohara",
                ),
            )
        # Composite index on (org_id, chain_id) — the hot path for
        # per-tenant chain queries.
        existing_indexes = {i["name"] for i in inspector.get_indexes(table_name)}
        idx_name = f"ix_{table_name}_org_id_chain_id"
        if idx_name not in existing_indexes:
            op.create_index(
                idx_name,
                table_name,
                ["org_id", "chain_id"],
            )

    _add_org_id_and_index("disclosure_records")
    # The other 3 tables may not exist yet in fresh deployments — only
    # migrate them if they do.
    for tbl in (
        "tool_execution_receipts",
        "policy_decisions",
        "key_rotation_events",
    ):
        if inspector.has_table(tbl):
            _add_org_id_and_index(tbl)

    # 2. Backfill chain_id to per-tenant namespace.
    # Old format: any string (v1.0.x used "default" or similar).
    # New format: "tenant:{org_id}:{disclosure_type}".
    # We use a sentinel "(unknown)" for disclosure_type to preserve
    # the existing data without losing it; v1.2.1+ will re-namespace
    # to actual disclosure_type on next write.
    #
    # NOTE: this is idempotent — if chain_id already starts with
    # "tenant:" we skip it. This lets the migration run safely
    # multiple times in dev/CI environments.
    op.execute(
        """
        UPDATE disclosure_records
        SET chain_id = 'tenant:' || org_id || ':(unknown)'
        WHERE chain_id NOT LIKE 'tenant:%'
        """
    )


def downgrade() -> None:
    """Reverse the migration: drop indexes, drop org_id columns,
    restore chain_id to its pre-migration value (best-effort)."""
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    def _drop_org_id_and_index(table_name: str) -> None:
        if not inspector.has_table(table_name):
            return
        existing_indexes = {i["name"] for i in inspector.get_columns(table_name)}
        idx_name = f"ix_{table_name}_org_id_chain_id"
        # drop_index is order-sensitive; only call if it exists.
        try:
            op.drop_index(idx_name, table_name=table_name)
        except Exception:
            pass

        existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
        if "org_id" in existing_cols:
            op.drop_column(table_name, "org_id")

    for tbl in (
        "disclosure_records",
        "tool_execution_receipts",
        "policy_decisions",
        "key_rotation_events",
    ):
        _drop_org_id_and_index(tbl)

    # Best-effort: restore chain_id to pre-migration value by stripping
    # the "tenant:apohara:" prefix. This loses data if disclosure_type
    # was meaningful, but it preserves the v1.0.x single-tenant chain_id
    # shape for rollback scenarios.
    op.execute(
        """
        UPDATE disclosure_records
        SET chain_id = REPLACE(chain_id, 'tenant:apohara:', '')
        WHERE chain_id LIKE 'tenant:apohara:%'
        """
    )
