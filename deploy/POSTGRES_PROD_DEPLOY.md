# P5.2 — PostgreSQL Production-Grade Deploy

This document captures the production posture for the TrustLayer control plane's
Postgres backend (per Plan v1.2 / IC-7 §Postgres connection management). It is
explicitly **operator-facing**: no real credentials, no real endpoints, no
secrets — only the connection options, the migration path, and the runbook
steps an operator needs to provision RDS / Supabase / self-hosted Postgres for
the first real notarization.

This document pairs with the **P5.4 e2e first-real-cert script**
(`scripts/run_first_real_cert.sh`) which exercises the end-to-end pipeline
against whatever Postgres URL is configured here.

## 1. Connection string

The control plane reads its connection URL from `TL_DATABASE_URL`. The default
in `app/config.py` is the **dev** connection:

```
postgresql+asyncpg://trustlayer:trustlayer@localhost:5432/trustlayer
```

For production, set:

```
TL_DATABASE_URL="postgresql+asyncpg://<user>:<password>@<host>:5432/<db>?sslmode=require"
```

asyncpg accepts `?sslmode=require` / `verify-ca` / `verify-full` as URL query
parameters — the SQLAlchemy URL strips them and forwards to asyncpg. The
explicit `database_ssl_mode` + `database_ssl_root_cert_path` settings below are
the Plan v1.2 preferred shape (they let the operator pin a specific CA bundle
shipped with the deployment, no system-root fallback).

## 2. SSL/TLS settings

| env var                       | dev default | production target |
|-------------------------------|-------------|-------------------|
| `TL_DATABASE_SSL_MODE`        | `prefer`    | `require` or stricter (`verify-ca` / `verify-full`) |
| `TL_DATABASE_SSL_ROOT_CERT_PATH` | _(unset)_   | path to the bundled CA (e.g. RDS `global-bundle.pem`, Supabase CA) |

SSL mode semantics (from asyncpg docs):

- `disable` — no TLS. **NEVER in production.**
- `prefer` — TLS if the server supports it, else plaintext. Dev only.
- `require` — TLS required, but the server cert is **NOT** verified. Closes
  the eavesdropping vector but leaves the MITM vector open. Acceptable
  behind a private VPC link but not on the public Internet.
- `verify-ca` — TLS required **AND** server cert signed by the supplied CA.
  Closes both vectors.
- `verify-full` — TLS required **AND** server cert matches the supplied CA
  **AND** the CN/SAN matches the hostname. **The production target.**

For the first real notarization, set `verify-ca` (the common sweet spot — most
managed Postgres providers ship a CA bundle that works for this).

## 3. Connection pool settings

| env var                                 | dev default | production guidance |
|-----------------------------------------|-------------|----------------------|
| `TL_DATABASE_POOL_SIZE`                 | `10`        | `2 × CPU cores per app instance` (10–50 for most). |
| `TL_DATABASE_POOL_MAX_OVERFLOW`         | `5`         | `0` for strict bound; `5–10` for burst tolerance. |
| `TL_DATABASE_POOL_TIMEOUT_SECONDS`      | `30`        | `30` is fine; lower (5–10) if you want fail-fast on saturation. |
| `TL_DATABASE_POOL_PRE_PING`             | `True`      | Keep `True` — catches server-side idle disconnects. |

The plan-v1.2 guidance is **2 × CPU cores** for `pool_size`. With a 4-vCPU
app instance, `pool_size=10` and `max_overflow=5` means the app can hold up to
15 concurrent connections per replica. For a 3-replica deployment, the
Postgres `max_connections` setting should be ≥ `3 × 15 = 45` (plus headroom
for the migration script and admin sessions — typically 100).

## 4. Provisioning (AWS RDS example)

```bash
# 1. Create the parameter group (no TLS downgrade, long statement timeout).
aws rds create-db-parameter-group \
    --db-parameter-group-name trustlayer-prod-pg16 \
    --db-parameter-group-family postgres16 \
    --description "TrustLayer prod Postgres 16"

aws rds modify-db-parameter-group \
    --db-parameter-group-name trustlayer-prod-pg16 \
    --parameters \
        "ParameterName=ssl,ParameterValue=1,ApplyMethod=pending-reboot" \
        "ParameterName=log_statement,ParameterValue=ddl,ApplyMethod=pending-reboot" \
        "ParameterName=statement_timeout,ParameterValue=60s,ApplyMethod=pending-reboot"

# 2. Create the RDS instance.
aws rds create-db-instance \
    --db-instance-identifier trustlayer-prod \
    --db-instance-class db.t4g.medium \
    --engine postgres \
    --engine-version 16.4 \
    --db-name trustlayer \
    --master-username trustlayer \
    --manage-master-user-password \
    --db-parameter-group-name trustlayer-prod-pg16 \
    --storage-encrypted \
    --kms-key-id alias/aws/rds \
    --backup-retention-period 35 \
    --enable-cloudwatch-logs-exports postgresql \
    --no-multi-az  # set --multi-az for HA in critical deployments \
    --allocated-storage 20 \
    --max-allocated-storage 100

# 3. Download the CA bundle and ship it to the deployment.
aws rds download-db-log-file-portion \
    --db-instance-identifier trustlayer-prod \
    --log-file-name global-bundle.pem

# 4. Configure the control plane.
export TL_DATABASE_URL="postgresql+asyncpg://trustlayer:<password>@trustlayer-prod.<region>.rds.amazonaws.com:5432/trustlayer?sslmode=require"
export TL_DATABASE_SSL_MODE="verify-ca"
export TL_DATABASE_SSL_ROOT_CERT_PATH="/etc/trustlayer/rds-ca-bundle.pem"
export TL_DATABASE_POOL_SIZE=10
export TL_DATABASE_POOL_MAX_OVERFLOW=5
```

## 5. Provisioning (Supabase example)

```bash
# 1. Create the Supabase project (via dashboard or CLI).
supabase projects create trustlayer-prod --org-id <ORG_ID> --region us-east-1 --plan pro

# 2. Get the direct connection string + CA cert from the dashboard
#    (Settings → Database → Connection string → Direct).
export TL_DATABASE_URL="postgresql+asyncpg://postgres:<password>@db.<project-ref>.supabase.co:5432/postgres?sslmode=require"
export TL_DATABASE_SSL_MODE="verify-full"
export TL_DATABASE_SSL_ROOT_CERT_PATH="/etc/trustlayer/supabase-ca.pem"
```

## 6. Migrations

Two migration scripts run in this order before the app starts in production:

1. **Legacy `notary.db` → SQLAlchemy `certificates`** (one-way, idempotent):
   ```bash
   PYTHONPATH=services/control_plane \
       uv run --no-project --with pydantic --with 'pydantic[email]' \
               --with pydantic-settings --with sqlalchemy --with asyncpg \
               --with python-dotenv \
       python services/control_plane/scripts/migrate_notary_sqlite_to_pg.py
   ```
   Reads rows from `./notary.db` (default `TL_NOTARY_DB_PATH`) and inserts
   into the new `certificates` SQLAlchemy table. Skips `cert_id`s already
   present (idempotent — safe to re-run).

2. **Alembic migration `0003_create_certificates.py`** (creates the table on
   fresh Postgres — required if starting from an empty database):
   ```bash
   PYTHONPATH=services/control_plane \
       alembic upgrade head
   ```
   The dev-fallback in `app/main.py` lifespan also creates the
   `certificates` table on first startup, scoped to that single table so
   other models (DisclosureRecord, etc.) are not affected by a pre-existing
   Postgres enum-string mismatch.

## 7. Backups + PITR (managed Postgres)

AWS RDS:
- `aws rds modify-db-instance --db-instance-identifier trustlayer-prod \
    --backup-retention-period 35 --apply-immediately`
- Automated daily snapshots are ON by default for RDS. PITR is enabled by
  default for `engine=postgres` since 2019 — restore to any second within
  the retention window.
- Manual snapshot: `aws rds create-db-snapshot --db-instance-identifier \
    trustlayer-prod --db-snapshot-identifier pre-upgrade-2026-06-28`

Supabase:
- Daily backups are automatic on the Pro plan (7-day retention).
- PITR is enabled — restore to any second within retention.
- Manual: Supabase dashboard → Database → Backups → Create backup.

Self-hosted:
- `pg_basebackup` for full daily snapshots + WAL archiving for PITR.
- See https://www.postgresql.org/docs/current/continuous-archiving.html for the
  canonical recipe.

## 8. Operational runbook

### "Database is full of errors after a failover"
The asyncpg pool may hold connections to the old primary. The control plane's
`pool_pre_ping=True` (default) catches dead connections on the next use and
re-establishes. No action needed; errors clear within `pool_size` requests.

### "PoolTimeout after a traffic spike"
- Increase `TL_DATABASE_POOL_MAX_OVERFLOW` (5 → 20) for short-term relief.
- Long-term: raise Postgres `max_connections` AND `TL_DATABASE_POOL_SIZE`.

### "SSL: certificate verify failed"
- The CA bundle path is wrong or stale. Re-download (see AWS RDS / Supabase
  steps above) and update `TL_DATABASE_SSL_ROOT_CERT_PATH`.
- Or relax to `verify-ca` if `verify-full` hostname pinning fails (most common
  cause: CN doesn't match the RDS endpoint hostname).

## 9. Security checklist

- [ ] `TL_DATABASE_URL` is set via secret manager (Vault / AWS Secrets Manager
      / Doppler), not committed to `.env`.
- [ ] `sslmode=require` minimum; `verify-full` preferred.
- [ ] Postgres role has INSERT + SELECT only on the `certificates` table
      (no UPDATE / DELETE — enforced by the GRANTs applied during
      provisioning, per Plan v3.1 §Risks R6 append-only audit table).
- [ ] At-rest encryption enabled (RDS `StorageEncrypted=true`,
      Supabase "Encrypted at rest" default).
- [ ] Backup retention ≥ 3 years (EU AI Act Art. 12 + DORA Art. 17
      record-keeping).
- [ ] Logs exported to a SIEM (CloudWatch Logs / Supabase Logflare).
