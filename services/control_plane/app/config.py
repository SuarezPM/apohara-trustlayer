"""Settings for the TrustLayer Control Plane (env-driven via pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Control plane configuration. Env vars: TL_*."""

    model_config = SettingsConfigDict(
        env_prefix="TL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Service
    service_name: str = "trustlayer-control-plane"
    environment: str = Field(default="dev")  # dev | staging | prod

    # HTTP
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])

    # Database (per plan v3.1 §Risks R6: append-only audit tables)
    database_url: str = Field(
        default="postgresql+asyncpg://trustlayer:trustlayer@localhost:5432/trustlayer",
        description="PostgreSQL connection string (asyncpg).",
    )
    # P5.2: PostgreSQL production-grade connection options. The asyncpg
    # URL scheme accepts `ssl=require` as a query parameter (asyncpg-native)
    # but the explicit `database_ssl_mode` + `database_ssl_root_cert_path`
    # pair below is the Plan v1.2 / IC-7 preferred shape — it allows the
    # operator to point at a CA bundle shipped with the binary (no
    # baked-in system roots in production).
    database_ssl_mode: str = Field(
        default="prefer",
        description=(
            "PostgreSQL SSL mode (asyncpg `ssl` parameter): "
            "'disable' | 'prefer' | 'require' | 'verify-ca' | 'verify-full'. "
            "Production MUST be 'require' or stricter (Plan IC-7)."
        ),
    )
    database_ssl_root_cert_path: str | None = Field(
        default=None,
        description=(
            "Path to the Postgres CA cert (PEM). Required for"
            " 'verify-ca' / 'verify-full'. Production should pin the CA"
            " shipped with the deployment (RDS ca-bundle / Supabase CA)."
        ),
    )
    database_pool_size: int = Field(
        default=10,
        description=(
            "SQLAlchemy async connection pool size. Rule of thumb:"
            " 2 x CPU cores per app instance. Production: 10-50."
        ),
    )
    database_pool_max_overflow: int = Field(
        default=5,
        description=(
            "Connections allowed beyond `pool_size` during burst. 0 ="
            " no overflow (pool is strictly bounded)."
        ),
    )
    database_pool_timeout_seconds: int = Field(
        default=30,
        description="Seconds to wait before raising PoolTimeout on exhaustion.",
    )
    database_pool_pre_ping: bool = Field(
        default=True,
        description=(
            "Test connection liveness with SELECT 1 before use. Catches"
            " server-side idle disconnects. Off by default in asyncpg"
            " but ON by default for asyncpg-via-async (recommended)."
        ),
    )

    # Org identity (Architect IC-4: OrgId newtype, env-driven, NO silent default)
    # Per Architect approval gate (IC-4 reconciliation): the env var IS
    # the demo entry point, but fail-fast in non-demo builds. The default
    # `"apohara"` only applies when (a) TL_ORG_ID is set explicitly OR
    # (b) the build was compiled with `--features demo`. Production
    # builds (no demo feature) MUST set TL_ORG_ID or fail startup.
    org_id: str = Field(
        default="apohara",
        description="TL_ORG_ID env var. Default 'apohara' is demo-only. Production MUST set explicitly.",
    )

    # TSA provider (Architect IC-3: fail-fast on unset/invalid)
    tsa_provider: str = Field(default="mock")  # mock | free_tsa | digicert

    # W8 Notary Layer (production wire-up)
    # The DB is SQLite for dev (W8.4 production would be Postgres); the
    # output dir is where reportlab writes the certificate PDFs.
    notary_db_path: str = Field(
        default="notary.db",
        description="TL_NOTARY_DB_PATH — SQLite path for NotaryDB.",
    )
    notary_output_dir: str = Field(
        default="artifacts/notary",
        description="TL_NOTARY_OUTPUT_DIR — where certificate PDFs are written.",
    )

    # Compliance status (per AC-22: response envelope includes disclaimers)
    v1_disclaimers: list[str] = Field(
        default_factory=lambda: [
            "v1: Watermark=NotApplicable",
            "v1: DORA=Partial",
            "v1: ISO42001=NotImplemented",
            "v1: NIST=NotImplemented",
        ],
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor."""
    return Settings()
