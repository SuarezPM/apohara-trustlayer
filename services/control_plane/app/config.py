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
