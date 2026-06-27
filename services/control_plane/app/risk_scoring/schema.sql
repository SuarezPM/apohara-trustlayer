-- W12 — Production risk register (ISO/IEC 23894:2023 AI risk management)
-- Wave 2 production wire-up: PostgreSQL DDL for the risk_register table.
--
-- Schema design notes (per 11th-auditor review, June 2026):
-- - UUID primary key (gen_random_uuid) so DB-assigned id is independent of
--   any caller-supplied value; persistent_id is the stable external identifier
--   used by the org's compliance team for audit traceability (per Clause 6.7).
-- - inherent_risk_score and residual_risk_score are GENERATED ALWAYS AS STORED
--   columns (PostgreSQL 12+) so the DB enforces the formula
--   `residual = GREATEST(1, ROUND(inherent * (1 - control_effectiveness)))`
--   and the application cannot drift from it.
-- - lifecycle_stage covers the AI lifecycle per ISO 23894:2023 Clause 6.2
--   + EU AI Act Art. 9: design -> development -> deployment -> monitoring
--   -> decommissioning.
-- - iso23894_stage tracks the 5 process stages under Clause 6.
-- - nist_rmf_fn tracks the 4 Core Functions of NIST AI RMF 1.0
--   (GOVERN/MAP/MEASURE/MANAGE) so we can produce a single dashboard
--   with both ISO 23894 and NIST AI RMF crosswalks.
-- - CHECK constraints enforce likelihood/impact 1-5, control_effectiveness
--   0-1, and the closed-set ENUM-like values for lifecycle_stage, iso23894_stage,
--   nist_rmf_fn, and treatment.
-- - Indexes on (org_id), (org_id, lifecycle_stage), (org_id, nist_rmf_fn),
--   and (residual_risk_score DESC) cover the dashboard's hot query patterns.

CREATE TABLE IF NOT EXISTS risk_register (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    persistent_id   TEXT UNIQUE NOT NULL,
    org_id          TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    asset_id        TEXT NOT NULL,
    lifecycle_stage TEXT NOT NULL CHECK (lifecycle_stage IN
        ('design','development','deployment','monitoring','decommissioning')),
    iso23894_stage  TEXT NOT NULL CHECK (iso23894_stage IN
        ('6.1_context','6.2_identification','6.3_analysis',
         '6.4_evaluation','6.5_treatment')),
    nist_rmf_fn     TEXT NOT NULL CHECK (nist_rmf_fn IN
        ('GOVERN','MAP','MEASURE','MANAGE')),
    likelihood      INT NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
    impact          INT NOT NULL CHECK (impact BETWEEN 1 AND 5),
    inherent_risk_score INT GENERATED ALWAYS AS (likelihood * impact) STORED,
    control_effectiveness REAL NOT NULL DEFAULT 0.0
        CHECK (control_effectiveness BETWEEN 0.0 AND 1.0),
    residual_risk_score INT GENERATED ALWAYS AS
        (GREATEST(1, ROUND((likelihood * impact)::NUMERIC * (1.0 - control_effectiveness)))) STORED,
    treatment       TEXT NOT NULL CHECK (treatment IN
        ('avoid','reduce','transfer','accept')),
    owner           TEXT,
    review_cadence_days INT NOT NULL DEFAULT 90,
    last_reviewed   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_register_org_id
    ON risk_register (org_id);
CREATE INDEX IF NOT EXISTS idx_risk_register_org_stage
    ON risk_register (org_id, lifecycle_stage);
CREATE INDEX IF NOT EXISTS idx_risk_register_org_rmf
    ON risk_register (org_id, nist_rmf_fn);
CREATE INDEX IF NOT EXISTS idx_risk_register_residual
    ON risk_register (residual_risk_score DESC);