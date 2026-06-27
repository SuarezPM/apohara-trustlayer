"""DB-backed RiskRegister (production wire-up for W12).

Uses SQLAlchemy 2.0 with sync engine. The async variant is deferred
to W12.1 (not in this wave).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean, Column, Computed, DateTime, Float, Integer, String,
    create_engine, select, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, sessionmaker

from app.risk_scoring.iso_23894 import (
    ISO23894Stage, NISTAIRMFFunction, Risk, RiskRegister,
    RiskScoreSummary, RiskTreatment,
)

Base = declarative_base()


class RiskRecord(Base):
    """SQLAlchemy model for the risk_register table."""
    __tablename__ = "risk_register"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    persistent_id = Column(String, unique=True, nullable=False)
    org_id = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(String)
    asset_id = Column(String, nullable=False)
    lifecycle_stage = Column(String, nullable=False)
    iso23894_stage = Column(String, nullable=False)
    nist_rmf_fn = Column(String, nullable=False, index=True)
    likelihood = Column(Integer, nullable=False)
    impact = Column(Integer, nullable=False)
    # GENERATED ALWAYS AS STORED columns — DB enforces the formula.
    # Marked as Computed(sqltext="...") so SQLAlchemy does not try to INSERT
    # a value for these columns (PostgreSQL rejects non-DEFAULT writes).
    inherent_risk_score = Column(
        Integer, Computed("likelihood * impact", persisted=True)
    )
    control_effectiveness = Column(Float, nullable=False, default=0.0)
    residual_risk_score = Column(
        Integer,
        Computed(
            "GREATEST(1, ROUND((likelihood * impact)::NUMERIC * (1.0 - control_effectiveness)))",
            persisted=True,
        ),
    )
    treatment = Column(String, nullable=False)
    owner = Column(String)
    review_cadence_days = Column(Integer, nullable=False, default=90)
    last_reviewed = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    def to_risk(self) -> Risk:
        return Risk(
            risk_id=str(self.id),
            title=self.title,
            description=self.description or "",
            asset_id=self.asset_id,
            lifecycle_stage=self.lifecycle_stage,
            iso23894_stage=ISO23894Stage(self.iso23894_stage),
            nist_rmf_function=NISTAIRMFFunction(self.nist_rmf_fn),
            likelihood=self.likelihood,
            impact=self.impact,
            control_effectiveness=self.control_effectiveness,
            treatment=RiskTreatment(self.treatment),
            owner=self.owner or "",
            review_cadence_days=self.review_cadence_days,
            last_reviewed=self.last_reviewed.isoformat() if self.last_reviewed else None,
            persistent_id=self.persistent_id,
        )


class DBRiskRegister(RiskRegister):
    """DB-backed RiskRegister (production wire-up)."""
    def __init__(self, org_id: str, session_factory):
        super().__init__(org_id)
        self._session_factory = session_factory

    def add(self, risk: Risk) -> None:
        # Set persistent_id if not set
        if not risk.persistent_id:
            risk.persistent_id = f"risk-{uuid.uuid4().hex[:8]}"
        with self._session_factory() as session:
            record = RiskRecord(
                persistent_id=risk.persistent_id,
                org_id=self.org_id,
                title=risk.title,
                description=risk.description,
                asset_id=risk.asset_id,
                lifecycle_stage=risk.lifecycle_stage,
                iso23894_stage=risk.iso23894_stage.value,
                nist_rmf_fn=risk.nist_rmf_function.value,
                likelihood=risk.likelihood,
                impact=risk.impact,
                # inherent_risk_score + residual_risk_score are GENERATED ALWAYS
                # AS STORED — DB computes them from likelihood, impact,
                # control_effectiveness. We do NOT pass values.
                control_effectiveness=risk.control_effectiveness,
                treatment=risk.treatment.value,
                owner=risk.owner,
                review_cadence_days=risk.review_cadence_days,
                last_reviewed=datetime.now(timezone.utc),
            )
            session.add(record)
            session.commit()
            # Update the risk's risk_id with the DB-assigned UUID
            risk.risk_id = str(record.id)
        # Also keep the in-memory copy for backward compat
        super().add(risk)

    def summary(self) -> RiskScoreSummary:
        """Build summary from the DB."""
        with self._session_factory() as session:
            records = session.query(RiskRecord).filter(
                RiskRecord.org_id == self.org_id
            ).all()
            from collections import Counter
            bands = Counter(_band(r.residual_risk_score) for r in records)
            stages = Counter(r.iso23894_stage for r in records)
            rmfs = Counter(r.nist_rmf_fn for r in records)
            treatments = Counter(r.treatment for r in records)
            risks = [r.to_risk() for r in records]
            top = sorted(risks, key=lambda r: r.residual_risk_score, reverse=True)[:5]
            return RiskScoreSummary(
                org_id=self.org_id,
                total_risks=len(records),
                by_band=dict(bands),
                by_stage=dict(stages),
                by_nist_rmf=dict(rmfs),
                by_treatment=dict(treatments),
                highest_residual_risks=top,
                generated_at=datetime.now(timezone.utc).isoformat(),
            )


def _band(residual: int) -> str:
    if residual >= 16: return "critical"
    if residual >= 9: return "high"
    if residual >= 4: return "medium"
    return "low"


def get_db_session_factory():
    """Build the SQLAlchemy session factory from TRUSTLAYER_DB_URL env var."""
    url = os.environ.get("TRUSTLAYER_DB_URL", "postgresql+psycopg://trustlayer:trustlayer@localhost:5432/trustlayer")
    engine = create_engine(url, echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)