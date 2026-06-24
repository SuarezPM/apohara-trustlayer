//! ISO/IEC 42001:2023 — AI Management System (AIMS) mapper.
//!
//! ISO 42001 is the only AI governance standard that is independently
//! certifiable by an external auditor (DORA, EU AI Act, and NIST AI
//! RMF are regulations or guidance). For a Track 3 (Regulated &
//! High-Stakes) demo, the certifiability claim is the differentiator.
//!
//! Fields mapped (US-05: 5 fields, not 4):
//!   - Clause 6.1 — AI risk assessment: BaaarGate 5-condition check
//!     always runs. Populated for every packet.
//!   - Clause 8.4 — Impact assessment: a static reference to the
//!     compliance crate version (the "evidence" for the assessment).
//!   - Clause 9.1 — Monitoring & measurement: the test suite + BAAAR
//!     gate composition. The 310+ tests are the measurement
//!     mechanism.
//!   - Clause 10.2 — Continual improvement: a pointer to the
//!     post-hackathon sprint as the documented improvement cycle.
//!   - Annex A.6 — AI system lifecycle stage: production (THEMIS
//!     2.0 is a deployed, Band-of-Agents-hackathon-track-3
//!     entry). The lifecycle field is the auditable "what stage
//!     of the AI lifecycle is this system in" claim.

use crate::framework::{ComplianceMap, ComplianceMapper, EvidencePacket, Framework};

/// Maps an Evidence Packet to ISO/IEC 42001:2023 clauses.
pub struct Iso42001Mapper;

impl ComplianceMapper for Iso42001Mapper {
    fn framework(&self) -> Framework {
        Framework::Iso42001
    }

    fn map(&self, packet: &EvidencePacket) -> ComplianceMap {
        // 5 fields: 6.1 (risk assessment), 8.4 (impact assessment),
        // 9.1 (monitoring), 10.2 (improvement cycle), A.6
        // (lifecycle stage).
        let mut m = ComplianceMap::new(self.framework(), 5);

        // Clause 6.1 — AI risk assessment.
        m.add_field(
            "clause_6_1_risk_assessment",
            serde_json::json!({
                "mechanism": "BaaarGate::check (5 deterministic conditions: risk_score>0.85, secret_leak, coherence<0.3, debate_rounds>=5, explicit_halt)",
                "always_invoked": true,
                "agent_decisions_observed": packet.agent_decisions.len(),
            }),
        );

        // Clause 8.4 — Impact assessment.
        m.add_field(
            "clause_8_4_impact_assessment",
            serde_json::json!({
                "ref": format!("themis-compliance v{}", env!("CARGO_PKG_VERSION")),
                "scope": "AI decision-support system for buyer-side AP invoice fraud detection",
            }),
        );

        // Clause 9.1 — Monitoring & measurement.
        m.add_field(
            "clause_9_1_monitoring_measurement",
            serde_json::json!({
                "monitoring_mechanism": "BAAAR-gate + 310+-test suite",
                "evidence_packet_emitted": true,
                "audit_log_durable": true,
            }),
        );

        // Clause 10.2 — Continual improvement.
        m.add_field(
            "clause_10_2_continual_improvement",
            serde_json::json!({
                "improvement_cycle": "post-hackathon sprint (vNext roadmap)",
                "feed": "BAAAR HALT events + tenant incident reports → compliance mapper deltas",
            }),
        );

        // Annex A.6 — AI system lifecycle stage. US-05: a 5th field
        // explicitly maps the lifecycle stage (production for the
        // hackathon demo). A real production deployment would feed
        // this from a deployment manifest.
        m.add_field(
            "annex_a_6_lifecycle_stage",
            serde_json::json!({
                "stage": "production",
                "deployment_manifest_ref": "Band of Agents Hackathon 2026-06-19 submission",
                "rollback_supported": true,
            }),
        );

        m.add_note(format!(
            "ISO/IEC 42001:2023 AIMS clauses mapped: 5/5 populated for tenant={}, invoice={}",
            packet.tenant_id, packet.invoice_id
        ));

        m
    }
}

/// Flat field struct that the SealedPacket carries
/// alongside the rekor_entry (US-05). Built from the
/// 5 ISO 42001 clauses + the lifecycle stage. `Default`
/// returns the production-shaped static claims (BAAAR is
/// always invoked, monitoring is the test suite, etc.).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Iso42001Fields {
    /// Clause 6.1 — risk_assessment_conducted: BAAAR runs every run.
    pub risk_assessment_conducted: bool,
    /// Clause 8.4 — impact_assessment_ref: compliance crate version.
    pub impact_assessment_ref: String,
    /// Clause 9.1 — monitoring_mechanism: BAAAR + tests.
    pub monitoring_mechanism: String,
    /// Clause 10.2 — improvement_cycle: documented feedback loop.
    pub improvement_cycle: String,
    /// Annex A.6 — lifecycle_stage: production / staging / etc.
    pub lifecycle_stage: String,
}

impl Default for Iso42001Fields {
    fn default() -> Self {
        Self {
            risk_assessment_conducted: true,
            impact_assessment_ref: format!("themis-compliance v{}", env!("CARGO_PKG_VERSION")),
            monitoring_mechanism: "BAAAR-gate + 310+-test suite".to_string(),
            improvement_cycle: "post-hackathon sprint (vNext roadmap)".to_string(),
            lifecycle_stage: "production".to_string(),
        }
    }
}

impl Iso42001Fields {
    /// Build a one-line human-readable summary for `themis-verify`.
    pub fn summary_line(&self) -> String {
        format!(
            "ISO 42001: risk_assessment={}, monitoring={}, lifecycle={}",
            if self.risk_assessment_conducted {
                "conducted"
            } else {
                "not_conducted"
            },
            self.monitoring_mechanism,
            self.lifecycle_stage
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use themis_agents::baaar::Outcome;
    use themis_agents::decision::{AgentDecision, DecisionType};

    fn dec(tenant: &str, dt: DecisionType) -> AgentDecision {
        AgentDecision {
            agent_id: "x".to_string(),
            tenant_id: tenant.to_string(),
            invoice_id: "inv-001".to_string(),
            decision_type: dt,
            confidence: 0.9,
            reasoning: "x".to_string(),
            timestamp_ms: 0,
            payload: serde_json::json!({}),
        }
    }

    #[test]
    fn framework_is_iso_42001() {
        assert_eq!(Iso42001Mapper.framework(), Framework::Iso42001);
        assert_eq!(Iso42001Mapper.framework().as_str(), "iso_42001");
    }

    #[test]
    fn all_5_clauses_populated_on_empty_packet() {
        // US-05: 5 fields (was 4 in the v1 plan; the 5th is
        // Annex A.6 lifecycle stage). ISO 42001 is structural
        // — populated from metadata, not decisions. Empty
        // packet still gets 5/5 (analogous to DORA art_9/art_17
        // on empty packet).
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 5);
        assert_eq!(m.total, 5);
        assert!((m.coverage_pct() - 1.0).abs() < 0.001);
    }

    #[test]
    fn all_5_clauses_populated_on_well_formed_packet() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "wayne",
            "inv-002",
            vec![
                dec("wayne", DecisionType::Extracted),
                dec("wayne", DecisionType::FraudAssessed),
                dec("wayne", DecisionType::ProvenanceSigned),
            ],
            Outcome::Approve,
        ));
        assert_eq!(m.populated, 5);
        let field_names: Vec<&str> = m.fields.iter().map(|(n, _)| *n).collect();
        assert!(field_names.contains(&"clause_6_1_risk_assessment"));
        assert!(field_names.contains(&"clause_8_4_impact_assessment"));
        assert!(field_names.contains(&"clause_9_1_monitoring_measurement"));
        assert!(field_names.contains(&"clause_10_2_continual_improvement"));
        assert!(field_names.contains(&"annex_a_6_lifecycle_stage"));
    }

    #[test]
    fn clause_6_1_marks_baaar_mechanism() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        let (name, value) = m
            .fields
            .iter()
            .find(|(n, _)| *n == "clause_6_1_risk_assessment")
            .expect("clause_6_1 must be present");
        assert_eq!(*name, "clause_6_1_risk_assessment");
        let v = value.as_object().expect("clause_6_1 must be a JSON object");
        assert_eq!(
            v.get("always_invoked").and_then(|x| x.as_bool()),
            Some(true)
        );
        assert!(
            v.get("mechanism")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .contains("BaaarGate"),
            "clause_6_1 mechanism must reference BaaarGate"
        );
    }

    #[test]
    fn clause_8_4_references_compliance_crate_version() {
        let m = Iso42001Mapper.map(&EvidencePacket::new(
            "stark",
            "inv-001",
            vec![],
            Outcome::Approve,
        ));
        let (_, value) = m
            .fields
            .iter()
            .find(|(n, _)| *n == "clause_8_4_impact_assessment")
            .expect("clause_8_4 must be present");
        let v = value.as_object().expect("clause_8_4 must be a JSON object");
        let r#ref = v.get("ref").and_then(|x| x.as_str()).unwrap_or("");
        assert!(
            r#ref.starts_with("themis-compliance v"),
            "clause_8_4 ref must start with 'themis-compliance v', got: {}",
            r#ref
        );
    }
}
