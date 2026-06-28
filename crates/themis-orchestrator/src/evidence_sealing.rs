//! `EvidenceSealing` — wraps the optional per-tenant `EvidenceService`
//! map. Extracted from `Orchestrator` in P4.2 to reduce the
//! god-object's responsibilities.
//!
//! Behavior preserved verbatim from the original sealing block in
//! `Orchestrator::process_invoice_sealed`:
//! - `None` when no evidence services are registered (the orchestrator
//!   returns an error to the caller in this case).
//! - `seal(packet, invoice_id, tenant_id)` looks up the per-tenant
//!   service, serializes the packet to canonical JSON, and seals it
//!   propagating the `rekor_entry` from the prior `anchor_in_rekor`
//!   run.

use std::collections::HashMap;

use themis_evidence::packet::{EvidenceService, SealedPacket};

use crate::orchestrator::OrchestratorError;
use crate::packet::SignedPacket;

/// Per-tenant evidence sealing collaborator.
///
/// `Some(services)` enables the sealed-packet path on
/// `process_invoice_sealed`; `None` returns an `OrchestratorError::Evidence`.
pub(crate) struct EvidenceSealing {
    services: Option<tokio::sync::Mutex<HashMap<String, EvidenceService>>>,
}

impl EvidenceSealing {
    /// Wrap the per-tenant service map (moved; usually built once
    /// at orchestrator construction). The map matches the original
    /// `Orchestrator` storage shape (`HashMap<tenant, EvidenceService>`,
    /// not `Arc<...>`) to preserve the `&mut EvidenceService` access
    /// pattern inside `seal()`.
    pub(crate) fn new(services: HashMap<String, EvidenceService>) -> Self {
        if services.is_empty() {
            Self { services: None }
        } else {
            Self {
                services: Some(tokio::sync::Mutex::new(services)),
            }
        }
    }

    /// `true` when at least one tenant has a registered service.
    pub(crate) fn has_services(&self) -> bool {
        self.services.is_some()
    }

    /// Seal the canonical JSON of `signed.packet()` for the given
    /// tenant + invoice, propagating the `rekor_entry` from the
    /// preceding `anchor_in_rekor` run.
    pub(crate) async fn seal(
        &self,
        signed: &SignedPacket,
        tenant_id: &str,
        invoice_id: &str,
    ) -> Result<SealedPacket, OrchestratorError> {
        let evidence_lock = self.services.as_ref().ok_or_else(|| {
            OrchestratorError::Evidence(
                "no evidence service configured; use with_evidence() at construction".to_string(),
            )
        })?;
        let payload = serde_json::to_string(signed.packet()).map_err(|e| {
            OrchestratorError::Evidence(format!("serialize packet for seal: {e}"))
        })?;
        let mut map = evidence_lock.lock().await;
        let svc = map.get_mut(tenant_id).ok_or_else(|| {
            OrchestratorError::Evidence(format!("no evidence service for tenant {tenant_id}"))
        })?;
        // Propagate the Rekor entry from the inner `process_invoice`
        // run (which already invoked `anchor_in_rekor` on the
        // BLAKE3 hash) into the SealedPacket. US-A5: the PDF
        // + verifier now carry the transparency-log proof.
        svc.seal(invoice_id, &payload, signed.rekor_entry().cloned())
            .await
            .map_err(|e| OrchestratorError::Evidence(format!("seal: {e}")))
    }
}
