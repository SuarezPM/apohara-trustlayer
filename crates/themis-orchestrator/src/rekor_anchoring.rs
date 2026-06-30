//! `RekorAnchoring` — wraps the optional Rekor transparency-log
//! client. Extracted from `Orchestrator` in P4.2 to reduce the
//! god-object's responsibilities.
//!
//! Behavior preserved verbatim from the original `anchor_in_rekor`
//! method on `Orchestrator`:
//! - When the client is `None`, the packet is returned unchanged
//!   (back-compat for tests / mock-only paths).
//! - When the client is `Some`, the BLAKE3 hash is anchored and the
//!   resulting `RekorEntry` is attached via `SignedPacket::wrap_with_rekor`.
//! - On Rekor failure, the packet is returned unchanged with a
//!   `tracing::warn!` — the run is not failed (the Rekor anchor is
//!   best-effort, the demo may run without `cosign` installed).

use std::sync::Arc;

use crate::packet::SignedPacket;
use themis_evidence::rekor::RekorClient;

/// Rekor anchoring collaborator.
///
/// `Some(client)` enables end-to-end anchoring on every
/// `process_invoice` run; `None` short-circuits the anchor step.
pub(crate) struct RekorAnchoring {
    client: Option<Arc<dyn RekorClient>>,
}

impl RekorAnchoring {
    /// Wrap an optional `RekorClient` (no-op when `None`).
    pub(crate) fn new(client: Option<Arc<dyn RekorClient>>) -> Self {
        Self { client }
    }

    /// `true` when a Rekor client is configured.
    pub(crate) fn is_enabled(&self) -> bool {
        self.client.is_some()
    }

    /// Anchor `signed`'s BLAKE3 hash in Rekor (when a client is
    /// configured) and return the augmented `SignedPacket` with the
    /// `rekor_entry` field populated. Returns the original `signed`
    /// unchanged when no client is configured OR when Rekor
    /// anchoring fails (the run is not failed — best-effort).
    pub(crate) async fn anchor(&self, signed: SignedPacket, tenant_id: &str) -> SignedPacket {
        let Some(rekor) = self.client.as_ref() else {
            return signed;
        };
        let blake3_hash_hex = signed.blake3_hash_hex().to_string();
        match rekor.anchor(&blake3_hash_hex, tenant_id).await {
            Ok(entry) => SignedPacket::wrap_with_rekor(
                signed.packet().clone(),
                signed.signature_hex().to_string(),
                signed.public_key_hex().to_string(),
                entry,
            ),
            Err(e) => {
                // Don't fail the whole run if Rekor is unavailable
                // (e.g. cosign missing on the demo machine); just
                // log and skip the anchor.
                tracing::warn!("[warn] Rekor anchor failed for {tenant_id}: {e}");
                signed
            }
        }
    }
}
