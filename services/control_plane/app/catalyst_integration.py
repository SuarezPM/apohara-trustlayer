from typing import Optional
"""W7.2 Catalyst Orchestrator Integration — design doc.

Per Plan v3.0 W7.2, integrate TrustLayer as the attestation substrate
for the Apohara Catalyst mesh orchestrator (when it exists) or any
compatible mesh orchestrator. TrustLayer provides per-step evidence
collection that becomes COSE_Sign1 receipts → SCITT → public verify.

## Why this matters

Per the 7th auditor brief: "Cada step del Catalyst DAG emite un
CatalystStepReceipt firmado, el OrchestrationManifest es el receipt
del grafo completo de decisiones, trustlayer_catalyst_verify(run_id)
en MCP verifica toda la ejecución."

This is what turns TrustLayer from "we can sign one thing" into
"we can sign an entire multi-agent workflow as a verifiable graph".

## Architecture

The integration is a Catalyst plugin (Rust crate, `tl-catalyst`)
that intercepts every agent step and emits a COSE_Sign1 receipt to
the local TrustLayer SCITT TS.

### Per-step receipt (AgentInteractionRecord per IETF draft-emirdag)

Per agent step, the plugin captures:
- agent_id (which agent ran)
- tool_calls (what the agent invoked, with hashes of inputs/outputs)
- input_prompt_hash (BLAKE3 of the prompt sent to the LLM)
- output_response_hash (BLAKE3 of the response)
- decision (the structured decision: verdict, action, refusal)
- latency_ms (time taken)
- context_root_hash (hash of the current context window state)
- prev_step_hash (chain to the previous step in the same run)

This gets wrapped in a COSE_Sign1 envelope signed by the agent's
Ed25519 key, then sent to the local SCITT TS as a Capsule.

### Per-Capsule collection (per IETF draft-mih-scitt-agent-action-capsule)

The plugin also implements "record every verdict, including refusals".
A blocked or denied Capsule is auditor-grade evidence that the gate
worked. No survivorship bias.

### OrchestrationManifest (the graph-level receipt)

When the DAG completes, the plugin produces an OrchestrationManifest
that:
- Lists all step receipts in DAG order (by prev_step_hash chain)
- Records the graph structure (parent-child relationships)
- Computes a root hash over all step hashes
- Submits this to the SCITT TS as a single TS query (not 1000+ small
  queries — the TS batches efficiently)
- Returns the COSE receipt with Merkle inclusion proof

The verify endpoint then walks the receipt chain, recomputes the
root hash, and confirms the TS signature.

## MCP tool

`trustlayer_catalyst_verify(run_id)` in tools_v2.rs:
- Queries the SCITT TS for the OrchestrationManifest entry
- Recomputes the root hash from each step receipt
- Checks the chain (prev_step_hash links)
- Returns the full COSE receipt with Merkle inclusion proof

This is the tool that a compliance officer calls to verify an entire
multi-agent workflow with a single COSE receipt.

## Compliance mappings (per IETF draft-emirdag-scitt-ai-agent-execution)

The Capsule format maps directly to:
- EU AI Act Art. 12(2)(a-c): automatic event logging of high-risk AI
  systems
- DORA Art. 10: ICT incident records (replayable, cryptographically
  verifiable)
- PLD Art. 9: disclosure order response (the Capsule is the artifact)
- ISO/IEC 42001:2023 Clause 8.4: AI system operation records
- NIST AI 600-1: provenance + integrity for the 12 GAI risks

## Production wire-up (W7.2.1)

1. Implement the plugin as a Rust crate `tl-catalyst` that depends on
   `tl-evidence` and uses the `apohara-sealchain` 5-layer pattern.
2. Integrate with whatever mesh orchestrator exists (if apohara-catalyst
   emerges, or any compatible orchestrator via a generic interface).
3. The plugin must be non-intrusive: no scheduler changes, no protocol
   changes. It observes (passive) the DAG execution via the
   orchestrator's event bus.
4. The COSE_Sign1 signing key is per-agent (or per-run for ephemeral
   keys). Per-run ephemeral is the safer default.
5. The SCITT TS is the same instance used for other TrustLayer
   receipts (e.g., bundle exports). One TS, multiple receipt types.

## Anti-patterns to avoid

- Recording only successful steps (survivorship bias — a hidden
  failure that's not recorded is a hidden liability)
- Storing the prompt/response content in the Capsule (PII risk).
  Only hashes, never the content itself.
- Using a different signing key for the orchestration manifest than
  the per-step receipts. This breaks the chain and makes verification
  harder. Use one key per run, with the per-step receipts signed by
  the same key (which can be per-agent or per-run).
- Submitting each step receipt individually to the SCITT TS
  (N+1 round trips for N steps). Batch into a single OrchestrationManifest
  submission.

## Reference: eidos-agi/stepproof

The closest public analog to this pattern is [eidos-agi/stepproof](https://github.com/eidos-agi/stepproof)
(April 20, 2026) — an "enforcement layer" that forces agents to stay
inside declared plans, producing evidence at every step, submitting
to an independent verifier before advancing. Pattern:
Worker → PreToolUse hook → Plan contract → Verifier (read-only) →
hash-chained audit log. Maps directly to PLD Art. 10 / EU AI Act
Art. 12 evidence requirements.

## Reference: Abraxas1010/agenthalo

[github.com/Abraxas1010/agenthalo](https://github.com/Abraxas1010/agenthalo) (Feb 21, 2026)
— Agent H.A.L.O. Human-AI Agent Lifecycle Orchestrator. Uses
NucleusDB with SHA-256 Merkle proofs + ML-DSA-65 signatures +
Certificate Transparency log. DIDComm v2 messaging with X25519+ML-KEM-768
hybrid KEM. libp2p P2P mesh + Nym mixnet. ~98K lines Rust.

Our integration is lighter: we don't need P2P mesh or DIDComm for
the basic W7.2 deliverable. We just need per-step COSE receipts
into a local SCITT TS. The agenthalo pattern is a W7.2+ stretch
goal.
"""


# ============================================================================
# Minimal W7.2 implementation stub
# ============================================================================


def agent_step_receipt(
    run_id: str,
    step_id: int,
    agent_id: str,
    tool_calls: list,
    input_prompt_hash: str,
    output_response_hash: str,
    decision: dict,
    latency_ms: int,
    context_root_hash: str,
    prev_step_hash: Optional[str] = None,
) -> dict:
    """Build a per-step receipt (COSE_Sign1 structure).

    Production wire-up signs this with Ed25519 and submits to SCITT TS.
    W7.2 stub returns the metadata structure.
    """
    import hashlib
    import json
    import time

    payload = {
        "run_id": run_id,
        "step_id": step_id,
        "agent_id": agent_id,
        "tool_calls": tool_calls,
        "input_prompt_hash": input_prompt_hash,
        "output_response_hash": output_response_hash,
        "decision": decision,
        "latency_ms": latency_ms,
        "context_root_hash": context_root_hash,
        "prev_step_hash": prev_step_hash,
        "timestamp": int(time.time()),
    }
    payload_json = json.dumps(payload, sort_keys=True)
    payload_hash = hashlib.blake2b(payload_json.encode(), digest_size=32).hexdigest()
    return {
        "step_id": step_id,
        "payload": payload,
        "payload_hash": payload_hash,
        "cose_sign1_b64": f"eyJhbGciOiJFZDI1NTE5In0.{payload_hash}",
        "disclaimers": [
            "W7.2 v3.0: stub receipt. Production signs COSE_Sign1 with Ed25519 + SCITT TS.",
        ],
    }


def orchestration_manifest(
    run_id: str,
    step_receipts: list,
) -> dict:
    """Build an OrchestrationManifest from a list of step receipts.

    Computes the root hash and returns the graph-level receipt.
    """
    import hashlib
    import json
    import time

    if not step_receipts:
        raise ValueError("at least one step receipt required")

    # Chain validation
    prev_hash = None
    for i, receipt in enumerate(step_receipts):
        if receipt.get("prev_step_hash") != prev_hash:
            raise ValueError(
                f"step {receipt['step_id']} chain mismatch: "
                f"expected {prev_hash}, got {receipt.get('prev_step_hash')}"
            )
        prev_hash = receipt.get("payload_hash")

    # Root hash = hash of all step hashes in order
    all_hashes = b""
    for r in step_receipts:
        all_hashes += r["payload_hash"].encode()
    root_hash = hashlib.blake2b(all_hashes, digest_size=32).hexdigest()

    return {
        "run_id": run_id,
        "step_count": len(step_receipts),
        "root_hash": root_hash,
        "issued_at": int(time.time()),
        "steps": [r["step_id"] for r in step_receipts],
        "disclaimers": [
            "W7.2 v3.0: stub manifest. Production submits to SCITT TS for Merkle inclusion.",
        ],
    }
