/**
 * Event Ingestion Route — POST /v1/events
 *
 * The core pipeline: authenticate → resolve namespace → verify chain → store → witness.
 * This is where the compliance value lives.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";
import type { EventIngestionRequest } from "../core/types.js";
import { verifyBatch } from "../core/chain.js";
import { canPerform, canAccessNamespace } from "../core/rbac.js";
import { createWitness, createGenesisWitness } from "../core/witness.js";
import { GENESIS_HASH } from "../core/types.js";

export const eventRoutes = new Hono<{ Variables: AuthVariables }>();

/**
 * POST /v1/events — Ingest audit events with chain verification.
 */
eventRoutes.post("/events", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");

  // RBAC: only agent and org_admin can write events
  if (!canPerform(auth.role, "write", "events")) {
    return c.json({ error: "Forbidden: insufficient role for event ingestion" }, 403);
  }

  // Parse request body
  let body: EventIngestionRequest;
  try {
    body = await c.req.json<EventIngestionRequest>();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  if (!body.namespace || !body.events || !Array.isArray(body.events)) {
    return c.json({ error: "Missing required fields: namespace, events" }, 400);
  }

  if (body.events.length === 0) {
    return c.json({ error: "Empty events array" }, 400);
  }

  // Parse namespace "owner/agent" format
  const nsParts = body.namespace.split("/");
  if (nsParts.length !== 2 || !nsParts[0] || !nsParts[1]) {
    return c.json({ error: "Invalid namespace format. Expected: owner/agent" }, 400);
  }
  const [, agentName] = nsParts;

  // Resolve or create namespace
  let ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) {
    // Auto-create namespace on first event ingestion
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const crypto = require("node:crypto");
    const nsId = crypto.randomUUID();
    ns = {
      id: nsId,
      orgId: auth.orgId,
      teamId: null,
      owner: auth.orgSlug,
      agent: agentName,
      createdAt: new Date().toISOString(),
      lastEvent: null,
      eventCount: 0,
    };
    await store.namespaces.createNamespace(ns);
  }

  // RBAC: verify key scope grants access to this namespace
  if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
    // Return 404 (not 403) to avoid namespace enumeration
    return c.json({ error: "Namespace not found" }, 404);
  }

  // Get existing chain head
  const existingHead = await store.events.getChainHead(ns.id);

  // Verify the event batch
  const verifyResult = verifyBatch(existingHead, body.events);

  if (!verifyResult.valid) {
    // Chain break — create alert and return error
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const crypto = require("node:crypto");
    await store.alerts.createAlert({
      id: crypto.randomUUID(),
      orgId: auth.orgId,
      namespaceId: ns.id,
      type: verifyResult.break!.type === "duplicate_genesis" ? "duplicate_genesis" : "chain_break",
      severity: "critical",
      message: verifyResult.break!.message,
      data: {
        expected: verifyResult.break!.expected,
        received: verifyResult.break!.received,
        atSeq: verifyResult.break!.atSeq,
      },
      createdAt: new Date().toISOString(),
      resolvedAt: null,
    });

    return c.json(
      {
        error: "chain_break",
        message: verifyResult.break!.message,
        expected_prev_hash: verifyResult.break!.expected,
        received_prev_hash: verifyResult.break!.received,
        last_known_seq: existingHead?.seq ?? -1,
      },
      409,
    );
  }

  // No new events (pure replay) — return success without storing
  if (verifyResult.accepted === 0) {
    return c.json({
      accepted: 0,
      witness: null,
      message: "All events already ingested (replay)",
    });
  }

  // Store new events
  const newEvents = body.events.slice(body.events.length - verifyResult.accepted);
  const receivedAt = new Date().toISOString();
  await store.events.insertEvents(ns.id, newEvents, receivedAt);

  // Generate witness attestation
  const totalEvents = ns.eventCount + verifyResult.accepted;
  const isGenesisChain = existingHead === null;
  const witness = isGenesisChain
    ? createGenesisWitness(ns.id, verifyResult.newHead!, totalEvents)
    : createWitness(
        ns.id,
        verifyResult.newHead!,
        existingHead!.seq,
        existingHead!.hash,
        existingHead!.timestamp,
        totalEvents,
      );
  await store.witnesses.createWitness(witness);

  return c.json({
    accepted: verifyResult.accepted,
    witness: {
      id: witness.id,
      chain_head_seq: witness.chainHead.seq,
      chain_head_hash: witness.chainHead.hash,
      witnessed_at: witness.witnessedAt,
    },
  });
});

/**
 * POST /v1/namespaces/:owner/:agent/backfill — Upload full audit trail.
 * Only allowed on empty namespaces.
 */
eventRoutes.post("/namespaces/:owner/:agent/backfill", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");
  const agentName = c.req.param("agent");

  if (!canPerform(auth.role, "write", "events")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  let body: { events: unknown[] };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  // Resolve namespace
  const ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) {
    return c.json({ error: "Namespace not found. Send events via POST /v1/events first." }, 404);
  }

  // Backfill only allowed on empty namespaces
  const existingHead = await store.events.getChainHead(ns.id);
  if (existingHead !== null) {
    return c.json(
      {
        error: "namespace_has_events",
        message: "Cannot backfill namespace with existing events. Use POST /v1/events for incremental streaming.",
      },
      409,
    );
  }

  // Verify the complete chain
  const events = body.events as import("../core/types.js").AuditEvent[];
  const verifyResult = verifyBatch(null, events);

  if (!verifyResult.valid) {
    return c.json(
      {
        error: "chain_break",
        message: verifyResult.break!.message,
      },
      409,
    );
  }

  // Store all events
  const receivedAt = new Date().toISOString();
  await store.events.insertEvents(ns.id, events, receivedAt);

  // Generate witness covering entire history
  const witness = createGenesisWitness(ns.id, verifyResult.newHead!, events.length);
  await store.witnesses.createWitness(witness);

  return c.json({
    accepted: events.length,
    chain_valid: true,
    witness: {
      id: witness.id,
      chain_head_seq: witness.chainHead.seq,
      chain_head_hash: witness.chainHead.hash,
      chain_tail_hash: GENESIS_HASH,
      total_events: events.length,
      witnessed_at: witness.witnessedAt,
    },
  });
});
