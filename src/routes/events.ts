/**
 * Event Ingestion Route — POST /v1/events
 *
 * The core pipeline: authenticate → resolve namespace → verify chain → store → witness.
 * This is where the compliance value lives.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";
import type { EventIngestionRequest } from "../core/types.js";
import { verifyBatchFromStrings } from "../core/chain.js";
import type { AuditEvent } from "../core/types.js";
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

  // Enforce batch size limit (D1 batch limit + Worker CPU budget)
  const MAX_BATCH_SIZE = 1000;
  if (body.events.length > MAX_BATCH_SIZE) {
    return c.json({ error: `Batch too large. Maximum ${MAX_BATCH_SIZE} events per request.` }, 413);
  }

  // Events are canonical JSON strings from the SDK.
  // Parse each for metadata + validation, keep raw strings for hashing.
  const eventStrings = body.events;
  const parsedEvents: AuditEvent[] = [];

  for (let i = 0; i < eventStrings.length; i++) {
    if (typeof eventStrings[i] !== "string") {
      return c.json({ error: `Event ${i}: must be a canonical JSON string, not ${typeof eventStrings[i]}` }, 400);
    }

    let e: AuditEvent;
    try {
      e = JSON.parse(eventStrings[i]);
    } catch {
      return c.json({ error: `Event ${i}: invalid JSON` }, 400);
    }

    // Runtime validation of parsed event fields
    if (e.v !== 1) {
      return c.json({ error: `Event ${i}: unsupported schema version ${e.v}. Expected: 1` }, 400);
    }
    if (typeof e.seq !== "number" || !Number.isInteger(e.seq) || e.seq < 0) {
      return c.json({ error: `Event ${i}: seq must be a non-negative integer` }, 400);
    }
    if (typeof e.prev_hash !== "string" || !e.prev_hash.startsWith("sha256:")) {
      return c.json({ error: `Event ${i}: prev_hash must be a string starting with "sha256:"` }, 400);
    }
    if (typeof e.timestamp !== "string" || !e.timestamp) {
      return c.json({ error: `Event ${i}: timestamp is required` }, 400);
    }
    if (typeof e.event !== "string" || !e.event) {
      return c.json({ error: `Event ${i}: event type is required` }, 400);
    }
    if (typeof e.data !== "object" || e.data === null) {
      return c.json({ error: `Event ${i}: data must be a non-null object` }, 400);
    }

    parsedEvents.push(e);
  }

  // Parse namespace "owner/agent" format
  const nsParts = body.namespace.split("/");
  if (nsParts.length !== 2 || !nsParts[0] || !nsParts[1]) {
    return c.json({ error: "Invalid namespace format. Expected: owner/agent" }, 400);
  }
  const [, agentName] = nsParts;

  // Resolve namespace (check scope BEFORE auto-creation to prevent
  // namespace enumeration/exhaustion via unauthorized keys)
  let ns = await store.namespaces.getNamespace(auth.orgId, agentName);

  if (ns) {
    // Existing namespace — verify scope access
    if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
      return c.json({ error: "Namespace not found" }, 404);
    }
  } else {
    // New namespace — verify the key has org-level or broad scope before auto-creating.
    // Namespace-scoped keys cannot auto-create (they reference a specific namespace ID
    // that doesn't exist yet). Only org-scoped and team-scoped keys can auto-create.
    if (auth.scopeType === "namespace") {
      return c.json({ error: "Namespace not found" }, 404);
    }

    const nsId = crypto.randomUUID();
    ns = {
      id: nsId,
      orgId: auth.orgId,
      teamId: auth.scopeType === "team" ? auth.scopeId : null, // F8: associate with team if team-scoped key
      owner: auth.orgSlug,
      agent: agentName,
      createdAt: new Date().toISOString(),
      lastEvent: null,
      eventCount: 0,
    };
    try {
      await store.namespaces.createNamespace(ns);
    } catch {
      // F3: Race condition — concurrent request may have created it first.
      // Re-fetch. If still not found, it's a real error.
      ns = await store.namespaces.getNamespace(auth.orgId, agentName);
      if (!ns) {
        return c.json({ error: "Failed to create namespace" }, 500);
      }
      // Verify scope on the concurrently-created namespace
      if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
        return c.json({ error: "Namespace not found" }, 404);
      }
    }
  }

  // Get existing chain head
  const existingHead = await store.events.getChainHead(ns.id);

  // Verify the event batch — hash raw strings, check parsed prev_hash/seq
  const verifyResult = verifyBatchFromStrings(existingHead, eventStrings, parsedEvents);

  if (!verifyResult.valid) {
    // Chain break — create alert and return error
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

  // No new events (pure replay) — return success without storing.
  // Note: we don't verify replay content hashes against stored events here.
  // This is architecturally correct for Phase 1:
  // - The response is identical regardless of content (no information leak)
  // - A compromised key already has read access via GET endpoints
  // - DB-level hash verification is a Phase 2 enhancement (requires query in route)
  if (verifyResult.accepted === 0) {
    return c.json({
      accepted: 0,
      witness: null,
    });
  }

  // Store new events (pass raw strings as payloads — preserves exact SDK bytes)
  const newStartIdx = eventStrings.length - verifyResult.accepted;
  const newEventStrings = eventStrings.slice(newStartIdx);
  const newParsedEvents = parsedEvents.slice(newStartIdx);
  const receivedAt = new Date().toISOString();
  await store.events.insertEventsRaw(ns.id, newEventStrings, newParsedEvents, receivedAt);

  // Generate witness attestation
  const totalEvents = ns.eventCount + verifyResult.accepted;
  const isGenesisChain = existingHead === null;
  const witness = isGenesisChain
    ? createGenesisWitness(ns.id, verifyResult.newHead!, totalEvents, newParsedEvents[0].timestamp)
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

  if (!body.events || !Array.isArray(body.events) || body.events.length === 0) {
    return c.json({ error: "Missing or empty events array" }, 400);
  }

  // Enforce batch size limit (backfill can be larger than regular ingestion)
  const MAX_BACKFILL_SIZE = 5000;
  if (body.events.length > MAX_BACKFILL_SIZE) {
    return c.json({ error: `Backfill too large. Maximum ${MAX_BACKFILL_SIZE} events. Split into multiple requests.` }, 413);
  }

  // Resolve namespace + scope check
  const ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) {
    return c.json({ error: "Namespace not found. Send events via POST /v1/events first." }, 404);
  }
  if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
    return c.json({ error: "Namespace not found" }, 404);
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

  // Backfill events are also canonical JSON strings
  const backfillStrings = body.events as string[];
  const backfillParsed: AuditEvent[] = [];
  for (let i = 0; i < backfillStrings.length; i++) {
    if (typeof backfillStrings[i] !== "string") {
      return c.json({ error: `Event ${i}: must be a canonical JSON string` }, 400);
    }
    try {
      backfillParsed.push(JSON.parse(backfillStrings[i]));
    } catch {
      return c.json({ error: `Event ${i}: invalid JSON` }, 400);
    }
  }

  // Verify the complete chain — hash raw strings for cross-language compatibility
  const verifyResult = verifyBatchFromStrings(null, backfillStrings, backfillParsed);

  if (!verifyResult.valid) {
    return c.json(
      {
        error: "chain_break",
        message: verifyResult.break!.message,
      },
      409,
    );
  }

  // Store all events (raw strings as payloads)
  const receivedAt = new Date().toISOString();
  await store.events.insertEventsRaw(ns.id, backfillStrings, backfillParsed, receivedAt);

  // Generate witness covering entire history
  const witness = createGenesisWitness(ns.id, verifyResult.newHead!, backfillParsed.length, backfillParsed[0].timestamp);
  await store.witnesses.createWitness(witness);

  return c.json({
    accepted: backfillParsed.length,
    chain_valid: true,
    witness: {
      id: witness.id,
      chain_head_seq: witness.chainHead.seq,
      chain_head_hash: witness.chainHead.hash,
      chain_tail_hash: GENESIS_HASH,
      total_events: backfillParsed.length,
      witnessed_at: witness.witnessedAt,
    },
  });
});
