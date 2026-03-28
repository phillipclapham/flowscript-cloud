/**
 * Namespace Routes — event replay, stats, witnesses.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";
import { canPerform, canAccessNamespace } from "../core/rbac.js";

export const namespaceRoutes = new Hono<{ Variables: AuthVariables }>();

/**
 * GET /v1/namespaces/:owner/:agent/events — Replay events with filters.
 */
namespaceRoutes.get("/namespaces/:owner/:agent/events", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");
  const agentName = c.req.param("agent");

  if (!canPerform(auth.role, "read", "events")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) return c.json({ error: "Namespace not found" }, 404);
  if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
    return c.json({ error: "Namespace not found" }, 404);
  }

  const query = c.req.query();
  const eventType = query.event_type ? query.event_type.split(",") : undefined;

  const result = await store.events.getEvents(ns.id, {
    afterSeq: query.after_seq ? parseInt(query.after_seq) : undefined,
    beforeSeq: query.before_seq ? parseInt(query.before_seq) : undefined,
    eventType,
    sessionId: query.session_id,
    traceId: query.trace_id,
    after: query.after,
    before: query.before,
    limit: Math.min(parseInt(query.limit ?? "100"), 5000),
    offset: parseInt(query.offset ?? "0"),
  });

  return c.json({
    events: result.events,
    total: result.total,
    has_more: result.total > (parseInt(query.offset ?? "0") + result.events.length),
  });
});

/**
 * GET /v1/namespaces/:owner/:agent/stats — Namespace statistics.
 */
namespaceRoutes.get("/namespaces/:owner/:agent/stats", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");
  const agentName = c.req.param("agent");

  if (!canPerform(auth.role, "read", "namespaces")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) return c.json({ error: "Namespace not found" }, 404);
  if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
    return c.json({ error: "Namespace not found" }, 404);
  }

  const head = await store.events.getChainHead(ns.id);

  return c.json({
    namespace: `${ns.owner}/${ns.agent}`,
    total_events: ns.eventCount,
    first_event: ns.createdAt,
    last_event: ns.lastEvent,
    chain_valid: head !== null,
    last_witness: null, // TODO: fetch latest witness
  });
});

/**
 * GET /v1/namespaces/:owner/:agent/witnesses — Witness attestations.
 */
namespaceRoutes.get("/namespaces/:owner/:agent/witnesses", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");
  const agentName = c.req.param("agent");

  if (!canPerform(auth.role, "read", "witnesses")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const ns = await store.namespaces.getNamespace(auth.orgId, agentName);
  if (!ns) return c.json({ error: "Namespace not found" }, 404);
  if (!canAccessNamespace(auth.scopeType, auth.scopeId, ns.orgId, ns.teamId, ns.id)) {
    return c.json({ error: "Namespace not found" }, 404);
  }

  const query = c.req.query();
  const witnesses = await store.witnesses.getWitnesses(ns.id, {
    after: query.after,
    before: query.before,
    limit: Math.min(parseInt(query.limit ?? "50"), 200),
  });

  return c.json({ witnesses });
});

/**
 * GET /v1/orgs/:slug/namespaces — List all namespaces in an org.
 */
namespaceRoutes.get("/orgs/:slug/namespaces", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");

  if (!canPerform(auth.role, "read", "namespaces")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const namespaces = await store.namespaces.listNamespaces(auth.orgId);
  return c.json({
    namespaces: namespaces.map((ns) => ({
      namespace: `${ns.owner}/${ns.agent}`,
      id: ns.id,
      event_count: ns.eventCount,
      last_event: ns.lastEvent,
    })),
  });
});
