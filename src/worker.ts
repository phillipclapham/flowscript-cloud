/**
 * FlowScript Cloud — Cloudflare Worker Entry Point
 *
 * Wires: Hono app + D1 store + API key auth + all routes.
 * This is the production entry point for api.flowscript.org.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import type { Env } from "./core/types.js";
import type { AuthVariables } from "./middleware/auth.js";
import { authMiddleware } from "./middleware/auth.js";
import { createD1Store } from "./db/d1.js";
import { healthRoutes } from "./routes/health.js";
import { eventRoutes } from "./routes/events.js";
import { namespaceRoutes } from "./routes/namespaces.js";
import { keyRoutes } from "./routes/keys.js";
import { orgRoutes } from "./routes/orgs.js";

// Create app with typed env + variables
const app = new Hono<{ Bindings: Env; Variables: AuthVariables }>();

// Global middleware
app.use("*", cors({
  origin: ["https://flowscript.org", "https://www.flowscript.org", "http://localhost:3000"],
  allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowHeaders: ["Authorization", "Content-Type"],
  maxAge: 86400,
}));

// Inject store into context for all requests
app.use("*", async (c, next) => {
  const store = createD1Store(c.env.DB);
  c.set("store", store);
  await next();
});

// No-auth routes
app.route("/v1", healthRoutes);

// Org signup is the ONLY unauthenticated POST endpoint.
// We register it explicitly before auth middleware to avoid auth on POST /v1/orgs.
app.post("/v1/orgs", async (c) => {
  // Forward to orgRoutes signup handler
  const store = c.get("store");
  let body: { name: string; slug: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
  if (!body.name || !body.slug) {
    return c.json({ error: "Missing required fields: name, slug" }, 400);
  }
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(body.slug) || body.slug.length < 3) {
    return c.json({ error: "Invalid slug" }, 400);
  }
  const existing = await store.orgs.getOrgBySlug(body.slug);
  if (existing) {
    return c.json({ error: "Organization slug already taken" }, 409);
  }

  // Rate limiting: max 10 org signups per hour (global).
  // Edge-level CF Rate Limiting rules should also be configured in production
  // for per-IP throttling, but this is the application-level safety net.
  const recentCount = await store.orgs.countRecentOrgs(60);
  if (recentCount >= 10) {
    return c.json({ error: "Too many signups. Please try again later." }, 429);
  }
  const now = new Date().toISOString();
  const org = {
    id: crypto.randomUUID(),
    name: body.name,
    slug: body.slug,
    plan: "free" as const,
    createdAt: now,
    updatedAt: now,
  };
  await store.orgs.createOrg(org);
  const { generateApiKey } = await import("./auth/apikey.js");
  const { rawKey, keyHash } = generateApiKey();
  await store.keys.createKey({
    id: keyHash,
    orgId: org.id,
    role: "org_admin",
    scopeType: "org",
    scopeId: org.id,
    label: "Initial admin key",
    createdBy: null,  // bootstrap key — no creating key
    createdAt: now,
    lastUsed: null,
    revokedAt: null,
    expiresAt: null,
  });
  return c.json({ org, api_key: rawKey, key_id: keyHash,
    note: "Store this API key securely. It will not be shown again." }, 201);
});

// ALL remaining routes require auth
app.use("/v1/*", authMiddleware);

// Authenticated routes
app.route("/v1", eventRoutes);
app.route("/v1", namespaceRoutes);
app.route("/v1", keyRoutes);
app.route("/v1", orgRoutes);  // GET /v1/orgs/:slug only (POST handled above)

// 404 fallback
app.notFound((c) => {
  return c.json({ error: "Not found" }, 404);
});

// Error handler
app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json({ error: "Internal server error" }, 500);
});

export default app;
