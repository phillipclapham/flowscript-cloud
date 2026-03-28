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
app.use("*", cors());

// Inject store into context for all requests
app.use("*", async (c, next) => {
  const store = createD1Store(c.env.DB);
  c.set("store", store);
  await next();
});

// No-auth routes
app.route("/v1", healthRoutes);
app.route("/v1", orgRoutes);   // POST /v1/orgs = signup (no auth); GET /v1/orgs/:slug = needs auth (handled in route)

// Auth-required routes
app.use("/v1/events", authMiddleware);
app.use("/v1/events/*", authMiddleware);
app.use("/v1/namespaces/*", authMiddleware);
app.use("/v1/auth/*", authMiddleware);
app.use("/v1/orgs/:slug", authMiddleware);
app.use("/v1/orgs/:slug/*", authMiddleware);

app.route("/v1", eventRoutes);
app.route("/v1", namespaceRoutes);
app.route("/v1", keyRoutes);

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
