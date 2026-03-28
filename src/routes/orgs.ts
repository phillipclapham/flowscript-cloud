/**
 * Organization Routes — authenticated org management.
 *
 * NOTE: POST /v1/orgs (signup) is handled in worker.ts BEFORE auth middleware.
 * This file only contains authenticated routes (GET /v1/orgs/:slug).
 * There is intentionally NO POST handler here — that would be dead code.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";

export const orgRoutes = new Hono<{ Variables: AuthVariables }>();

/**
 * GET /v1/orgs/:slug — Organization details (authenticated).
 */
orgRoutes.get("/orgs/:slug", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");
  const slug = c.req.param("slug");

  const org = await store.orgs.getOrgBySlug(slug);
  if (!org || org.id !== auth.orgId) {
    return c.json({ error: "Organization not found" }, 404);
  }

  return c.json({ org });
});
