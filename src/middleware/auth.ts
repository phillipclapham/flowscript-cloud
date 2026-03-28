/**
 * Auth Middleware — Hono middleware for API key authentication.
 *
 * Injects AuthResult into Hono context for downstream route handlers.
 */

import { createMiddleware } from "hono/factory";
import type { AuthResult, CloudStore } from "../core/types.js";
import { authenticateApiKey } from "../auth/apikey.js";

/** Extended Hono variables available to route handlers. */
export interface AuthVariables {
  auth: AuthResult;
  store: CloudStore;
}

/**
 * Hono middleware that authenticates requests via API key.
 * Sets c.var.auth with the AuthResult on success.
 * Returns 401/403 on failure.
 */
export const authMiddleware = createMiddleware<{ Variables: AuthVariables }>(
  async (c, next) => {
    const store = c.get("store");
    const authHeader = c.req.header("Authorization");
    const authResponse = await authenticateApiKey(authHeader, store.keys);

    if (!authResponse.ok) {
      return c.json({ error: authResponse.error }, authResponse.status as 401);
    }

    const auth = authResponse.result;

    // Resolve org slug
    const org = await store.orgs.getOrgById(auth.orgId);
    if (!org) {
      return c.json({ error: "Organization not found" }, 401);
    }
    auth.orgSlug = org.slug;

    // Touch key last_used (fire-and-forget — don't block the request)
    store.keys.touchKey(auth.keyId, new Date().toISOString()).catch((e) => {
      console.error("touchKey failed:", e);
    });

    c.set("auth", auth);
    await next();
  },
);
