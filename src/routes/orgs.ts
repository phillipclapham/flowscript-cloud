/**
 * Organization Routes — signup and management.
 *
 * POST /v1/orgs is the signup flow (no auth required).
 * Returns org + first admin key.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";
import type { Organization, ApiKeyRecord } from "../core/types.js";
import { generateApiKey } from "../auth/apikey.js";

export const orgRoutes = new Hono<{ Variables: AuthVariables }>();

/**
 * POST /v1/orgs — Create a new organization (signup).
 * No auth required — this IS the signup flow.
 */
orgRoutes.post("/orgs", async (c) => {
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

  // Validate slug format
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/.test(body.slug) || body.slug.length < 3) {
    return c.json({
      error: "Invalid slug. Must be lowercase alphanumeric with hyphens, minimum 3 characters.",
    }, 400);
  }

  // Check slug uniqueness
  const existing = await store.orgs.getOrgBySlug(body.slug);
  if (existing) {
    return c.json({ error: "Organization slug already taken" }, 409);
  }

  // Create org
  const now = new Date().toISOString();
  const org: Organization = {
    id: crypto.randomUUID(),
    name: body.name,
    slug: body.slug,
    plan: "free",
    createdAt: now,
    updatedAt: now,
  };
  await store.orgs.createOrg(org);

  // Create first admin key (org-scoped)
  const { rawKey, keyHash } = generateApiKey();
  const keyRecord: ApiKeyRecord = {
    id: keyHash,
    orgId: org.id,
    role: "org_admin",
    scopeType: "org",
    scopeId: org.id,
    label: "Initial admin key",
    createdAt: now,
    lastUsed: null,
    revokedAt: null,
    expiresAt: null,
  };
  await store.keys.createKey(keyRecord);

  return c.json(
    {
      org,
      api_key: rawKey,
      key_id: keyHash,
      note: "Store this API key securely. It will not be shown again.",
    },
    201,
  );
});

/**
 * GET /v1/orgs/:slug — Organization details.
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
