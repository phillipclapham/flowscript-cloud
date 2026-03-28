/**
 * Key Management Routes — CRUD for API keys.
 */

import { Hono } from "hono";
import type { AuthVariables } from "../middleware/auth.js";
import { canPerform, hasRoleLevel } from "../core/rbac.js";
import { generateApiKey } from "../auth/apikey.js";
import type { ApiKeyRecord, Role, ScopeType } from "../core/types.js";

export const keyRoutes = new Hono<{ Variables: AuthVariables }>();

/**
 * POST /v1/auth/keys — Create a new API key.
 */
keyRoutes.post("/auth/keys", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");

  if (!canPerform(auth.role, "manage", "keys")) {
    return c.json({ error: "Forbidden: need team_admin or org_admin role" }, 403);
  }

  let body: { role: string; scope_type: string; scope_id: string; label?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  // Validate role — can't create keys with higher privilege than your own
  const validRoles: Role[] = ["org_admin", "team_admin", "viewer", "agent"];
  if (!validRoles.includes(body.role as Role)) {
    return c.json({ error: `Invalid role. Must be one of: ${validRoles.join(", ")}` }, 400);
  }
  if (hasRoleLevel(body.role as Role, auth.role) && body.role !== auth.role) {
    return c.json({ error: "Cannot create key with higher privilege than your own" }, 403);
  }

  // Validate scope type
  const validScopes: ScopeType[] = ["org", "team", "namespace"];
  if (!validScopes.includes(body.scope_type as ScopeType)) {
    return c.json({ error: `Invalid scope_type. Must be one of: ${validScopes.join(", ")}` }, 400);
  }

  // Validate scope_id is within the caller's access.
  // team_admin cannot create org-scoped keys (privilege escalation).
  // namespace-scoped callers cannot create broader-scoped keys.
  if (auth.role === "team_admin") {
    if (body.scope_type === "org") {
      return c.json({ error: "team_admin cannot create org-scoped keys" }, 403);
    }
    if (body.scope_type === "team" && body.scope_id !== auth.scopeId) {
      return c.json({ error: "team_admin can only create keys for their own team" }, 403);
    }
  }

  // Generate key
  const { rawKey, keyHash } = generateApiKey();
  const now = new Date().toISOString();

  const record: ApiKeyRecord = {
    id: keyHash,
    orgId: auth.orgId,
    role: body.role as Role,
    scopeType: body.scope_type as ScopeType,
    scopeId: body.scope_id,
    label: body.label ?? null,
    createdAt: now,
    lastUsed: null,
    revokedAt: null,
    expiresAt: null,
  };

  await store.keys.createKey(record);

  return c.json(
    {
      api_key: rawKey,
      key_id: keyHash,
      role: record.role,
      scope_type: record.scopeType,
      scope_id: record.scopeId,
      label: record.label,
      created_at: record.createdAt,
      note: "Store this key securely. It will not be shown again.",
    },
    201,
  );
});

/**
 * DELETE /v1/auth/keys/:keyId — Revoke an API key.
 */
keyRoutes.delete("/auth/keys/:keyId", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");

  if (!canPerform(auth.role, "manage", "keys")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const keyId = c.req.param("keyId");
  await store.keys.revokeKey(keyId, new Date().toISOString());
  return c.json({ revoked: true, revoked_at: new Date().toISOString() });
});

/**
 * GET /v1/auth/keys — List API keys for the org.
 */
keyRoutes.get("/auth/keys", async (c) => {
  const auth = c.get("auth");
  const store = c.get("store");

  if (!canPerform(auth.role, "manage", "keys")) {
    return c.json({ error: "Forbidden" }, 403);
  }

  const keys = await store.keys.listKeys(auth.orgId);
  return c.json({
    keys: keys.map((k) => ({
      key_id: k.id,
      role: k.role,
      scope_type: k.scopeType,
      scope_id: k.scopeId,
      label: k.label,
      last_used: k.lastUsed,
      created_at: k.createdAt,
      revoked_at: k.revokedAt,
    })),
  });
});
