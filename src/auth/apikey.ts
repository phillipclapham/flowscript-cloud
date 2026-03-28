/**
 * API Key Authentication — hash-based key lookup with RBAC.
 *
 * Key format: fsk_{32 random bytes as hex} (68 chars total)
 * Storage: SHA256(raw_key) in DB. Raw key NEVER stored.
 * Validation: extract from Bearer header, SHA256 hash, DB lookup.
 */

import type { AuthResult, KeyStore } from "../core/types.js";
import { KEY_PREFIX } from "../core/types.js";

/**
 * Generate a new API key + its hash for storage.
 * Returns { rawKey, keyHash } — rawKey is shown once, keyHash is stored.
 */
export function generateApiKey(): { rawKey: string; keyHash: string } {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const crypto = require("node:crypto");
  const randomBytes = crypto.randomBytes(32).toString("hex");
  const rawKey = KEY_PREFIX + randomBytes;
  const keyHash = hashApiKey(rawKey);
  return { rawKey, keyHash };
}

/**
 * Hash an API key for storage/lookup. SHA-256 of the raw key string.
 */
export function hashApiKey(rawKey: string): string {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const crypto = require("node:crypto");
  return crypto.createHash("sha256").update(rawKey, "utf-8").digest("hex");
}

/**
 * Authenticate a request using the API key from the Authorization header.
 *
 * @param authHeader - The full Authorization header value.
 * @param keyStore - Key store for DB lookups.
 * @returns AuthResult if valid, null if auth fails.
 */
export type AuthResponse =
  | { ok: true; result: AuthResult }
  | { ok: false; error: string; status: number };

export async function authenticateApiKey(
  authHeader: string | null | undefined,
  keyStore: KeyStore,
): Promise<AuthResponse> {
  if (!authHeader) {
    return { ok: false, error: "Missing Authorization header", status: 401 };
  }

  // Parse Bearer token
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return { ok: false, error: "Invalid Authorization header format. Expected: Bearer fsk_...", status: 401 };
  }

  const rawKey = parts[1];
  if (!rawKey.startsWith(KEY_PREFIX)) {
    return { ok: false, error: "Invalid API key format. Expected: fsk_...", status: 401 };
  }

  // Hash and lookup
  const keyHash = hashApiKey(rawKey);
  const keyRecord = await keyStore.getKey(keyHash);

  if (!keyRecord) {
    return { ok: false, error: "Invalid API key", status: 401 };
  }

  // Check expiration
  if (keyRecord.expiresAt && new Date(keyRecord.expiresAt) < new Date()) {
    return { ok: false, error: "API key expired", status: 401 };
  }

  // Check revocation (already filtered in getKey query, but belt + suspenders)
  if (keyRecord.revokedAt) {
    return { ok: false, error: "API key revoked", status: 401 };
  }

  // Get org info for the result
  // Note: orgSlug resolution happens in middleware (needs OrgStore)
  return {
    ok: true as const,
    result: {
      orgId: keyRecord.orgId,
      orgSlug: "", // resolved by middleware
      role: keyRecord.role,
      scopeType: keyRecord.scopeType,
      scopeId: keyRecord.scopeId,
      keyId: keyRecord.id,
    },
  };
}
