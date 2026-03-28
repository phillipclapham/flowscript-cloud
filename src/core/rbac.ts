/**
 * RBAC — Role-Based Access Control logic.
 *
 * Pure functions. No I/O. Determines what each role can do.
 *
 * Roles (most → least privilege):
 *   org_admin   — full org management, read all namespaces
 *   team_admin  — manage team's namespaces + keys, read team events
 *   viewer      — read events + explanations for assigned namespaces
 *   agent       — WRITE-ONLY to assigned namespace(s). Cannot read.
 */

import type { Role, ScopeType } from "./types.js";

/** HTTP methods that map to read/write operations. */
type Operation = "read" | "write" | "manage";

/** Role hierarchy — higher index = more privilege. */
const ROLE_LEVEL: Record<Role, number> = {
  agent: 0,
  viewer: 1,
  team_admin: 2,
  org_admin: 3,
};

/**
 * Check if a role can perform an operation on a resource.
 *
 * @param role - The authenticated role.
 * @param operation - What the caller wants to do.
 * @param resourceType - What kind of resource (events, keys, orgs, namespaces, witnesses, alerts).
 */
export function canPerform(
  role: Role,
  operation: Operation,
  resourceType: string,
): boolean {
  // Agent: write-only to events. Nothing else.
  if (role === "agent") {
    return operation === "write" && resourceType === "events";
  }

  // Viewer: read events, witnesses, explanations. No write, no manage.
  if (role === "viewer") {
    return (
      operation === "read" &&
      ["events", "witnesses", "namespaces", "explanations"].includes(resourceType)
    );
  }

  // Team admin: read + manage team's resources (events, keys, namespaces, witnesses)
  if (role === "team_admin") {
    if (operation === "manage" && resourceType === "orgs") return false;
    return true;
  }

  // Org admin: everything
  if (role === "org_admin") {
    return true;
  }

  return false;
}

/**
 * Check if a key's scope grants access to a specific namespace.
 *
 * @param keyScopeType - The scope type of the API key (org, team, namespace).
 * @param keyScopeId - The scope ID of the API key.
 * @param targetNamespaceOrgId - The org ID of the target namespace.
 * @param targetNamespaceTeamId - The team ID of the target namespace (nullable).
 * @param targetNamespaceId - The ID of the target namespace.
 */
export function canAccessNamespace(
  keyScopeType: ScopeType,
  keyScopeId: string,
  targetNamespaceOrgId: string,
  targetNamespaceTeamId: string | null,
  targetNamespaceId: string,
): boolean {
  switch (keyScopeType) {
    case "org":
      // Org-scoped key: access any namespace in the org
      return keyScopeId === targetNamespaceOrgId;
    case "team":
      // Team-scoped key: access namespaces in the team
      return keyScopeId === targetNamespaceTeamId;
    case "namespace":
      // Namespace-scoped key: access only this specific namespace
      return keyScopeId === targetNamespaceId;
    default:
      return false;
  }
}

/**
 * Check if role A has at least the privilege level of role B.
 */
export function hasRoleLevel(role: Role, minimumRole: Role): boolean {
  return ROLE_LEVEL[role] >= ROLE_LEVEL[minimumRole];
}
