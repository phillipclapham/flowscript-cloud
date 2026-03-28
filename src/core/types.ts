/**
 * FlowScript Cloud — Core Types
 *
 * These types define the contract between the SDK (Python/TS), Cloud service,
 * and all internal modules. Changes here ripple everywhere — treat as API.
 *
 * The SDK audit entry format is the source of truth. Cloud receives, verifies,
 * and stores these entries. Cloud never modifies event content.
 */

// =============================================================================
// Constants
// =============================================================================

/** Sentinel hash for the first event in a chain. */
export const GENESIS_HASH = "sha256:GENESIS";

/** Hash prefix used by the SDK. */
export const HASH_PREFIX = "sha256:";

/** Current schema version expected from SDK. */
export const SCHEMA_VERSION = 1;

/** API key prefix for FlowScript Cloud keys. */
export const KEY_PREFIX = "fsk_";

// =============================================================================
// SDK Event Format (inbound — matches Python AuditWriter output)
// =============================================================================

/**
 * A single audit event as produced by the FlowScript SDK.
 *
 * This is the exact shape of one line from a .audit.jsonl file.
 * Cloud receives batches of these via POST /v1/events.
 *
 * Hash chain: event.prev_hash → SHA256(canonical_json(event)) = next event's prev_hash.
 * Canonical JSON: JSON.stringify with sorted keys, no spaces (matches Python's
 * json.dumps(sort_keys=True, separators=(",",":")))
 */
export interface AuditEvent {
  /** Schema version. Currently 1. */
  v: number;
  /** Sequence number within the chain (0-indexed, monotonically increasing). */
  seq: number;
  /** ISO 8601 UTC timestamp from the SDK. */
  timestamp: string;
  /** Event type (open-ended string, SDK-defined). */
  event: string;
  /** Hash of the previous event's canonical JSON, or GENESIS_HASH for first. */
  prev_hash: string;
  /** Agent session grouping (nullable). */
  session_id: string | null;
  /** Event-specific payload (arbitrary JSON object). */
  data: Record<string, unknown>;
  /** Framework attribution (nullable). */
  adapter: { framework?: string; class?: string; operation?: string } | null;
}

// =============================================================================
// Chain Verification
// =============================================================================

/** The last known state of a namespace's event chain. */
export interface ChainHead {
  /** Last event's sequence number. */
  seq: number;
  /** Hash of the last event's canonical JSON. */
  hash: string;
  /** Timestamp of the last event. */
  timestamp: string;
}

/** Result of verifying a batch of events against an existing chain. */
export interface BatchVerifyResult {
  /** Whether the entire batch is valid. */
  valid: boolean;
  /** Number of events that passed verification (before first break). */
  accepted: number;
  /** New chain head after accepting valid events. null if nothing accepted. */
  newHead: ChainHead | null;
  /** Details of chain break, if any. */
  break?: ChainBreak;
}

/** Details of a chain integrity violation. */
export interface ChainBreak {
  /** Type of break detected. */
  type:
    | "prev_hash_mismatch"    // event's prev_hash doesn't match expected
    | "seq_gap"               // sequence number gap
    | "seq_regression"        // sequence goes backwards
    | "hash_mismatch"         // recomputed hash doesn't match claimed hash
    | "internal_break"        // batch's internal chain is broken
    | "duplicate_genesis";    // GENESIS on namespace that already has events
  /** Sequence number where break was detected. */
  atSeq: number;
  /** Human-readable description. */
  message: string;
  /** Expected value (for comparison). */
  expected?: string;
  /** Received value (for comparison). */
  received?: string;
}

// =============================================================================
// Witness Attestations
// =============================================================================

/** Witness attestation — Cloud's cryptographic proof of chain integrity. */
export interface Witness {
  /** Unique witness ID. */
  id: string;
  /** Namespace this attestation covers. */
  namespaceId: string;
  /** Chain head at time of attestation. */
  chainHead: {
    seq: number;
    hash: string;
    timestamp: string;
  };
  /** Chain tail (usually GENESIS). */
  chainTail: {
    seq: number;
    hash: string;
    timestamp: string;
  };
  /** Total events in the namespace at time of attestation (cumulative). */
  totalEvents: number;
  /** When Cloud generated this attestation. */
  witnessedAt: string;
  /** Cryptographic signature (null in Phase 1). */
  signature: string | null;
}

// =============================================================================
// Authentication & Authorization
// =============================================================================

/** RBAC roles — ordered from most to least privilege. */
export type Role = "org_admin" | "team_admin" | "viewer" | "agent";

/** Scope types for API key permissions. */
export type ScopeType = "org" | "team" | "namespace";

/** Result of authenticating a request. */
export interface AuthResult {
  /** Organization ID. */
  orgId: string;
  /** Organization slug. */
  orgSlug: string;
  /** Authenticated role. */
  role: Role;
  /** Scope type of the key. */
  scopeType: ScopeType;
  /** ID of the scoped entity. */
  scopeId: string;
  /** Key ID (SHA256 of raw key). */
  keyId: string;
}

/** API key record as stored in the database. */
export interface ApiKeyRecord {
  /** SHA256 of the raw API key. */
  id: string;
  orgId: string;
  role: Role;
  scopeType: ScopeType;
  scopeId: string;
  label: string | null;
  createdBy: string | null;  // key_id that created this key (audit trail)
  createdAt: string;
  lastUsed: string | null;
  revokedAt: string | null;
  expiresAt: string | null;
}

// =============================================================================
// Entities
// =============================================================================

/** Pricing plan tiers. */
export type Plan = "free" | "team" | "business" | "enterprise";

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: Plan;
  createdAt: string;
  updatedAt: string;
}

export interface Team {
  id: string;
  orgId: string;
  name: string;
  slug: string;
  createdAt: string;
}

export interface Namespace {
  id: string;
  orgId: string;
  teamId: string | null;
  owner: string;
  agent: string;
  createdAt: string;
  lastEvent: string | null;
  eventCount: number;
}

// =============================================================================
// Alerts
// =============================================================================

export type AlertType =
  | "chain_break"
  | "duplicate_genesis"
  | "key_compromise"
  | "rate_exceeded"
  | "anomaly";

export type AlertSeverity = "info" | "warning" | "critical";

export interface Alert {
  id: string;
  orgId: string;
  namespaceId: string | null;
  type: AlertType;
  severity: AlertSeverity;
  message: string;
  data: Record<string, unknown> | null;
  createdAt: string;
  resolvedAt: string | null;
}

// =============================================================================
// API Request/Response Types
// =============================================================================

/** POST /v1/events request body.
 *
 * Events are transmitted as canonical JSON STRINGS — the exact bytes the SDK
 * hashed when building the chain. Cloud hashes these strings directly (no
 * JSON.parse roundtrip for hashing) and JSON.parses them separately for
 * metadata extraction. This eliminates cross-language serialization divergence
 * (Python 1.0 vs JS 1 for whole-number floats) as an entire bug class.
 */
export interface EventIngestionRequest {
  namespace: string;  // "owner/agent" format
  events: string[];   // Array of canonical JSON lines (SDK-generated)
}

/** POST /v1/events success response. */
export interface EventIngestionResponse {
  accepted: number;
  witness: {
    id: string;
    chain_head_seq: number;
    chain_head_hash: string;
    witnessed_at: string;
  };
}

/** POST /v1/events error response (chain break). */
export interface ChainBreakResponse {
  error: "chain_break";
  message: string;
  expected_prev_hash?: string;
  received_prev_hash?: string;
  last_known_seq?: number;
}

/** POST /v1/orgs request body. */
export interface OrgSignupRequest {
  name: string;
  slug: string;
}

/** POST /v1/orgs response. */
export interface OrgSignupResponse {
  org: Organization;
  api_key: string;  // raw key — shown once, never again
  key_id: string;
}

// =============================================================================
// Store Interfaces (implemented by D1, SQLite, etc.)
// =============================================================================

export interface EventStore {
  getChainHead(namespaceId: string): Promise<ChainHead | null>;
  /** Store events from raw canonical JSON strings + parsed metadata. */
  insertEventsRaw(namespaceId: string, rawStrings: string[], parsedEvents: AuditEvent[], receivedAt: string): Promise<number>;
  getEvents(namespaceId: string, opts: EventQueryOpts): Promise<{ events: StoredEvent[]; total: number }>;
}

export interface EventQueryOpts {
  afterSeq?: number;
  beforeSeq?: number;
  eventType?: string[];
  sessionId?: string;
  traceId?: string;
  after?: string;
  before?: string;
  limit: number;
  offset: number;
}

/** Event as stored in the database (with server-side metadata). */
export interface StoredEvent extends AuditEvent {
  /** Server-side receipt timestamp. */
  received_at: string;
}

export interface KeyStore {
  getKey(keyHash: string): Promise<ApiKeyRecord | null>;
  createKey(record: ApiKeyRecord): Promise<void>;
  revokeKey(keyId: string, orgId: string, revokedAt: string): Promise<boolean>;
  listKeys(orgId: string): Promise<ApiKeyRecord[]>;
  touchKey(keyId: string, lastUsed: string): Promise<void>;
}

export interface WitnessStore {
  createWitness(witness: Witness): Promise<void>;
  getWitnesses(namespaceId: string, opts: { after?: string; before?: string; limit: number }): Promise<Witness[]>;
}

export interface OrgStore {
  createOrg(org: Organization): Promise<void>;
  getOrgBySlug(slug: string): Promise<Organization | null>;
  getOrgById(id: string): Promise<Organization | null>;
  countRecentOrgs(minutesAgo: number): Promise<number>;
}

export interface NamespaceStore {
  getNamespace(orgId: string, agent: string): Promise<Namespace | null>;
  getNamespaceById(id: string): Promise<Namespace | null>;
  createNamespace(ns: Namespace): Promise<void>;
  updateNamespaceStats(id: string, lastEvent: string, eventCount: number): Promise<void>;
  listNamespaces(orgId: string): Promise<Namespace[]>;
}

export interface AlertStore {
  createAlert(alert: Alert): Promise<void>;
  listAlerts(orgId: string, opts: { limit: number }): Promise<Alert[]>;
}

/** Combined store interface — all storage operations. */
export interface CloudStore {
  events: EventStore;
  keys: KeyStore;
  witnesses: WitnessStore;
  orgs: OrgStore;
  namespaces: NamespaceStore;
  alerts: AlertStore;
}

// =============================================================================
// Hono Env (Cloudflare Workers bindings)
// =============================================================================

/** Cloudflare Worker environment bindings. */
export interface Env {
  DB: D1Database;
  ENVIRONMENT: string;
}
