/**
 * D1 Database Adapter — Cloudflare D1 implementation of store interfaces.
 *
 * CRITICAL CONSTRAINTS (from Daemon D1 research):
 * - BEGIN TRANSACTION is BLOCKED in D1 — use db.batch() for atomic operations
 * - Drizzle/Prisma .transaction() silently fails — raw SQL only
 * - INSERT OR REPLACE safer than ON CONFLICT upsert on CF's SQLite 3.41
 * - 100 bound params/query → max 20 rows per INSERT (5 cols)
 * - wrangler.toml binding name must match c.env.DB exactly
 */

import type {
  CloudStore,
  EventStore,
  KeyStore,
  WitnessStore,
  OrgStore,
  NamespaceStore,
  AlertStore,
  EventQueryOpts,
  StoredEvent,
  AuditEvent,
  ChainHead,
  ApiKeyRecord,
  Witness,
  Organization,
  Namespace,
  Alert,
} from "../core/types.js";
import { canonicalStringify } from "../core/chain.js";
import { computeEventHash } from "../core/chain.js";

/**
 * Create a CloudStore backed by Cloudflare D1.
 */
export function createD1Store(db: D1Database): CloudStore {
  return {
    events: new D1EventStore(db),
    keys: new D1KeyStore(db),
    witnesses: new D1WitnessStore(db),
    orgs: new D1OrgStore(db),
    namespaces: new D1NamespaceStore(db),
    alerts: new D1AlertStore(db),
  };
}

// =============================================================================
// Event Store
// =============================================================================

class D1EventStore implements EventStore {
  constructor(private db: D1Database) {}

  async getChainHead(namespaceId: string): Promise<ChainHead | null> {
    const row = await this.db
      .prepare("SELECT chain_head_seq, chain_head_hash, chain_head_ts FROM namespaces WHERE id = ?")
      .bind(namespaceId)
      .first<{ chain_head_seq: number | null; chain_head_hash: string | null; chain_head_ts: string | null }>();

    if (!row || row.chain_head_seq === null || row.chain_head_hash === null) {
      return null;
    }
    return {
      seq: row.chain_head_seq,
      hash: row.chain_head_hash,
      timestamp: row.chain_head_ts!,
    };
  }

  async insertEvents(namespaceId: string, events: AuditEvent[], receivedAt: string): Promise<number> {
    if (events.length === 0) return 0;

    // Build batch of INSERT statements + namespace update.
    // D1 batch() is the ONLY atomic primitive (no BEGIN TRANSACTION).
    const stmts: D1PreparedStatement[] = [];

    for (const event of events) {
      const payload = canonicalStringify(event);
      const hash = computeEventHash(event);
      const traceId = (event.data as Record<string, unknown>)?.trace_id as string | undefined;

      stmts.push(
        this.db
          .prepare(
            `INSERT OR IGNORE INTO events
             (namespace_id, seq, event_ts, event_type, session_id, trace_id, adapter, hash, prev_hash, payload, received_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            namespaceId,
            event.seq,
            event.timestamp,
            event.event,
            event.session_id,
            traceId ?? null,
            event.adapter ? JSON.stringify(event.adapter) : null,
            hash,
            event.prev_hash,
            payload,
            receivedAt,
          )
      );
    }

    // Update namespace chain head + event count with optimistic concurrency.
    // WHERE clause includes expected previous head — if another concurrent
    // request updated it first, this UPDATE affects 0 rows and we detect it.
    const lastEvent = events[events.length - 1];
    const lastHash = computeEventHash(lastEvent);
    const expectedPrevSeq = events[0].seq === 0 ? null : events[0].seq - 1;

    stmts.push(
      this.db
        .prepare(
          expectedPrevSeq === null
            ? `UPDATE namespaces
               SET chain_head_seq = ?, chain_head_hash = ?, chain_head_ts = ?,
                   last_event = ?, event_count = event_count + ?
               WHERE id = ? AND chain_head_seq IS NULL`
            : `UPDATE namespaces
               SET chain_head_seq = ?, chain_head_hash = ?, chain_head_ts = ?,
                   last_event = ?, event_count = event_count + ?
               WHERE id = ? AND chain_head_seq = ?`
        )
        .bind(
          lastEvent.seq,
          lastHash,
          lastEvent.timestamp,
          lastEvent.timestamp,
          events.length,
          namespaceId,
          ...(expectedPrevSeq === null ? [] : [expectedPrevSeq]),
        )
    );

    const results = await this.db.batch(stmts);

    // Check optimistic concurrency — last result is the UPDATE
    const updateResult = results[results.length - 1];
    if (updateResult && (updateResult as D1Result).meta?.changes === 0) {
      // Chain head was modified concurrently — caller should retry
      throw new Error("Concurrent chain head modification detected. Retry.");
    }

    return events.length;
  }

  async getEvents(
    namespaceId: string,
    opts: EventQueryOpts,
  ): Promise<{ events: StoredEvent[]; total: number }> {
    // Build query with filters
    const conditions = ["namespace_id = ?"];
    const params: unknown[] = [namespaceId];

    if (opts.afterSeq !== undefined) {
      conditions.push("seq > ?");
      params.push(opts.afterSeq);
    }
    if (opts.beforeSeq !== undefined) {
      conditions.push("seq < ?");
      params.push(opts.beforeSeq);
    }
    if (opts.eventType && opts.eventType.length > 0) {
      const placeholders = opts.eventType.map(() => "?").join(",");
      conditions.push(`event_type IN (${placeholders})`);
      params.push(...opts.eventType);
    }
    if (opts.sessionId) {
      conditions.push("session_id = ?");
      params.push(opts.sessionId);
    }
    if (opts.traceId) {
      conditions.push("trace_id = ?");
      params.push(opts.traceId);
    }
    if (opts.after) {
      conditions.push("event_ts > ?");
      params.push(opts.after);
    }
    if (opts.before) {
      conditions.push("event_ts < ?");
      params.push(opts.before);
    }

    const where = conditions.join(" AND ");

    // Count total
    const countResult = await this.db
      .prepare(`SELECT COUNT(*) as cnt FROM events WHERE ${where}`)
      .bind(...params)
      .first<{ cnt: number }>();
    const total = countResult?.cnt ?? 0;

    // Fetch page
    const rows = await this.db
      .prepare(
        `SELECT payload, received_at FROM events WHERE ${where} ORDER BY seq ASC LIMIT ? OFFSET ?`
      )
      .bind(...params, opts.limit, opts.offset)
      .all<{ payload: string; received_at: string }>();

    const events: StoredEvent[] = (rows.results ?? []).map((row) => ({
      ...JSON.parse(row.payload),
      received_at: row.received_at,
    }));

    return { events, total };
  }
}

// =============================================================================
// Key Store
// =============================================================================

class D1KeyStore implements KeyStore {
  constructor(private db: D1Database) {}

  async getKey(keyHash: string): Promise<ApiKeyRecord | null> {
    const row = await this.db
      .prepare("SELECT * FROM api_keys WHERE id = ? AND revoked_at IS NULL")
      .bind(keyHash)
      .first();

    if (!row) return null;
    return this.rowToKey(row);
  }

  async createKey(record: ApiKeyRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO api_keys (id, org_id, role, scope_type, scope_id, label, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        record.id,
        record.orgId,
        record.role,
        record.scopeType,
        record.scopeId,
        record.label,
        record.createdAt,
        record.expiresAt,
      )
      .run();
  }

  async revokeKey(keyId: string, revokedAt: string): Promise<void> {
    await this.db
      .prepare("UPDATE api_keys SET revoked_at = ? WHERE id = ?")
      .bind(revokedAt, keyId)
      .run();
  }

  async listKeys(orgId: string): Promise<ApiKeyRecord[]> {
    const rows = await this.db
      .prepare("SELECT * FROM api_keys WHERE org_id = ? ORDER BY created_at DESC")
      .bind(orgId)
      .all();
    return (rows.results ?? []).map((r) => this.rowToKey(r));
  }

  async touchKey(keyId: string, lastUsed: string): Promise<void> {
    await this.db
      .prepare("UPDATE api_keys SET last_used = ? WHERE id = ?")
      .bind(lastUsed, keyId)
      .run();
  }

  private rowToKey(row: Record<string, unknown>): ApiKeyRecord {
    return {
      id: row.id as string,
      orgId: row.org_id as string,
      role: row.role as ApiKeyRecord["role"],
      scopeType: row.scope_type as ApiKeyRecord["scopeType"],
      scopeId: row.scope_id as string,
      label: row.label as string | null,
      createdAt: row.created_at as string,
      lastUsed: row.last_used as string | null,
      revokedAt: row.revoked_at as string | null,
      expiresAt: row.expires_at as string | null,
    };
  }
}

// =============================================================================
// Witness Store
// =============================================================================

class D1WitnessStore implements WitnessStore {
  constructor(private db: D1Database) {}

  async createWitness(witness: Witness): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO witnesses
         (id, namespace_id, chain_head_seq, chain_head_hash, chain_head_ts,
          chain_tail_seq, chain_tail_hash, chain_tail_ts, total_events, witnessed_at, signature)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        witness.id,
        witness.namespaceId,
        witness.chainHead.seq,
        witness.chainHead.hash,
        witness.chainHead.timestamp,
        witness.chainTail.seq,
        witness.chainTail.hash,
        witness.chainTail.timestamp,
        witness.totalEvents,
        witness.witnessedAt,
        witness.signature,
      )
      .run();
  }

  async getWitnesses(
    namespaceId: string,
    opts: { after?: string; before?: string; limit: number },
  ): Promise<Witness[]> {
    const conditions = ["namespace_id = ?"];
    const params: unknown[] = [namespaceId];

    if (opts.after) {
      conditions.push("witnessed_at > ?");
      params.push(opts.after);
    }
    if (opts.before) {
      conditions.push("witnessed_at < ?");
      params.push(opts.before);
    }

    const where = conditions.join(" AND ");
    const rows = await this.db
      .prepare(`SELECT * FROM witnesses WHERE ${where} ORDER BY witnessed_at DESC LIMIT ?`)
      .bind(...params, opts.limit)
      .all();

    return (rows.results ?? []).map((r) => this.rowToWitness(r));
  }

  private rowToWitness(row: Record<string, unknown>): Witness {
    return {
      id: row.id as string,
      namespaceId: row.namespace_id as string,
      chainHead: {
        seq: row.chain_head_seq as number,
        hash: row.chain_head_hash as string,
        timestamp: row.chain_head_ts as string,
      },
      chainTail: {
        seq: row.chain_tail_seq as number,
        hash: row.chain_tail_hash as string,
        timestamp: row.chain_tail_ts as string,
      },
      totalEvents: row.total_events as number,
      witnessedAt: row.witnessed_at as string,
      signature: row.signature as string | null,
    };
  }
}

// =============================================================================
// Org Store
// =============================================================================

class D1OrgStore implements OrgStore {
  constructor(private db: D1Database) {}

  async createOrg(org: Organization): Promise<void> {
    await this.db
      .prepare(
        "INSERT INTO organizations (id, name, slug, plan, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
      )
      .bind(org.id, org.name, org.slug, org.plan, org.createdAt, org.updatedAt)
      .run();
  }

  async getOrgBySlug(slug: string): Promise<Organization | null> {
    const row = await this.db
      .prepare("SELECT * FROM organizations WHERE slug = ?")
      .bind(slug)
      .first();
    return row ? this.rowToOrg(row) : null;
  }

  async getOrgById(id: string): Promise<Organization | null> {
    const row = await this.db
      .prepare("SELECT * FROM organizations WHERE id = ?")
      .bind(id)
      .first();
    return row ? this.rowToOrg(row) : null;
  }

  private rowToOrg(row: Record<string, unknown>): Organization {
    return {
      id: row.id as string,
      name: row.name as string,
      slug: row.slug as string,
      plan: row.plan as Organization["plan"],
      createdAt: row.created_at as string,
      updatedAt: row.updated_at as string,
    };
  }
}

// =============================================================================
// Namespace Store
// =============================================================================

class D1NamespaceStore implements NamespaceStore {
  constructor(private db: D1Database) {}

  async getNamespace(orgId: string, agent: string): Promise<Namespace | null> {
    const row = await this.db
      .prepare("SELECT * FROM namespaces WHERE org_id = ? AND agent = ?")
      .bind(orgId, agent)
      .first();
    return row ? this.rowToNs(row) : null;
  }

  async getNamespaceById(id: string): Promise<Namespace | null> {
    const row = await this.db
      .prepare("SELECT * FROM namespaces WHERE id = ?")
      .bind(id)
      .first();
    return row ? this.rowToNs(row) : null;
  }

  async createNamespace(ns: Namespace): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO namespaces (id, org_id, team_id, owner, agent, created_at, event_count)
         VALUES (?, ?, ?, ?, ?, ?, 0)`
      )
      .bind(ns.id, ns.orgId, ns.teamId, ns.owner, ns.agent, ns.createdAt)
      .run();
  }

  async updateNamespaceStats(id: string, lastEvent: string, eventCount: number): Promise<void> {
    await this.db
      .prepare("UPDATE namespaces SET last_event = ?, event_count = ? WHERE id = ?")
      .bind(lastEvent, eventCount, id)
      .run();
  }

  async listNamespaces(orgId: string): Promise<Namespace[]> {
    const rows = await this.db
      .prepare("SELECT * FROM namespaces WHERE org_id = ? ORDER BY agent ASC")
      .bind(orgId)
      .all();
    return (rows.results ?? []).map((r) => this.rowToNs(r));
  }

  private rowToNs(row: Record<string, unknown>): Namespace {
    return {
      id: row.id as string,
      orgId: row.org_id as string,
      teamId: row.team_id as string | null,
      owner: row.owner as string,
      agent: row.agent as string,
      createdAt: row.created_at as string,
      lastEvent: row.last_event as string | null,
      eventCount: row.event_count as number,
    };
  }
}

// =============================================================================
// Alert Store
// =============================================================================

class D1AlertStore implements AlertStore {
  constructor(private db: D1Database) {}

  async createAlert(alert: Alert): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO alerts (id, org_id, namespace_id, type, severity, message, data, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        alert.id,
        alert.orgId,
        alert.namespaceId,
        alert.type,
        alert.severity,
        alert.message,
        alert.data ? JSON.stringify(alert.data) : null,
        alert.createdAt,
      )
      .run();
  }

  async listAlerts(orgId: string, opts: { limit: number }): Promise<Alert[]> {
    const rows = await this.db
      .prepare("SELECT * FROM alerts WHERE org_id = ? ORDER BY created_at DESC LIMIT ?")
      .bind(orgId, opts.limit)
      .all();
    return (rows.results ?? []).map((r) => ({
      id: r.id as string,
      orgId: r.org_id as string,
      namespaceId: r.namespace_id as string | null,
      type: r.type as Alert["type"],
      severity: r.severity as Alert["severity"],
      message: r.message as string,
      data: r.data ? JSON.parse(r.data as string) : null,
      createdAt: r.created_at as string,
      resolvedAt: r.resolved_at as string | null,
    }));
  }
}
