# FlowScript Cloud

Independent cryptographic witnessing for AI agent reasoning chains.

Your agents make decisions. FlowScript Cloud proves they happened, in order, unmodified. The SDK writes a hash-chained audit trail locally. Cloud verifies the chain and issues witness attestations — independent proof that a third party saw your agent's reasoning at a specific point in time.

This matters because the EU AI Act (Article 86) requires organizations to explain AI decisions on request. You can't explain what you didn't record, and you can't prove records weren't backdated without an independent witness. FlowScript Cloud is that witness.

**Live at [api.flowscript.org](https://api.flowscript.org/v1/health)** | [FlowScript SDK (Python)](https://pypi.org/project/flowscript-agents/) | [FlowScript SDK (TypeScript)](https://www.npmjs.com/package/flowscript-core)

## How It Works

```
SDK (Python/TS)              Cloud (api.flowscript.org)
─────────────────            ──────────────────────────
Agent writes event     →     Receives canonical JSON string
  ↓                          Computes SHA-256 of raw bytes
Appends to local             Verifies prev_hash links to chain head
  .audit.jsonl               Stores event + issues witness attestation
  ↓                              ↓
Local hash chain             Independent hash chain verification
  (source of truth)            (cryptographic witness)
```

The SDK hashes events locally. Cloud hashes the same raw bytes on receipt. If the hashes match, the chain is intact. If they don't, Cloud rejects the batch and creates an alert. No event content is ever modified by Cloud.

**Key architectural decision:** Events are transmitted as canonical JSON *strings*, not parsed objects. Cloud hashes the raw bytes exactly as the SDK serialized them. This eliminates cross-language serialization divergence (Python `1.0` vs JavaScript `1` for whole-number floats) as an entire class of bugs.

## Quick Start

### 1. Sign up (one curl)

```bash
curl -X POST https://api.flowscript.org/v1/orgs \
  -H "Content-Type: application/json" \
  -d '{"name": "My Org", "slug": "my-org"}'
```

Response includes your API key (`fsk_...`). Store it — it won't be shown again.

### 2. Wire your agent (two lines)

```python
from flowscript_agents import AuditConfig, Memory, CloudClient

cloud = CloudClient(api_key="fsk_...", namespace="my-org/my-agent")
mem = Memory.load_or_create("agent.json", options=MemoryOptions(
    audit=AuditConfig(on_event=cloud.queue_event, on_event_async=True)
))

# Use memory normally — events stream to Cloud automatically
mem.session_start("planning-session")
q = mem.question("Which database?")
mem.alternative(q, "PostgreSQL").decide(rationale="ACID compliance required")
mem.session_end()

cloud.flush()  # Send remaining buffered events
print(cloud.last_witness)  # Witness attestation from Cloud
```

Or via environment variables:
```bash
export FLOWSCRIPT_API_KEY=fsk_...
export FLOWSCRIPT_NAMESPACE=my-org/my-agent
```

### 3. Query your audit trail

```bash
# All events
curl https://api.flowscript.org/v1/namespaces/my-org/my-agent/events \
  -H "Authorization: Bearer fsk_..."

# Filter by type
curl "https://api.flowscript.org/v1/namespaces/my-org/my-agent/events?event_type=fixpoint_end"

# Witness attestations
curl https://api.flowscript.org/v1/namespaces/my-org/my-agent/witnesses \
  -H "Authorization: Bearer fsk_..."
```

## Architecture

### Chain Verification

Every event from the SDK contains a `prev_hash` field — the SHA-256 of the previous event's canonical JSON. This creates an append-only hash chain: inserting, removing, or modifying any event breaks the chain. Cloud verifies this chain on every ingestion request.

Chain breaks are rejected with a `409 Conflict` and create a critical alert. This is intentional — a broken chain means something went wrong (network corruption, tampering attempt, or a bug in the SDK).

### Witness Attestations

Each successful ingestion produces a witness record:

```json
{
  "id": "wit_b5ba2919...",
  "chain_head_seq": 42,
  "chain_head_hash": "sha256:99b0e0c9db4f...",
  "chain_tail_hash": "sha256:84b43743811e...",
  "total_events": 43,
  "witnessed_at": "2026-03-28T17:17:32.920Z"
}
```

A witness attests: "At time T, FlowScript Cloud independently verified that this agent's chain head was at sequence N with hash H." This is the compliance artifact — proof that your audit trail existed at a specific point in time and wasn't created after the fact.

### Convergence Certificates

When agents run fixpoint computations (consolidation, @fix operations), the SDK emits convergence certificates through the audit trail:

```json
{
  "event": "fixpoint_end",
  "data": {
    "name": "consolidation",
    "constraint": "L1",
    "status": "converged",
    "delta_sequence": [3, 0],
    "initial_graph_hash": "183122ca4cb2...",
    "final_graph_hash": "a7f3bc901de5...",
    "certificate_hash": "0fec2e9fe06f..."
  }
}
```

These certificates prove that a computation ran, terminated correctly, and the agent's reasoning state transitioned between known states. Cloud witnesses them alongside all other events — no special handling needed.

### RBAC

Four roles with hierarchical permissions:

| Role | Events | Namespaces | Keys | Use Case |
|------|--------|------------|------|----------|
| `org_admin` | read + write | all | manage | Organization owner |
| `team_admin` | read + write | team-scoped | manage (team) | Team lead |
| `agent` | write only | single namespace | none | Agent SDK key |
| `viewer` | read only | scoped | none | Auditor, dashboard |

Agent keys are deliberately write-only and namespace-scoped. An agent can append to its own audit trail but cannot read other agents' data or modify its own history.

## API Reference

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/health` | No | Health check |
| `POST` | `/v1/orgs` | No | Create organization (returns API key) |
| `GET` | `/v1/orgs/:slug` | Yes | Organization details |
| `POST` | `/v1/events` | Yes | Ingest events (chain-verified) |
| `POST` | `/v1/namespaces/:owner/:agent/backfill` | Yes | Upload full audit trail (empty namespaces only) |
| `GET` | `/v1/namespaces/:owner/:agent/events` | Yes | Query events (filters: event_type, session_id, trace_id, time range) |
| `GET` | `/v1/namespaces/:owner/:agent/stats` | Yes | Namespace statistics |
| `GET` | `/v1/namespaces/:owner/:agent/witnesses` | Yes | Witness attestations |
| `GET` | `/v1/orgs/:slug/namespaces` | Yes | List all namespaces |
| `POST` | `/v1/auth/keys` | Yes | Create API key (admin only) |
| `GET` | `/v1/auth/keys` | Yes | List keys (admin only) |
| `DELETE` | `/v1/auth/keys/:keyId` | Yes | Revoke key (admin only) |

### Authentication

All authenticated endpoints require a Bearer token:
```
Authorization: Bearer fsk_...
```

API keys are SHA-256 hashed before storage. The raw key is shown once at creation and never stored.

### Event Format

Events must be sent as an array of canonical JSON **strings** (not objects):

```json
{
  "namespace": "my-org/my-agent",
  "events": [
    "{\"adapter\":null,\"data\":{\"content\":\"test\"},\"event\":\"node_create\",\"prev_hash\":\"sha256:GENESIS\",\"seq\":0,\"session_id\":\"sess_1\",\"timestamp\":\"2026-03-28T10:00:00+00:00\",\"v\":1}"
  ]
}
```

The SDK handles this serialization automatically. If you're building a custom client, use `json.dumps(event, sort_keys=True, separators=(",", ":"))` (Python) or equivalent sorted-key compact serialization.

## Security Model

- **API keys** hashed with SHA-256 before storage (raw key never persisted)
- **RBAC** enforced on every request (role + scope type + scope ID)
- **Cross-tenant isolation** — keys are bound to a single organization
- **Namespace auto-creation** only for org-scoped and team-scoped keys (prevents namespace enumeration via narrow-scoped keys)
- **Rate limiting** — 10 org signups per hour (application-level), batch size limits (1,000 events per request, 5,000 per backfill)
- **Chain break alerts** — chain integrity violations create critical alerts in the database

### Known Limitations (Phase 1)

- **Witnesses are unsigned.** Phase 1 witnesses prove Cloud saw the chain but are not cryptographically signed. Phase 2 adds Ed25519 signatures.
- **Single-region.** D1 database is in ENAM (East North America). Multi-region replication is a Phase 3 feature.
- **No replay content verification.** Cloud verifies that retransmitted events form a valid chain prefix but does not verify that replayed events match what's already stored. Phase 2 enhancement.
- **No encryption at rest** beyond what Cloudflare provides at the infrastructure level. Application-level encryption is Phase 2.

## Development

```bash
# Install dependencies
npm install

# Run tests (25 unit + adversarial chain tests)
npm test

# Start local dev server (local D1)
npm run db:migrate
npm run dev

# Integration test (requires wrangler dev running)
bash test/integration/test_full_pipeline.sh

# Type check
npm run typecheck

# Deploy
npm run deploy
```

## Technology

- **Runtime:** Cloudflare Workers (edge compute, global deployment)
- **Framework:** [Hono](https://hono.dev/) (multi-runtime web framework)
- **Database:** Cloudflare D1 (SQLite at the edge)
- **Language:** TypeScript (strict mode)
- **Tests:** Vitest + bash integration suite

## License

[Business Source License 1.1](LICENSE)

- **Change Date:** March 28, 2030
- **Change License:** Apache License 2.0
- **Additional Use Grant:** You may use the Licensed Work for any purpose other than operating a competing commercial service that provides hosted audit trail verification or compliance witnessing for AI agents.

The FlowScript SDKs (flowscript-core, flowscript-agents) remain MIT licensed. The BSL applies only to the Cloud service code.

---

Built by [Phill Clapham](https://phillipclapham.com) | [FlowScript](https://flowscript.org)
