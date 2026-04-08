# FlowScript Cloud

> **Archived.** The compliance witnessing concepts explored here — hash-chain verification, witness attestations, convergence certificates, RBAC — informed the audit trail architecture in [**anneal-memory**](https://github.com/phillipclapham/anneal-memory). anneal-memory ships a tamper-evident hash-chained audit trail as a built-in feature, with `on_event` callbacks for streaming to external systems. The hosted witnessing service at `api.flowscript.org` is no longer active.

---

## What This Was

Independent cryptographic witnessing for AI agent reasoning chains. The SDK wrote a hash-chained audit trail locally; Cloud verified the chain and issued witness attestations — independent proof that a third party saw the agent's reasoning at a specific point in time.

Built on Cloudflare Workers + D1 (SQLite at the edge) with Hono. 68 tests (unit + adversarial chain tests).

### Key Architecture Decisions

- **Canonical JSON strings, not parsed objects** — events transmitted as raw bytes, hashed identically on both sides. Eliminated cross-language serialization divergence as an entire class of bugs.
- **Chain verification on ingestion** — every event's `prev_hash` verified against chain head before storage. Chain breaks rejected with 409 Conflict.
- **Witness attestations** — proof that audit trail existed at time T, wasn't created after the fact.
- **Convergence certificates** — fixpoint computations (consolidation, @fix) produce hash-chained attestations of state transitions.
- **Write-only agent keys** — agents can append to their audit trail but cannot read other agents' data or modify history.

### Technology

- Runtime: Cloudflare Workers
- Framework: [Hono](https://hono.dev/)
- Database: Cloudflare D1
- Language: TypeScript (strict mode)
- License: BSL 1.1 (converts to Apache 2.0 on March 28, 2030)

---

## Related

- **[anneal-memory](https://github.com/phillipclapham/anneal-memory)** — Where the compliance concepts live now
- **[FlowScript](https://github.com/phillipclapham/flowscript)** — TypeScript SDK, notation spec, web editor
- **[flowscript-agents](https://github.com/phillipclapham/flowscript-agents)** — Python SDK

---

Built by [Phill Clapham](https://phillipclapham.com)
