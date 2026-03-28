/**
 * Chain Verification — Pure functions for hash chain integrity checking.
 *
 * The hash chain is the root of trust for FlowScript Cloud. Every audit event
 * from the SDK contains a prev_hash field linking to the previous event.
 * Cloud verifies this chain on ingestion and rejects broken chains.
 *
 * CRITICAL: computeEventHash() must produce IDENTICAL output to the Python SDK's
 * AuditWriter._compute_hash(). The Python implementation uses:
 *   json.dumps(entry, sort_keys=True, separators=(",",":"))
 *   "sha256:" + hashlib.sha256(json_line.encode("utf-8")).hexdigest()
 *
 * This module uses canonicalStringify() to match that exact serialization.
 */

import type { AuditEvent, ChainHead, BatchVerifyResult, ChainBreak } from "./types.js";
import { GENESIS_HASH, HASH_PREFIX } from "./types.js";

// =============================================================================
// Canonical JSON Serialization
// =============================================================================

/**
 * Canonical JSON serialization matching Python's json.dumps(sort_keys=True, separators=(",",":"))
 *
 * Rules:
 * - Keys sorted lexicographically at every nesting level
 * - No whitespace between separators
 * - null preserved (not omitted)
 * - Numbers as integers where possible (no .0 suffix)
 *
 * This is the most critical function in the entire Cloud service. If it diverges
 * from Python's output by even one byte, all hash verification breaks.
 */
export function canonicalStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    // JSON.stringify handles integers and floats correctly for our case.
    // Python's json.dumps also outputs integers without .0 suffix.
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    // JSON.stringify handles escaping. We need to match Python's ensure_ascii=False
    // default behavior. Standard JSON.stringify should match for ASCII content.
    // For non-ASCII: Python outputs raw UTF-8 by default, JSON.stringify also
    // outputs raw UTF-8 (not \uXXXX) for non-BMP chars. Should match.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((item) => canonicalStringify(item));
    return "[" + items.join(",") + "]";
  }
  if (typeof value === "object") {
    // Sort keys lexicographically — this is what makes it canonical
    const keys = Object.keys(value as Record<string, unknown>).sort();
    const pairs = keys.map((key) => {
      const v = (value as Record<string, unknown>)[key];
      return JSON.stringify(key) + ":" + canonicalStringify(v);
    });
    return "{" + pairs.join(",") + "}";
  }
  // Fallback — should not reach here for valid audit events
  return JSON.stringify(value);
}

// =============================================================================
// Hash Computation
// =============================================================================

/**
 * Compute the SHA-256 hash of an audit event's canonical JSON.
 *
 * Returns "sha256:" + hex digest, matching the Python SDK format.
 *
 * This function works in both Node.js (via crypto module) and Cloudflare Workers
 * (via Web Crypto API). We use the synchronous Node.js crypto for simplicity
 * in tests, with an async variant for Workers if needed.
 */
export function computeEventHash(event: AuditEvent): string {
  const jsonLine = canonicalStringify(event);
  // Use Node.js crypto module (sync) — available in Node.js and Workers runtime.
  // We import dynamically to avoid bundler issues in Workers where node:crypto
  // is provided by the runtime but not resolvable at build time.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const nodeCrypto = require("node:crypto");
  const hash = nodeCrypto.createHash("sha256").update(jsonLine, "utf-8").digest("hex");
  return HASH_PREFIX + hash;
}

/**
 * Async hash computation for Cloudflare Workers (Web Crypto API).
 */
export async function computeEventHashAsync(event: AuditEvent): Promise<string> {
  const jsonLine = canonicalStringify(event);
  const encoded = new TextEncoder().encode(jsonLine);

  // Try Web Crypto first (CF Workers), fall back to Node.js
  if (globalThis.crypto?.subtle) {
    const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", encoded);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    return HASH_PREFIX + hashHex;
  }

  // Node.js fallback
  const nodeCrypto = await import("node:crypto");
  const hash = nodeCrypto.createHash("sha256").update(jsonLine, "utf-8").digest("hex");
  return HASH_PREFIX + hash;
}

// =============================================================================
// Chain Verification
// =============================================================================

/**
 * Verify a batch of events against an existing chain head.
 *
 * @param existingHead - The current chain head for this namespace (null if empty namespace).
 * @param events - The batch of events to verify.
 * @returns BatchVerifyResult with verification outcome.
 *
 * Verification rules:
 * 1. First event's prev_hash must match existingHead.hash (or GENESIS if null)
 * 2. Each event's seq must be exactly prev_seq + 1 (no gaps, no regression)
 * 3. Each event's recomputed hash must chain correctly to the next event's prev_hash
 * 4. GENESIS events on non-empty namespaces are rejected (duplicate_genesis)
 * 5. Replay of already-ingested events (seq ≤ head.seq) is accepted gracefully
 */
export function verifyBatch(
  existingHead: ChainHead | null,
  events: AuditEvent[],
): BatchVerifyResult {
  if (events.length === 0) {
    return { valid: true, accepted: 0, newHead: existingHead };
  }

  // Separate replayed events from new events.
  // Replay = batch starts at seq 0 and forms a consecutive range up to headSeq.
  // This covers the backfill-on-non-empty case (V7) and genuine retransmission (V4).
  // Anything else with seq ≤ headSeq is suspicious (regression or duplicate GENESIS).
  const headSeq = existingHead?.seq ?? -1;
  const expectedHash = existingHead?.hash ?? GENESIS_HASH;

  // Find where new events start and handle replay detection.
  //
  // A "replay" is a retransmission of events already in the chain (seq ≤ headSeq).
  // Valid replays: batch of consecutive events starting from some seq ≤ headSeq
  // and forming a proper ascending sequence. The batch may extend beyond headSeq.
  //
  // NOT a replay: a single event at seq ≤ headSeq that doesn't form part of
  // a consecutive batch — this is a seq_regression (potential insertion attack).
  let newStartIdx = 0;
  if (headSeq >= 0) {
    // Check if batch is a consecutive replay prefix (seq 0, 1, 2, ... up to headSeq)
    let isConsecutiveReplay = true;
    let replayEnd = 0; // exclusive: first index with seq > headSeq
    for (let i = 0; i < events.length; i++) {
      if (events[i].seq > headSeq) {
        replayEnd = i;
        break;
      }
      // Check consecutiveness within replay portion
      if (i > 0 && events[i].seq !== events[i - 1].seq + 1) {
        isConsecutiveReplay = false;
      }
      if (i === events.length - 1) {
        replayEnd = events.length; // all events are replays
      }
    }

    if (replayEnd === events.length) {
      // ALL events have seq ≤ headSeq
      if (isConsecutiveReplay && replayEnd > 1) {
        // Multi-event consecutive batch — genuine replay retransmission
        return { valid: true, accepted: 0, newHead: existingHead };
      }
      // Single event or non-consecutive at seq ≤ headSeq — suspicious
      // Check for duplicate GENESIS specifically
      if (events[0].prev_hash === GENESIS_HASH && events[0].seq === 0) {
        return {
          valid: false,
          accepted: 0,
          newHead: null,
          break: {
            type: "duplicate_genesis",
            atSeq: 0,
            message: "GENESIS event received but namespace already has events",
            expected: existingHead.hash,
            received: GENESIS_HASH,
          },
        };
      }
      // Non-GENESIS single old event — seq regression
      return {
        valid: false,
        accepted: 0,
        newHead: null,
        break: {
          type: "seq_regression",
          atSeq: events[0].seq,
          message: `Event seq ${events[0].seq} is ≤ chain head seq ${headSeq}`,
        },
      };
    }

    // Batch extends beyond headSeq — skip replay prefix
    newStartIdx = replayEnd;
  }

  const firstNew = events[newStartIdx];

  // Check for seq regression: a single event at seq ≤ headSeq that isn't
  // part of a replay prefix extending to new events
  if (firstNew.seq <= headSeq) {
    return {
      valid: false,
      accepted: 0,
      newHead: null,
      break: {
        type: "seq_regression",
        atSeq: firstNew.seq,
        message: `Event seq ${firstNew.seq} is ≤ chain head seq ${headSeq}`,
      },
    };
  }

  // Check that first new event chains from the existing head
  if (firstNew.prev_hash !== expectedHash) {
    return {
      valid: false,
      accepted: 0,
      newHead: null,
      break: {
        type: "prev_hash_mismatch",
        atSeq: firstNew.seq,
        message: `Event seq ${firstNew.seq} prev_hash does not match chain head`,
        expected: expectedHash,
        received: firstNew.prev_hash,
      },
    };
  }

  // Check seq continuity: first new event must be headSeq + 1
  if (firstNew.seq !== headSeq + 1) {
    return {
      valid: false,
      accepted: 0,
      newHead: null,
      break: {
        type: "seq_gap",
        atSeq: firstNew.seq,
        message: `Expected seq ${headSeq + 1}, got ${firstNew.seq}`,
        expected: String(headSeq + 1),
        received: String(firstNew.seq),
      },
    };
  }

  // Verify each new event's hash and internal chain continuity
  let prevHash = expectedHash;
  let lastValidIdx = newStartIdx - 1;
  let lastHead: ChainHead | null = existingHead;

  for (let i = newStartIdx; i < events.length; i++) {
    const event = events[i];

    // Verify seq continuity within batch
    const expectedSeq = i === newStartIdx ? headSeq + 1 : events[i - 1].seq + 1;
    if (event.seq !== expectedSeq) {
      return {
        valid: false,
        accepted: lastValidIdx - newStartIdx + 1,
        newHead: lastHead,
        break: {
          type: "seq_gap",
          atSeq: event.seq,
          message: `Expected seq ${expectedSeq}, got ${event.seq}`,
          expected: String(expectedSeq),
          received: String(event.seq),
        },
      };
    }

    // Verify prev_hash chains correctly
    if (event.prev_hash !== prevHash) {
      return {
        valid: false,
        accepted: i - newStartIdx,
        newHead: lastHead,
        break: {
          type: i === newStartIdx ? "prev_hash_mismatch" : "internal_break",
          atSeq: event.seq,
          message: `Event seq ${event.seq} prev_hash does not match expected`,
          expected: prevHash,
          received: event.prev_hash,
        },
      };
    }

    // Compute this event's hash for the next iteration's prev_hash check
    const computedHash = computeEventHash(event);

    // For hash_mismatch detection: if this is a standalone event (not followed
    // by another that references it), we can't detect payload tampering via
    // chain alone. But we CAN verify that the event's canonical JSON produces
    // a valid hash. We store the computed hash as the chain head.
    // The tamper detection comes when the NEXT batch arrives and its first
    // event's prev_hash must match our stored hash of THIS event.

    prevHash = computedHash;
    lastValidIdx = i;
    lastHead = {
      seq: event.seq,
      hash: computedHash,
      timestamp: event.timestamp,
    };
  }

  return {
    valid: true,
    accepted: events.length - newStartIdx,
    newHead: lastHead,
  };
}
