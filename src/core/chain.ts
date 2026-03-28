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

import type { AuditEvent, ChainHead, BatchVerifyResult } from "./types.js";
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
    // Sort keys lexicographically — this is what makes it canonical.
    // Filter out undefined values — matches JSON.stringify behavior and Python
    // (Python dicts can't have undefined; JS objects can).
    const raw = value as Record<string, unknown>;
    const keys = Object.keys(raw).filter((k) => raw[k] !== undefined).sort();
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
 * RUNTIME REQUIREMENT: nodejs_compat flag MUST be enabled in wrangler.toml.
 * This is a hard dependency — without it, node:crypto is unavailable in Workers
 * and all chain verification fails. The flag is set in the project's wrangler.toml.
 */
export function computeEventHash(event: AuditEvent): string {
  const jsonLine = canonicalStringify(event);
  return computeStringHash(jsonLine);
}

/**
 * Compute SHA-256 hash of a raw canonical JSON string.
 *
 * This is the PRODUCTION hash function for Cloud. It hashes the raw bytes
 * as received from the SDK, without any JSON.parse → JSON.stringify roundtrip.
 * This eliminates cross-language serialization divergence (Python 1.0 vs JS 1
 * for whole-number floats) as an entire bug class.
 *
 * Used by verifyBatchFromStrings() for real event ingestion.
 * computeEventHash() is for tests only (where we construct events in JS).
 */
export function computeStringHash(canonicalJson: string): string {
  const { createHash } = require("node:crypto") as typeof import("node:crypto");
  const hash = createHash("sha256").update(canonicalJson, "utf-8").digest("hex");
  return HASH_PREFIX + hash;
}

// =============================================================================
// Chain Verification
// =============================================================================

/**
 * Verify a batch of canonical JSON strings against an existing chain head.
 *
 * PRODUCTION PATH: Hashes raw strings directly (no JSON.parse roundtrip).
 * Eliminates cross-language float serialization divergence permanently.
 *
 * @param existingHead - The current chain head (null if empty namespace).
 * @param eventStrings - Canonical JSON strings as received from SDK.
 * @param parsedEvents - Pre-parsed events (for seq/prev_hash/timestamp extraction).
 */
export function verifyBatchFromStrings(
  existingHead: ChainHead | null,
  eventStrings: string[],
  parsedEvents: AuditEvent[],
): BatchVerifyResult {
  return verifyBatchCore(existingHead, parsedEvents, (i) => computeStringHash(eventStrings[i]));
}

/**
 * Verify a batch of parsed AuditEvent objects.
 * Used in TESTS where events are constructed in JS (no cross-language concern).
 * Hashes via canonicalStringify → SHA-256.
 */
export function verifyBatch(
  existingHead: ChainHead | null,
  events: AuditEvent[],
): BatchVerifyResult {
  return verifyBatchCore(existingHead, events, (i) => computeEventHash(events[i]));
}

/**
 * Core chain verification — parameterized on hash computation.
 * @param hashAt - Returns hash of event at index i.
 */
function verifyBatchCore(
  existingHead: ChainHead | null,
  events: AuditEvent[],
  hashAt: (index: number) => string,
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
            expected: existingHead!.hash,
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

    // Compute this event's hash for chain continuity.
    // In production (verifyBatchFromStrings), this hashes the raw SDK string.
    // In tests (verifyBatch), this hashes via canonicalStringify.
    const computedHash = hashAt(i);

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
