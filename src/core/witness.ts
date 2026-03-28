/**
 * Witness Attestation — Cloud's proof of chain integrity.
 *
 * After successful chain verification, Cloud generates a witness record
 * attesting: "I verified the chain from tail to head, all N events valid."
 *
 * Phase 1: Unsigned (timestamp + chain boundaries + event count).
 * Phase 2+: Signed with Cloud's keypair (enterprise can verify independently).
 */

import type { Witness, ChainHead } from "./types.js";
import { GENESIS_HASH } from "./types.js";

/**
 * Generate a unique witness ID.
 * Format: wit_ + random hex (collision-resistant for high-volume ingestion).
 */
function generateWitnessId(): string {
  // crypto.randomUUID() is available globally in CF Workers and Node.js 19+
  return "wit_" + crypto.randomUUID().replace(/-/g, "");
}

/**
 * Create a witness attestation for a successful chain verification.
 *
 * @param namespaceId - The namespace this attestation covers.
 * @param newHead - The chain head after verification.
 * @param tailSeq - The oldest seq in the verified range (0 for full chain, or first new event seq).
 * @param tailHash - The hash before the verified range (GENESIS or prev chain head hash).
 * @param tailTimestamp - Timestamp of the tail event.
 * @param totalEvents - Total events in the namespace after this ingestion.
 */
export function createWitness(
  namespaceId: string,
  newHead: ChainHead,
  tailSeq: number,
  tailHash: string,
  tailTimestamp: string,
  totalEvents: number,
): Witness {
  return {
    id: generateWitnessId(),
    namespaceId,
    chainHead: {
      seq: newHead.seq,
      hash: newHead.hash,
      timestamp: newHead.timestamp,
    },
    chainTail: {
      seq: tailSeq,
      hash: tailHash,
      timestamp: tailTimestamp,
    },
    totalEvents,
    witnessedAt: new Date().toISOString(),
    signature: null, // Phase 1: unsigned
  };
}

/**
 * Create a witness for a fresh chain (starting from GENESIS).
 */
export function createGenesisWitness(
  namespaceId: string,
  newHead: ChainHead,
  totalEvents: number,
  firstEventTimestamp?: string,
): Witness {
  return createWitness(
    namespaceId,
    newHead,
    0,
    GENESIS_HASH,
    firstEventTimestamp ?? newHead.timestamp,
    totalEvents,
  );
}
