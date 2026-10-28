import type { AnalysisError } from "../analysisErrorBase.js";
import type { Result } from "../result.js";
import type { ProtocolSessionFact } from "./protocolModelLearner.js";

/** Messages one capture yielded, with the identity REA verified for it. */
export interface ProtocolMessageReadResult {
  readonly sessions: readonly ProtocolSessionFact[];
  readonly sha256: string;
  readonly bytes: number;
  readonly format: "pcap" | "pcapng" | "other";
  readonly packets: number;
  readonly limitations: readonly string[];
}

/**
 * Boundary over one saved capture's message projection. Packet-file parsing
 * belongs to the pcap lane; the learning lane consumes its parsed messages.
 */
export interface ProtocolMessageSourcePort {
  read(
    path: string,
    options?: { readonly signal?: AbortSignal; readonly timeoutMs?: number },
  ): Promise<Result<ProtocolMessageReadResult, AnalysisError>>;
  close(): Promise<void>;
}
