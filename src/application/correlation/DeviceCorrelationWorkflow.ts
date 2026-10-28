import { isIPv4, isIPv6 } from "node:net";

import { z } from "zod";

import type { Evidence } from "../../domain/evidence.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "../../domain/inputIssueProjection.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { EvidenceLookup } from "../EvidenceInputResolver.js";
import {
  ouiPrefix,
  ouiVendorFromTable,
  ouiVendorSearchToken,
} from "./ouiSubsets.js";

export const CORRELATE_DEVICE_EVIDENCE_OPERATION = "correlate_device_evidence";

import { correlateDeviceEvidenceInputSchema } from "../../domain/correlation/deviceCorrelationSchemas.js";
export { correlateDeviceEvidenceInputSchema };

export type CorrelateDeviceEvidenceInput = z.output<
  typeof correlateDeviceEvidenceInputSchema
>;

export type DeviceEndpointKind =
  | "mac"
  | "bluetooth"
  | "ipv4"
  | "ipv6"
  | "usb_pair";

export interface DeviceEndpoint {
  readonly kind: DeviceEndpointKind;
  readonly value: string;
  readonly normalized: string;
  readonly original_spellings: readonly string[];
  readonly locations: number;
}

export interface DeviceCorrelationRecord {
  readonly evidence_id: string;
  readonly subject: { readonly name: string; readonly sha256: string } | null;
  readonly endpoints: readonly DeviceEndpoint[];
  readonly counts: Readonly<Record<DeviceEndpointKind, number>>;
}

export interface DeviceCorrelationMatch {
  readonly normalized: string;
  readonly kind: DeviceEndpointKind;
  readonly evidence_ids: readonly string[];
  readonly confidence: "observed";
  readonly note: string | null;
}

export interface DeviceCorrelationOui {
  readonly prefix: string;
  readonly vendor: string | null;
  readonly confidence: "observed" | "derived";
}

export interface DeviceCorrelationUnparsed {
  readonly evidence_id: string;
  readonly reason: string;
}

export interface DeviceCorrelationReport {
  readonly records: readonly DeviceCorrelationRecord[];
  readonly matches: readonly DeviceCorrelationMatch[];
  readonly oui: readonly DeviceCorrelationOui[];
  readonly unparsed: readonly DeviceCorrelationUnparsed[];
  readonly limitations: readonly string[];
}

interface FoundEndpoint {
  kind: DeviceEndpointKind;
  value: string;
  normalized: string;
  spelling: string;
  count: number;
}

interface Span {
  start: number;
  end: number;
}

/**
 * Read-only selector for already-retained Evidence records. The session's
 * Evidence ledger satisfies this with `EvidenceReader["evidenceForAnalysis"]`
 * or `EvidenceReader["evidenceById"]`; the integration adapter owns the seam.
 */
export type DeviceEvidenceReader = EvidenceLookup;

const BLUETOOTH_KEY_PATTERN =
  /bluetooth|(^|[^a-z])bt([^a-z]|$)|device_address/iu;

const MAC_COLON_PATTERN =
  /(?<![0-9a-f:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![0-9a-f:])/giu;
const MAC_HYPHEN_PATTERN =
  /(?<![0-9a-f-])[0-9a-f]{2}(?:-[0-9a-f]{2}){5}(?![0-9a-f-])/giu;
const MAC_DOT_PATTERN =
  /(?<![0-9a-f])[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}(?![0-9a-f])/giu;
const MAC_PATTERNS = [MAC_COLON_PATTERN, MAC_HYPHEN_PATTERN, MAC_DOT_PATTERN];
const HEX_COLON_RUN_PATTERN = /(?<![\w:])([0-9a-f:]+)(?![\w:])/giu;
const IPV4_RUN_PATTERN = /(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])/gu;

const compareValues = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const overlapsSpan = (start: number, end: number, spans: readonly Span[]) =>
  spans.some((span) => start < span.end && span.start < end);

const macNormalized = (groups: readonly string[]): string =>
  groups.map((group) => group.toLowerCase()).join(":");

const scan48Bit = (
  text: string,
  kind: DeviceEndpointKind,
  found: FoundEndpoint[],
  spans: Span[],
): void => {
  for (const pattern of MAC_PATTERNS) {
    for (const match of text.matchAll(pattern)) {
      const spelling = match[0];
      const hex = spelling.replace(/[:.-]/gu, "");
      const normalized = macNormalized(hex.match(/../gu) ?? []);
      found.push({ kind, value: spelling, normalized, spelling, count: 1 });
      spans.push({ start: match.index, end: match.index + spelling.length });
    }
  }
};

const scanIp = (
  text: string,
  found: FoundEndpoint[],
  consumed: readonly Span[],
): void => {
  for (const match of text.matchAll(HEX_COLON_RUN_PATTERN)) {
    const token = match[1];
    if (token === undefined) continue;
    const start = match.index;
    if (start === undefined) continue;
    const end = start + token.length;
    if (
      token.includes(":") &&
      !overlapsSpan(start, end, consumed) &&
      isIPv6(token)
    )
      found.push({
        kind: "ipv6",
        value: token,
        normalized: token.toLowerCase(),
        spelling: token,
        count: 1,
      });
  }
  for (const match of text.matchAll(IPV4_RUN_PATTERN)) {
    const token = match[0];
    const start = match.index;
    if (start === undefined) continue;
    const end = start + token.length;
    if (isIPv4(token) && !overlapsSpan(start, end, consumed))
      found.push({
        kind: "ipv4",
        value: token,
        normalized: token.toLowerCase(),
        spelling: token,
        count: 1,
      });
  }
};

const normalizeUsbIdentifier = (raw: string): string | null => {
  const hex = raw.toLowerCase().replace(/^(usb)?(vid|pid)(_|:)?|^0x/u, "");
  return /^[0-9a-f]{1,4}$/u.test(hex) ? hex : null;
};

const scanUsbPair = (node: JsonValue, found: FoundEndpoint[]): void => {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return;
  const record = node as { [key: string]: JsonValue };
  const vendor = record["vendor_id"];
  const product = record["product_id"];
  if (typeof vendor !== "string" && typeof vendor !== "number") return;
  if (typeof product !== "string" && typeof product !== "number") return;
  const vendorRaw = String(vendor);
  const productRaw = String(product);
  const vendorHex = normalizeUsbIdentifier(vendorRaw);
  const productHex = normalizeUsbIdentifier(productRaw);
  if (vendorHex === null || productHex === null) return;
  found.push({
    kind: "usb_pair",
    value: `${vendorRaw}:${productRaw}`,
    normalized: `${vendorHex}:${productHex}`,
    spelling: `${vendorRaw}/${productRaw}`,
    count: 1,
  });
};

const pathIsBluetooth = (path: readonly string[]): boolean =>
  path.some((key) => BLUETOOTH_KEY_PATTERN.test(key));

const scanStringLeaf = (
  text: string,
  kind: DeviceEndpointKind,
  found: FoundEndpoint[],
): void => {
  const spans: Span[] = [];
  scan48Bit(text, kind, found, spans);
  scanIp(text, found, spans);
};

const collectTree = (node: JsonValue, found: FoundEndpoint[]): void => {
  const visit = (value: JsonValue, keyPath: readonly string[]): void => {
    if (typeof value === "string") {
      scanStringLeaf(
        value,
        pathIsBluetooth(keyPath) ? "bluetooth" : "mac",
        found,
      );
      return;
    }
    if (Array.isArray(value)) {
      for (const member of value) visit(member, keyPath);
      return;
    }
    if (value !== null && typeof value === "object") {
      scanUsbPair(value, found);
      for (const [key, member] of Object.entries(value)) {
        scanStringLeaf(
          key,
          pathIsBluetooth([...keyPath, key]) ? "bluetooth" : "mac",
          found,
        );
        visit(member, [...keyPath, key]);
      }
    }
  };
  visit(node, []);
};

interface EndpointAggregate {
  kind: DeviceEndpointKind;
  value: string;
  normalized: string;
  spellings: string[];
  locations: number;
}

const aggregateFound = (found: readonly FoundEndpoint[]): DeviceEndpoint[] => {
  const aggregates = new Map<string, EndpointAggregate>();
  for (const endpoint of found) {
    const key = `${endpoint.kind}\u0000${endpoint.normalized}`;
    const existing = aggregates.get(key);
    if (existing === undefined) {
      aggregates.set(key, {
        kind: endpoint.kind,
        value: endpoint.value,
        normalized: endpoint.normalized,
        spellings: [endpoint.spelling],
        locations: endpoint.count,
      });
      continue;
    }
    if (!existing.spellings.includes(endpoint.spelling))
      existing.spellings.push(endpoint.spelling);
    existing.locations += endpoint.count;
  }
  return [...aggregates.values()]
    .map((entry) => ({
      kind: entry.kind,
      value: entry.value,
      normalized: entry.normalized,
      original_spellings: [...entry.spellings].sort(compareValues),
      locations: entry.locations,
    }))
    .sort(
      (left, right) =>
        compareValues(left.kind, right.kind) ||
        compareValues(left.normalized, right.normalized),
    );
};

const emptyCounts = (): Record<DeviceEndpointKind, number> => ({
  mac: 0,
  bluetooth: 0,
  ipv4: 0,
  ipv6: 0,
  usb_pair: 0,
});

const buildRecord = (evidence: Evidence): DeviceCorrelationRecord => {
  const found: FoundEndpoint[] = [];
  collectTree(evidence.normalized_result, found);
  const endpoints = aggregateFound(found);
  const counts = emptyCounts();
  for (const endpoint of endpoints) counts[endpoint.kind] += 1;
  const subject = evidence.subject;
  return {
    evidence_id: evidence.evidence_id,
    subject:
      subject === null
        ? null
        : { name: subject.name, sha256: subject.digest.sha256 },
    endpoints,
    counts,
  };
};

const vendorObservedIn = (evidence: Evidence, vendorToken: string): boolean => {
  if (vendorToken === "") return false;
  let observed = `${evidence.provider.id} ${evidence.provider.name}`
    .toLowerCase()
    .includes(vendorToken);
  const visit = (node: JsonValue): void => {
    if (observed) return;
    if (typeof node === "string") {
      observed = node.toLowerCase().includes(vendorToken);
      return;
    }
    if (Array.isArray(node)) {
      for (const member of node) visit(member);
      return;
    }
    if (node !== null && typeof node === "object")
      for (const member of Object.values(node)) visit(member);
  };
  visit(evidence.normalized_result);
  return observed;
};

const isEvidenceShaped = (candidate: unknown): candidate is Evidence =>
  typeof candidate === "object" &&
  candidate !== null &&
  typeof (candidate as Evidence).evidence_id === "string" &&
  "normalized_result" in candidate;

/**
 * Cross-match address-like endpoints across caller-selected Evidence records.
 * Observed matches state only that the same normalized address appeared in
 * each listed record; OUI vendor attribution is a derived "probably" from a
 * curated registry subset; no same-device identity claim is produced.
 */
export const correlateDeviceEvidence = (
  rawInput: unknown,
  reader: DeviceEvidenceReader,
): Result<DeviceCorrelationReport, AnalysisInputError> => {
  const parsed = correlateDeviceEvidenceInputSchema.safeParse(rawInput);
  if (!parsed.success)
    return err(
      analysisInputErrorFromIssues(
        CORRELATE_DEVICE_EVIDENCE_OPERATION,
        parsed.error.issues,
        rawInput,
        { cause: parsed.error },
      ),
    );
  const unparsed: DeviceCorrelationUnparsed[] = [];
  const records: DeviceCorrelationRecord[] = [];
  const recordEvidence: Evidence[] = [];
  for (const evidenceId of parsed.data.evidence_ids) {
    const evidence = reader(evidenceId);
    if (evidence === undefined) {
      unparsed.push({
        evidence_id: evidenceId,
        reason:
          "evidence_id is not present in the current session's Evidence ledger",
      });
      continue;
    }
    if (!isEvidenceShaped(evidence) || evidence.evidence_id !== evidenceId) {
      unparsed.push({
        evidence_id: evidenceId,
        reason:
          "record does not carry an authenticated Evidence normalized_result tree",
      });
      continue;
    }
    recordEvidence.push(evidence);
    records.push(buildRecord(evidence));
  }
  const matchCandidates = new Map<
    string,
    {
      kind: DeviceEndpointKind;
      normalized: string;
      kinds: Set<DeviceEndpointKind>;
      ids: Set<string>;
    }
  >();
  for (const record of records)
    for (const endpoint of record.endpoints) {
      const valueClass =
        endpoint.kind === "mac" || endpoint.kind === "bluetooth"
          ? "48bit"
          : endpoint.kind;
      const key = `${valueClass}\u0000${endpoint.normalized}`;
      let candidate = matchCandidates.get(key);
      if (candidate === undefined) {
        candidate = {
          kind: endpoint.kind,
          normalized: endpoint.normalized,
          kinds: new Set(),
          ids: new Set(),
        };
        matchCandidates.set(key, candidate);
      }
      candidate.kinds.add(endpoint.kind);
      candidate.ids.add(record.evidence_id);
    }
  const matches: DeviceCorrelationMatch[] = [];
  for (const candidate of matchCandidates.values()) {
    if (candidate.ids.size < 2) continue;
    const mixed =
      candidate.kinds.has("mac") && candidate.kinds.has("bluetooth");
    matches.push({
      normalized: candidate.normalized,
      kind:
        mixed && candidate.kinds.has("bluetooth")
          ? "bluetooth"
          : candidate.kind,
      evidence_ids: [...candidate.ids].sort(compareValues),
      confidence: "observed",
      note: mixed
        ? "the same normalized address was labeled mac in one record and bluetooth in another"
        : null,
    });
  }
  matches.sort(
    (left, right) =>
      compareValues(left.kind, right.kind) ||
      compareValues(left.normalized, right.normalized),
  );
  const ouiRows: DeviceCorrelationOui[] = [];
  const seenPrefixes = new Set<string>();
  for (const record of records)
    for (const endpoint of record.endpoints) {
      if (endpoint.kind !== "mac" && endpoint.kind !== "bluetooth") continue;
      const prefix = ouiPrefix(endpoint.normalized);
      if (prefix === null || seenPrefixes.has(prefix)) continue;
      seenPrefixes.add(prefix);
      const vendor = ouiVendorFromTable(prefix);
      if (vendor === null) {
        ouiRows.push({ prefix, vendor: null, confidence: "derived" });
        continue;
      }
      const token = ouiVendorSearchToken(vendor);
      ouiRows.push({
        prefix,
        vendor,
        confidence: recordEvidence.some((correlationRecord) =>
          vendorObservedIn(correlationRecord, token),
        )
          ? "observed"
          : "derived",
      });
    }
  ouiRows.sort((left, right) => compareValues(left.prefix, right.prefix));
  return ok({
    records,
    matches,
    oui: ouiRows,
    unparsed,
    limitations: [
      "A match states only that the exact same normalized address spelling was observed in each listed evidence record; no same-device claim is made.",
      "Bluetooth peripheral addresses can rotate (resolvable-private addresses), so the absence of a match is not proof of non-identity between records.",
      "OUI vendor attribution comes from a curated, non-exhaustive IEEE-registry subset shipped at authoring time and never refreshed at runtime; vendor: null means the prefix was unrecognized, not that it is unregistered, and every OUI vendor claim remains a derived 'probably' even when the vendor name was also observed in a record.",
      "Endpoint extraction walks the normalized_result trees only; values present solely in raw_result, parameters, or Evidence subjects are not correlated.",
      "Extraction is value-shape based: dotted-quad strings that are not addresses (for example component version numbers like 1.2.3.4) still validate as IPv4 and are reported as ipv4 endpoints; callers judge context from the record's operation.",
      "48-bit colon spellings are labeled bluetooth only when an enclosing key name mentions bluetooth (device_address, bt_, bluetooth); otherwise they are labeled mac regardless of the record's operation.",
      "Colon-hex runs that overlap a 48-bit address spelling are never re-classified as IPv6, and IPv4-in-IPv6 mixed spellings are classified only as their embedded IPv4 component.",
    ],
  });
};
