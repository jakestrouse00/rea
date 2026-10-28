import { describe, expect, it } from "vitest";

import { createEvidence, type Evidence } from "../../domain/evidence.js";
import { AnalysisInputError } from "../../domain/analysisErrorCore.js";
import type { EvidenceLookup } from "../EvidenceInputResolver.js";
import { ouiVendorFromTable } from "./ouiSubsets.js";
import {
  correlateDeviceEvidence,
  correlateDeviceEvidenceInputSchema,
} from "./DeviceCorrelationWorkflow.js";

const provider = { id: "test-provider", name: "Test Provider", version: null };

let digestCounter = 0;
const nextSha = (): string => (digestCounter++).toString(16).padStart(64, "0");

const makeEvidence = (
  result: unknown,
  options: {
    subject?: boolean;
    operation?: string;
    manufacturer?: unknown;
  } = {},
): Evidence => {
  const normalized =
    options.manufacturer === undefined
      ? result
      : {
          ...(result as Record<string, unknown>),
          manufacturer: options.manufacturer,
        };
  return createEvidence(
    options.subject === false
      ? undefined
      : {
          path: `/tmp/subject-${digestCounter}`,
          format: "pe",
          sha256: nextSha(),
        },
    provider,
    {
      operation: options.operation ?? "test_operation",
      parameters: {},
      result: normalized,
    },
  );
};

const ledgerReader = (records: readonly Evidence[]): EvidenceLookup => {
  const byId = new Map(records.map((record) => [record.evidence_id, record]));
  return (evidenceId) => byId.get(evidenceId);
};

const run = (input: unknown, records: readonly Evidence[]) => {
  const result = correlateDeviceEvidence(input, ledgerReader(records));
  if (!result.ok) throw result.error;
  return result.value;
};

describe("correlateDeviceEvidence", () => {
  it("extracts MAC, Bluetooth, IPv4, IPv6, and USB endpoints from a deep normalized tree", () => {
    const evidence = makeEvidence({
      neighbors: [
        { ip: "192.168.1.14", mac: "A4:83:E7:12:34:56" },
        { ip: "fe80::1", mac: "f0-18-98-aa-bb-cc" },
      ],
      bluetooth: { device_address: "70-ae-2a-81-f3-4b" },
      switch: { port: "cisco dot a4b2.8c3d.12ef in text" },
      usb: [
        { vendor_id: "usbvid_0b95", product_id: "usbpid_1790" },
        { vendor_id: "0x05ac", product_id: "0x12a8" },
      ],
      meta: { ipv6: "2001:db8:0:0:0:0:0:1" },
    });
    const other = makeEvidence({ filler: true });
    const report = run(
      { evidence_ids: [evidence.evidence_id, other.evidence_id] },
      [evidence, other],
    );
    const row = report.records.find(
      (record) => record.evidence_id === evidence.evidence_id,
    );
    expect(row).toBeDefined();
    expect(row!.endpoints.map((item) => [item.kind, item.normalized])).toEqual(
      expect.arrayContaining([
        ["mac", "a4:83:e7:12:34:56"],
        ["mac", "f0:18:98:aa:bb:cc"],
        ["bluetooth", "70:ae:2a:81:f3:4b"],
        ["mac", "a4:b2:8c:3d:12:ef"],
        ["ipv4", "192.168.1.14"],
        ["ipv6", "fe80::1"],
        ["ipv6", "2001:db8:0:0:0:0:0:1"],
        ["usb_pair", "0b95:1790"],
        ["usb_pair", "05ac:12a8"],
      ]),
    );
    const mac = row!.endpoints.find(
      (item) => item.normalized === "a4:83:e7:12:34:56",
    )!;
    expect(mac.original_spellings).toEqual(["A4:83:E7:12:34:56"]);
    expect(mac.locations).toBe(1);
    const usb = row!.endpoints.find((item) => item.normalized === "0b95:1790")!;
    expect(usb.original_spellings).toEqual(["usbvid_0b95/usbpid_1790"]);
    expect(row!.counts.mac).toBe(3);
    expect(row!.counts.bluetooth).toBe(1);
    expect(row!.subject!.sha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("preserves every original spelling while matching on the normalized value", () => {
    const evidence = makeEvidence({
      arp: "a4:83:e7:12:34:56",
      ndp: "A4:83:E7:12:34:56",
      windows: "A4-83-E7-12-34-56",
      cisco: "a483.e712.3456",
    });
    const other = makeEvidence({ table: [{ mac: "A4:83:E7:12:34:56" }] });
    const report = run(
      { evidence_ids: [evidence.evidence_id, other.evidence_id] },
      [evidence, other],
    );
    const row = report.records[0]!;
    const address = row.endpoints.find(
      (item) => item.normalized === "a4:83:e7:12:34:56",
    )!;
    expect(address.kind).toBe("mac");
    expect(address.original_spellings).toEqual([
      "A4-83-E7-12-34-56",
      "A4:83:E7:12:34:56",
      "a483.e712.3456",
      "a4:83:e7:12:34:56",
    ]);
    expect(address.locations).toBe(4);
    const sortedIds = [evidence.evidence_id, other.evidence_id].sort(
      (left, right) => (left < right ? -1 : left > right ? 1 : 0),
    );
    expect(report.matches).toEqual([
      {
        normalized: "a4:83:e7:12:34:56",
        kind: "mac",
        evidence_ids: sortedIds,
        confidence: "observed",
        note: null,
      },
    ]);
  });

  it("cross-matches a MAC in one record with a Bluetooth address in another without a same-device claim", () => {
    const network = makeEvidence({ neighbor_mac: "f0:18:98:aa:bb:cc" });
    const peripheral = makeEvidence({
      bluetooth: { device_address: "F0-18-98-AA-BB-CC" },
    });
    const sortedIds = [network.evidence_id, peripheral.evidence_id].sort(
      (left, right) => (left < right ? -1 : left > right ? 1 : 0),
    );
    const report = run(
      { evidence_ids: [network.evidence_id, peripheral.evidence_id] },
      [network, peripheral],
    );
    expect(report.matches).toEqual([
      {
        normalized: "f0:18:98:aa:bb:cc",
        kind: "bluetooth",
        evidence_ids: sortedIds,
        confidence: "observed",
        note: "the same normalized address was labeled mac in one record and bluetooth in another",
      },
    ]);
    expect(report.oui).toEqual([
      { prefix: "f0:18:98", vendor: "Apple, Inc.", confidence: "derived" },
    ]);
    expect(report.limitations.length).toBeGreaterThan(0);
    expect(
      report.limitations.some((line) => line.includes("resolvable-private")),
    ).toBe(true);
    expect(
      report.limitations.some((line) =>
        line.includes("no same-device claim is made"),
      ),
    ).toBe(true);
  });
});

describe("correlateDeviceEvidence records, OUI attribution and schema", () => {
  it("classifies a vendor as observed only when the vendor name appears in record content", () => {
    const evidence = makeEvidence(
      { bluetooth: { device_address: "28:11:a5:00:11:22" } },
      { manufacturer: "Bose Corporation" },
    );
    const other = makeEvidence({});
    const report = run(
      { evidence_ids: [evidence.evidence_id, other.evidence_id] },
      [evidence, other],
    );
    expect(report.oui).toEqual([
      {
        prefix: "28:11:a5",
        vendor: "Bose Corporation",
        confidence: "observed",
      },
    ]);
  });

  it("keeps vendor null for unrecognized OUI prefixes", () => {
    const evidence = makeEvidence(
      { mac: "de:ad:be:ef:00:01" },
      { subject: false },
    );
    const other = makeEvidence({});
    const report = run(
      { evidence_ids: [evidence.evidence_id, other.evidence_id] },
      [evidence, other],
    );
    expect(report.oui).toEqual([
      { prefix: "de:ad:be", vendor: null, confidence: "derived" },
    ]);
    expect(ouiVendorFromTable("de:ad:be")).toBeNull();
  });

  it("reports records with no address-like values as empty rows, not unparsed", () => {
    const plain = makeEvidence({ text: "no endpoints here" });
    const other = makeEvidence({});
    const report = run(
      { evidence_ids: [plain.evidence_id, other.evidence_id] },
      [plain, other],
    );
    expect(report.records).toHaveLength(2);
    expect(report.matches).toEqual([]);
    expect(report.unparsed).toEqual([]);
    expect(report.oui).toEqual([]);
  });

  it("reports unknown evidence ids as unparsed instead of failing the call", () => {
    const known = makeEvidence({});
    const unknownId = `ev_${"ab".repeat(32)}`;
    const report = run({ evidence_ids: [known.evidence_id, unknownId] }, [
      known,
    ]);
    expect(report.unparsed).toEqual([
      {
        evidence_id: unknownId,
        reason:
          "evidence_id is not present in the current session's Evidence ledger",
      },
    ]);
    expect(report.records.map((record) => record.evidence_id)).toEqual([
      known.evidence_id,
    ]);
  });

  it("rejects fewer-than-two distinct ids, malformed ids, and duplicate ids through the input schema", () => {
    const malformed = correlateDeviceEvidenceInputSchema.safeParse({
      evidence_ids: ["ev_zz", "ev_" + "ab".repeat(32)],
    });
    expect(malformed.success).toBe(false);
    const duplicates = correlateDeviceEvidenceInputSchema.safeParse({
      evidence_ids: ["ev_" + "ab".repeat(32), "ev_" + "ab".repeat(32)],
    });
    expect(duplicates.success).toBe(false);
    const single = correlateDeviceEvidence(
      {
        evidence_ids: ["ev_" + "ab".repeat(32)],
      },
      () => undefined,
    );
    expect(single.ok).toBe(false);
    if (!single.ok) expect(single.error).toBeInstanceOf(AnalysisInputError);
  });

  it("never fetches at runtime and keeps extraction offline", () => {
    const source = correlateDeviceEvidence.toString();
    expect(source).not.toMatch(/fetch\s*\(/u);
    expect(source).not.toMatch(/https?:\/\//iu);
  });
});
