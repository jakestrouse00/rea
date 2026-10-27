import { expect, it } from "vitest";
import { createEvidence } from "../evidence.js";
import {
  projectAnalysisView,
  type AnalysisViewParent,
} from "./analysisView.js";

const handshake = {
  stream: "7",
  server_name: "example.example",
  record_version: "0x0301",
  hello_version: "0x0303",
  cipher_values: ["0x1301"],
  extension_types: ["0", "11"],
  curves: ["29"],
  ec_point_formats: ["0"],
  alpn: ["h2"],
  ja3: "f09d9334475ec483246499ee7a6ff1d2",
  ja4: "t12d0203h2_777cda164f4b_7638730b74bd",
};

const capture = (
  tsharkStderr: string,
  overrides: Partial<{
    tls_sni_values: string[];
    tls_sni_count: number;
    tls_handshakes: (typeof handshake)[];
    tls_handshake_count: number;
    dns_queries: {
      query: string;
      response_addresses: string[];
      response_address_count: number;
    }[];
    dns_query_count: number;
  }> = {},
): AnalysisViewParent => {
  const target = {
    path: "/recordings/input.pcap",
    sha256: "c".repeat(64),
    bytes: 24,
  };
  const report = {
    client: {
      tshark_command: "/usr/bin/tshark",
      tshark_source: "path",
      tshark_version: "4.6.6",
      capinfos_command: "/usr/bin/capinfos",
      capinfos_source: "path",
      capinfos_version: "4.6.6",
    },
    target,
    file_type: "pcap",
    encapsulation: "Ethernet",
    packet_count: 0,
    capture_start: null,
    capture_end: null,
    capture_duration_seconds: null,
    snapshot_length: null,
    endpoints: [],
    endpoint_count: 0,
    dns_queries: [],
    dns_query_count: 0,
    tls_sni_values: [],
    tls_sni_count: 0,
    tls_handshakes: [],
    tls_handshake_count: 0,
    protocol_distribution: [],
    protocol_count: 0,
    http_request_uris: [],
    http_request_uri_count: 0,
    http_uri_redaction_count: 0,
    unattributed_dns_addresses: [],
    unattributed_dns_address_count: 0,
    unattributed_dns_packet_count: 0,
    coverage: "complete",
    diagnostics: { capinfos_stderr: "", tshark_stderr: tsharkStderr },
    ...overrides,
  };
  const evidence = createEvidence(
    { ...target, format: "file" },
    { id: "fixture", name: "Fixture", version: "1" },
    {
      operation: "inspect_pcap_capture",
      parameters: { path: target.path },
      result: report,
      confidence: "derived",
      authority: "historical-reference",
    },
  );
  return {
    evidenceId: evidence.evidence_id,
    operation: evidence.operation,
    normalizedResult: report,
    subject: evidence.subject,
    limitations: evidence.limitations,
  };
};

const diagnostics = (offset: number, limit: number) =>
  ({
    kind: "pcap",
    facet: "diagnostics",
    stream: "tshark",
    offset,
    limit,
  }) as const;

it("reads historical capture Evidence without inventing executable identity", () => {
  const result = projectAnalysisView(capture(""), { kind: "summary" });
  if (!result.ok) throw result.error;
  if (result.value.kind !== "summary")
    throw new Error("Expected a packet summary.");
  if (!("client" in result.value.summary))
    throw new Error("Expected packet client facts.");
  expect(result.value.summary.client).toMatchObject({
    tshark_resolved_path: null,
    tshark_sha256: null,
    tshark_identity_status: "unresolved",
    capinfos_resolved_path: null,
    capinfos_sha256: null,
    capinfos_identity_status: "unresolved",
  });
});

it("pages diagnostics without splitting a surrogate pair", () => {
  const parent = capture("ab😀cd");
  expect(projectAnalysisView(parent, diagnostics(3, 2))).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  const first = projectAnalysisView(parent, diagnostics(0, 3));
  if (!first.ok) throw first.error;
  expect(first.value).toMatchObject({
    page: { facet: "diagnostics", text: "ab", status: "retained" },
    coverage: { examined: 2, total: 6, next_offset: 2 },
  });
  let text = "";
  for (let offset: number | null = 0; offset !== null;) {
    const page = projectAnalysisView(parent, diagnostics(offset, 3));
    if (!page.ok) throw page.error;
    if (page.value.kind !== "pcap" || page.value.page.facet !== "diagnostics")
      throw new Error("Expected a diagnostics page.");
    text += page.value.page.text;
    offset = page.value.coverage.next_offset;
  }
  expect(text).toBe("ab😀cd");
});

it("pages retained tls-handshakes facts without rerunning tshark", () => {
  const parent = capture("", {
    tls_handshakes: [handshake],
    tls_handshake_count: 1,
  });
  const page = projectAnalysisView(parent, {
    kind: "pcap",
    facet: "tls-handshakes",
    offset: 0,
    limit: 64,
  });
  if (!page.ok) throw page.error;
  if (page.value.kind !== "pcap" || page.value.page.facet !== "tls-handshakes")
    throw new Error("Expected a tls-handshakes page.");
  expect(page.value.page.items).toEqual([handshake]);
  expect(page.value.coverage).toMatchObject({
    examined: 1,
    total: 1,
    next_offset: null,
  });
  const summary = projectAnalysisView(parent, { kind: "summary" });
  if (!summary.ok) throw summary.error;
  const summaryData = (
    summary.value as unknown as {
      summary: { retained_counts: Record<string, number> };
    }
  ).summary;
  expect(summaryData.retained_counts.tls_handshakes).toBe(1);
});

it("discloses opt-in risk-plane advisories with the observational limitation only", () => {
  const parent = capture("", {
    tls_sni_values: ["js.datadome.co", "plain.example"],
    tls_sni_count: 2,
    dns_queries: [
      {
        query: "client.perimeterx.net",
        response_addresses: [],
        response_address_count: 0,
      },
    ],
    dns_query_count: 1,
    tls_handshakes: [handshake],
    tls_handshake_count: 1,
  });
  const page = projectAnalysisView(parent, {
    kind: "pcap",
    facet: "risk-plane",
    offset: 0,
    limit: 64,
  });
  if (!page.ok) throw page.error;
  if (page.value.kind !== "pcap" || page.value.page.facet !== "risk-plane")
    throw new Error("Expected a risk-plane page.");
  const advisories = page.value.page.items;
  expect(advisories).toEqual(
    expect.arrayContaining([
      expect.stringContaining("DataDome"),
      expect.stringContaining("HUMAN Security (PerimeterX)"),
      expect.stringContaining("observational disclosure only"),
    ]),
  );
  // A non-matching SNI inside the retained handshakes contributes nothing;
  // only retained host, DNS question and HTTP-host values are matched.
  expect(page.value.limitations.join(" ")).toContain(
    "Matching covers only retained SNI, DNS and HTTP-host values",
  );
  const summary = projectAnalysisView(parent, { kind: "summary" });
  if (!summary.ok) throw summary.error;
  const summaryData = (
    summary.value as unknown as {
      summary: { retained_counts: Record<string, number> };
    }
  ).summary;
  expect(summaryData.retained_counts.tls_handshakes).toBe(1);
  // The summary never carries advisories implicitly.
  expect(JSON.stringify(summaryData)).not.toContain("DataDome");
});
