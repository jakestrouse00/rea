import { expect, it } from "vitest";
import { createHash } from "node:crypto";

import { NativeAotArtifactService } from "./NativeAotArtifactService.js";
import type { NativeAotPort } from "./NativeAotPort.js";
import type {
  InspectNativeAotTypesInput,
  NativeAotArtifactInspection,
} from "../../domain/managed/nativeAotArtifact.js";
import { inspectManagedNativeAotBytes } from "../../dotnet/ManagedNativeAotImage.js";
import { buildManagedNativeAotPeFixture } from "../../dotnet/ManagedNativeAotPe.fixture.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { parseEvidence } from "../../domain/evidence.js";
import { ok } from "../../domain/result.js";

const fixture = buildManagedNativeAotPeFixture();
const SHA256 = createHash("sha256").update(fixture.bytes).digest("hex");

const completeInspection = (path: string): NativeAotArtifactInspection => ({
  ...inspectManagedNativeAotBytes(SHA256, fixture.bytes),
  artifact: {
    path,
    sha256: SHA256,
    byte_length: fixture.bytes.length,
    format: "pe",
  },
});

const provider = (
  report: NativeAotArtifactInspection,
  calls: { count: number },
): NativeAotPort => ({
  identity: { id: "fixture-nativeaot", name: "Fixture reader", version: "1" },
  inspect: (_input: InspectNativeAotTypesInput) => {
    calls.count += 1;
    return Promise.resolve(ok(report));
  },
});

it("rejects invalid input before touching the provider", async () => {
  const calls = { count: 0 };
  const service = new NativeAotArtifactService(
    provider(completeInspection("/tmp/app.exe"), calls),
  );
  for (const input of [
    { path: "relative/app.exe" },
    { path: "/tmp/app\0.exe" },
    { path: "/tmp/app.exe", offset: -1 },
    { path: "/tmp/app.exe", limit: 0 },
    { path: "/tmp/app.exe", extra: true },
  ]) {
    const result = await service.inspect(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  }
  expect(calls.count).toBe(0);
});

it("returns the complete inspection with default paging and artifact-bound Evidence", async () => {
  const calls = { count: 0 };
  const path = "/tmp/app.exe";
  const service = new NativeAotArtifactService(
    provider(completeInspection(path), calls),
  );
  const result = await service.inspect({ path });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  const evidence = result.value;
  expect(evidence.operation).toBe("inspect_nativeaot_types");
  const parsed = parseEvidence(evidence);
  expect(parsed.subject).toMatchObject({
    local_path: path,
    digest: { sha256: SHA256 },
    format: "pe",
    architecture: "x86",
  });
  const result_ = evidence.normalized_result as NativeAotArtifactInspection;
  expect(result_.paging).toMatchObject({
    offset: 0,
    total_rows: 6,
    returned_rows: 6,
    complete: true,
  });
  expect(result_.rows).toHaveLength(6);
  expect(result_.limitations.length).toBeGreaterThan(0);
  expect(evidence.locations).toContainEqual({
    kind: "file-offset-range",
    start: fixture.rtrHeaderOffset,
    end: fixture.rtrHeaderOffset + 16,
  });
  expect(calls.count).toBe(1);
});

it("pages recovered rows deterministically with exact row indexes", async () => {
  const path = "/tmp/app.exe";
  const service = new NativeAotArtifactService(
    provider(completeInspection(path), { count: 0 }),
  );
  const page = await service.inspect({ path, offset: 2, limit: 2 });
  expect(page.ok).toBe(true);
  if (!page.ok) throw page.error;
  expect(
    (page.value.normalized_result as NativeAotArtifactInspection).rows.map(
      (row) => row.index,
    ),
  ).toEqual([2, 3]);
  expect(
    (page.value.normalized_result as NativeAotArtifactInspection).paging,
  ).toEqual({
    offset: 2,
    limit: 2,
    total_rows: 6,
    returned_rows: 2,
    complete: false,
  });
  const tail = await service.inspect({ path, offset: 99, limit: 10 });
  expect(tail.ok).toBe(true);
  if (!tail.ok) throw tail.error;
  expect(
    (tail.value.normalized_result as NativeAotArtifactInspection).rows,
  ).toEqual([]);
  expect(
    (tail.value.normalized_result as NativeAotArtifactInspection).paging,
  ).toMatchObject({
    offset: 6,
    returned_rows: 0,
    complete: true,
  });
});

it("keeps paging incomplete on every page while coverage reports truncated rows", async () => {
  const path = "/tmp/app.exe";
  const admitted = completeInspection(path);
  const truncated: NativeAotArtifactInspection = {
    ...admitted,
    coverage: { ...admitted.coverage, rows_omitted: 2, truncated: true },
  };
  const service = new NativeAotArtifactService(
    provider(truncated, { count: 0 }),
  );
  const head = await service.inspect({ path, limit: 5 });
  expect(head.ok).toBe(true);
  if (!head.ok) throw head.error;
  expect(
    (head.value.normalized_result as NativeAotArtifactInspection).paging,
  ).toEqual({
    offset: 0,
    limit: 5,
    total_rows: 6,
    returned_rows: 5,
    complete: false,
  });
  const tail = await service.inspect({ path, offset: 5, limit: 5 });
  expect(tail.ok).toBe(true);
  if (!tail.ok) throw tail.error;
  expect(
    (tail.value.normalized_result as NativeAotArtifactInspection).paging,
  ).toEqual({
    offset: 5,
    limit: 5,
    total_rows: 6,
    returned_rows: 1,
    complete: false,
  });
});

it("rejects reader identity changes and malformed reader output", async () => {
  const path = "/tmp/app.exe";
  const changed = completeInspection("/tmp/other.exe");
  const malicious = await new NativeAotArtifactService(
    provider(changed, { count: 0 }),
  ).inspect({ path });
  expect(malicious.ok).toBe(false);
  if (!malicious.ok)
    expect(malicious.error).toBeInstanceOf(AnalysisOutputError);

  const malformedShape = {} as unknown as NativeAotArtifactInspection;
  const malformed = await new NativeAotArtifactService(
    provider(malformedShape, { count: 0 }),
  ).inspect({ path });
  expect(malformed.ok).toBe(false);
  if (!malformed.ok)
    expect(malformed.error).toBeInstanceOf(AnalysisOutputError);
});

it("honors cancellation before reading", async () => {
  const controller = new AbortController();
  const reason = { request: "caller cancellation" };
  controller.abort(reason);
  let calls = 0;
  const service = new NativeAotArtifactService({
    identity: { id: "fixture", name: "f", version: "1" },
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(completeInspection("/tmp/app.exe")));
    },
  });
  const result = await service.inspect(
    { path: "/tmp/app.exe" },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error.cause).toBe(reason);
  }
  expect(calls).toBe(0);
});
