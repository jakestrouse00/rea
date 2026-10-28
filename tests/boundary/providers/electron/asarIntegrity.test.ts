import { expect, test } from "vitest";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { createPackage, getRawHeader } from "@electron/asar";

import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { AsarIntegrityProvider } from "../../../../src/electron/AsarIntegrityProvider.js";
import {
  inspectAsarIntegrityInputSchema,
  type AsarIntegrityReport,
} from "../../../../src/domain/electron/asarIntegrity.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

const buildArchive = async (
  root: string,
): Promise<{ readonly archive: string; readonly source: string }> => {
  const source = join(root, "app");
  await mkdir(join(source, "node_modules"), { recursive: true });
  await writeFile(join(source, "index.js"), "console.log('main');\n");
  await writeFile(
    join(source, "node_modules", "helper.js"),
    "module.exports = 1;\n",
  );
  await writeFile(join(source, "main.jsc"), Buffer.from("c0de0000cached-data"));
  await writeFile(
    join(source, "vendor.bytecode"),
    Buffer.from("bytecode-fixture"),
  );
  const archive = join(root, "app.asar");
  await createPackage(source, archive);
  return { archive, source };
};

const inspect = async (
  archive: string,
  input: Record<string, unknown> = {},
) => {
  const provider = new AsarIntegrityProvider({});
  const result = await provider.inspect(
    inspectAsarIntegrityInputSchema.parse({ path: archive, ...input }),
  );
  await provider.close();
  if (!result.ok) throw result.error;
  return result.value;
};

test("verifies header-declared member checksums and lists bytecode candidates", async () => {
  const root = await createTestTempDirectory("rea-asar-integrity-");
  const { archive } = await buildArchive(root);
  const report = await inspect(archive);
  expect(report).toMatchObject({
    path: archive,
    container: { files: 4, directories: 1 },
    integrity: {
      algorithm: "SHA256",
      members_declaring: 4,
      members_verified: 4,
      members_mismatched: 0,
      members_without_checksums: 0,
      members_unverified: 0,
      truncated: false,
      state: "verified",
    },
    coverage: "complete",
  });
  expect(report.integrity.verified_bytes).toBeGreaterThan(0);
  expect(report.handoff).toMatchObject({
    tool: "decompile_v8_bytecode",
    command_environment: "REA_VIEW8_COMMAND",
  });
  expect(report.handoff.candidates).toEqual([
    {
      path: "main.jsc",
      bytes: 19,
      sha256: null,
      unpacked: false,
      integrity: "verified",
    },
    {
      path: "vendor.bytecode",
      bytes: 16,
      sha256: null,
      unpacked: false,
      integrity: "verified",
    },
  ]);
  expect(JSON.stringify(report)).not.toContain("console.log");
});

test("reports a mismatching member as a finding rather than a failure", async () => {
  const root = await createTestTempDirectory("rea-asar-tamper-");
  const { archive } = await buildArchive(root);
  const raw = getRawHeader(archive);
  const files = (raw.header as { files: Record<string, unknown> }).files;
  const node = files["index.js"] as { offset: string; size: number };
  const bytes = await readFile(archive);
  const absolute = 8 + raw.headerSize + Number(node.offset);
  bytes.write("X", absolute);
  await writeFile(archive, bytes);

  const report = await inspect(archive);
  expect(report.integrity).toMatchObject({
    members_mismatched: 1,
    members_verified: 3,
    state: "mismatched",
    mismatched_paths: ["index.js"],
  });
});

test("stops at the selected verification budget and marks members unverified", async () => {
  const root = await createTestTempDirectory("rea-asar-budget-");
  const { archive } = await buildArchive(root);
  const report = await inspect(archive, { max_verify_bytes: 0 });
  expect(report.integrity).toMatchObject({
    members_declaring: 4,
    members_verified: 0,
    members_unverified: 4,
    verified_bytes: 0,
    truncated: true,
    state: "partial",
  });
  expect(report.handoff.candidates.map(({ integrity }) => integrity)).toEqual([
    "unverified",
    "unverified",
  ]);
  expect(report.coverage).toBe("partial");
});

test("bounds the candidate list without dropping verification", async () => {
  const root = await createTestTempDirectory("rea-asar-candidates-");
  const { archive } = await buildArchive(root);
  const report = await inspect(archive, { max_candidates: 1 });
  expect(report.handoff.candidates).toHaveLength(1);
  expect(report.integrity.members_verified).toBe(4);
});

test("keeps the caller-selected path when it is a symlink to the archive", async () => {
  const root = await createTestTempDirectory("rea-asar-link-");
  const { archive } = await buildArchive(root);
  const link = join(root, "linked.asar");
  const { symlink } = await import("node:fs/promises");
  await symlink(archive, link);
  const report = await inspect(link);
  expect(report.path).toBe(link);
  expect(report.resolved_path).toBe(archive);
  expect(report.integrity.state).toBe("verified");
});

test("refuses a non-archive file instead of inventing members", async () => {
  const root = await createTestTempDirectory("rea-asar-invalid-");
  const path = join(root, "not-an-archive.asar");
  await writeFile(path, "plain text, not a pickle header");
  const provider = new AsarIntegrityProvider({});
  const result = await provider.inspect(
    inspectAsarIntegrityInputSchema.parse({ path }),
  );
  await provider.close();
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).message).toContain(
    "could not be read as an ASAR container",
  );
});

test("keeps cancellation identity when a member stream is aborted mid-flight", async () => {
  const { Readable } = await import("node:stream");
  const { verifyAsarMemberIntegrity } =
    await import("../../../../src/electron/AsarPackedIntegrity.js");
  const { ArtifactReaderFailure } =
    await import("../../../../src/artifacts/ArtifactReader.js");
  const controller = new AbortController();
  const reason = new Error("caller cancelled mid-stream");
  const chunks = [Buffer.alloc(4 * 1024, 1), Buffer.alloc(4 * 1024, 2)];
  const stream = Readable.from(
    (async function* () {
      yield chunks[0];
      controller.abort(reason);
      yield chunks[1];
    })(),
  );
  const failure = await verifyAsarMemberIntegrity(
    { algorithm: "SHA256", hash: "a".repeat(64), blockSize: 4, blocks: [] },
    stream,
    controller.signal,
  ).catch((cause: unknown) => cause);
  expect(failure).toBeInstanceOf(ArtifactReaderFailure);
  expect(failure).toMatchObject({ reason: "cancelled" });
  expect(
    (failure as { cancellation?: { reason?: unknown } }).cancellation?.reason,
  ).toBe(reason);
});

test("reports a cancelled streaming pass as cancellation, not an input error", async () => {
  const root = await createTestTempDirectory("rea-asar-midcancel-");
  const source = join(root, "many");
  await mkdir(source, { recursive: true });
  for (let index = 0; index < 150; index += 1)
    await writeFile(
      join(source, `file-${index}.js`),
      `module.exports=${index};
`,
    );
  const archive = join(root, "many.asar");
  await createPackage(source, archive);
  const provider = new AsarIntegrityProvider({});
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error("caller cancelled"));
  }, 0);
  try {
    const result = await provider.inspect(
      inspectAsarIntegrityInputSchema.parse({ path: archive }),
      { signal: controller.signal },
    );
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisCancelledError" },
    });
  } finally {
    clearTimeout(timer);
    await provider.close();
  }
});

test("cancels before reading members", async () => {
  const root = await createTestTempDirectory("rea-asar-cancel-");
  const { archive } = await buildArchive(root);
  const provider = new AsarIntegrityProvider({});
  const controller = new AbortController();
  controller.abort(new Error("caller cancelled"));
  const result = await provider.inspect(
    inspectAsarIntegrityInputSchema.parse({ path: archive }),
    { signal: controller.signal },
  );
  await provider.close();
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
});

test("does not report candidate integrity for a member without a declaration", async () => {
  const { summarizeAsarHeader } =
    await import("../../../../src/electron/AsarPackedIntegrity.js");
  const summary = summarizeAsarHeader({
    files: {
      "bundle.jsc": { size: 4, offset: "0" },
      "app.js": {
        size: 4,
        offset: "4",
        integrity: {
          algorithm: "SHA256",
          hash: "a".repeat(64),
          blockSize: 0,
          blocks: [],
        },
      },
    },
  });
  expect(
    summary.members.map(({ path, integrity }) => ({ path, integrity })),
  ).toEqual([
    { path: "bundle.jsc", integrity: { state: "absent" } },
    {
      path: "app.js",
      integrity: {
        state: "unsupported",
        reason: "integrity blockSize is invalid",
      },
    },
  ]);
  expect(summary).toMatchObject({ files: 2, directories: 0, unpackedFiles: 0 });
});

test("exposes a serializable report schema", async () => {
  const root = await createTestTempDirectory("rea-asar-schema-");
  const { archive } = await buildArchive(root);
  const report: AsarIntegrityReport = await inspect(archive);
  expect(JSON.parse(JSON.stringify(report))).toEqual(report);
});
