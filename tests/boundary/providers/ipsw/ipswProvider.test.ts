import { expect, test } from "vitest";
import { mkdir, readFile, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { IpswProvider } from "../../../../src/iosipsw/IpswProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import { writeFakeIpsw, type FakeIpswBehavior } from "./fakeIpsw.js";

const FIXTURE_DIGEST = "c".repeat(64);

const providerFor = async (
  behavior: FakeIpswBehavior,
  options: {
    readonly configureCache?: boolean;
    readonly platform?: NodeJS.Platform;
  } = {},
): Promise<{
  readonly provider: IpswProvider;
  readonly launcher: string;
  readonly callsPath: string;
  readonly root: string;
  readonly cachePath: string;
}> => {
  const root = await createTestTempDirectory("rea-ipsw-");
  const { launcher, callsPath } = await writeFakeIpsw(root, behavior);
  const cachePath = join(root, "dyld_shared_cache_arm64e");
  await writeFile(cachePath, "CACHE-FIXTURE");
  const environment: Record<string, string> = { REA_IPSW_COMMAND: launcher };
  if (options.configureCache !== false)
    environment.REA_IPSW_DSC_PATH = cachePath;
  return {
    launcher,
    provider: new IpswProvider({
      environment,
      ...(options.platform === undefined ? {} : { platform: options.platform }),
    }),
    callsPath,
    root,
    cachePath,
  };
};

const resultOf = async (
  provider: IpswProvider,
  request: Parameters<IpswProvider["execute"]>[0],
): Promise<Record<string, unknown>> => {
  const result = await provider.execute(request);
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

test("inventories a local IPSW and records the ipsw client version", async () => {
  const { provider, callsPath, root } = await providerFor({
    info: {
      product: "iPhone15,2",
      version: "18.3.1",
      build: "22D72",
      buildtrain: "22D",
      devices: [
        "iPhone15,2",
        { identifier: "iPhone16,1" },
        { unexpected: true },
      ],
      files: [
        { name: "BuildManifest.plist", size: 120, digest: FIXTURE_DIGEST },
        {
          path: "System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64e",
          size: "2048",
        },
        { nameless: true },
      ],
    },
  });
  const archive = join(root, "fixture.ipsw");
  await writeFile(archive, "IPSW-FIXTURE");
  const result = await resultOf(provider, {
    operation: "inspect_ipsw",
    input: { path: archive },
  });
  expect(result.client).toEqual({
    command: expect.any(String),
    version: "3.1.575",
  });
  expect(result.product).toBe("iPhone15,2");
  expect(result.version).toBe("18.3.1");
  expect(result.build).toBe("22D72");
  expect(result.build_train).toBe("22D");
  expect(result.bytes).toBe("IPSW-FIXTURE".length);
  expect(result.device_identifiers).toEqual(["iPhone15,2", "iPhone16,1"]);
  expect(result.partitions).toEqual([
    { name: "BuildManifest.plist", bytes: 120, sha256: FIXTURE_DIGEST },
    { name: "dyld_shared_cache_arm64e", bytes: 2048, sha256: null },
  ]);
  expect(result.partition_count).toBe(2);
  // Two inventory rows could not be named; the inventory is partial.
  expect(result.coverage).toBe("partial");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`["info","${archive}","--json"]`);
});

test("keeps unreported inventory sections unknown instead of empty", async () => {
  const { provider, root } = await providerFor({
    info: { product: "iPhone15,2", version: "18.3.1" },
  });
  const archive = join(root, "fixture.ipsw");
  await writeFile(archive, "IPSW-FIXTURE");
  const result = await resultOf(provider, {
    operation: "inspect_ipsw",
    input: { path: archive },
  });
  expect(result.device_identifiers).toEqual([]);
  expect(result.partitions).toEqual([]);
  expect(result.partition_count).toBe(0);
  // Absent sections are unknown, not verified-empty.
  expect(result.coverage).toBe("partial");
  await provider.close();
});

test("refuses plainly when no ipsw binary is selected", async () => {
  const provider = new IpswProvider({ environment: {} });
  const result = await provider.execute({
    operation: "inspect_ipsw",
    input: { path: "/does/not/matter.ipsw" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  expect(result.error.message).toContain("REA_IPSW_COMMAND");
  await provider.close();
});

test("refuses a launcher whose version probe fails", async () => {
  const root = await createTestTempDirectory("rea-ipsw-badver-");
  const { launcher } = await writeFakeIpsw(root, { version: { exit: 3 } });
  const provider = new IpswProvider({
    environment: { REA_IPSW_COMMAND: launcher },
  });
  const result = await provider.execute({
    operation: "inspect_macho_entitlements",
    input: { path: join(root, "image") },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe(
    "capability_unavailable",
  );
  await provider.close();
});

test("reports unparseable inventory output as a protocol failure", async () => {
  const { provider, root } = await providerFor({ info: "table, not JSON\n" });
  const archive = join(root, "fixture.ipsw");
  await writeFile(archive, "IPSW-FIXTURE");
  const result = await provider.execute({
    operation: "inspect_ipsw",
    input: { path: archive },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  await provider.close();
});

test("extracts selected cache images into one new digested directory", async () => {
  const { provider, callsPath, root } = await providerFor({
    manifest: {
      arch: "arm64e",
      images: [
        {
          name: "UIKit",
          path: "/System/Library/Frameworks/UIKit.framework/UIKit",
          address: "0x1A2B3C000",
          size: 4096,
        },
        {
          name: "Foundation",
          path: "/System/Library/Frameworks/Foundation.framework/Foundation",
          address: 4369000000,
          size: "8192",
        },
        { path: "/usr/lib/libobjc.A.dylib" },
      ],
    },
    extractFiles: {
      UIKit: "UIKIT-BYTES",
      "libobjc.A.dylib": "OBJC-BYTES",
    },
  });
  const outputDirectory = join(root, "out");
  const result = await resultOf(provider, {
    operation: "extract_dyld_shared_cache_images",
    input: {
      output_directory: outputDirectory,
      images: ["UIKit", "Missing"],
      max_images: 4,
    },
  });
  expect(result.architecture).toBe("arm64e");
  expect(result.image_count).toBe(3);
  expect(result.manifest_truncated).toBe(false);
  expect(result.requested).toEqual(["UIKit", "Missing"]);
  expect(result.missing).toEqual(["Missing"]);
  const published = result.published as {
    relative_path: string;
    bytes: number;
    sha256: string;
  }[];
  expect(published.map(({ relative_path }) => relative_path)).toEqual([
    "UIKit",
    "libobjc.A.dylib",
  ]);
  for (const file of published) expect(file.sha256).toMatch(/^[a-f0-9]{64}$/u);
  const directory = result.output_directory as string;
  expect(await readFile(join(directory, "UIKit"), "utf8")).toBe("UIKIT-BYTES");
  expect(result.published_truncated).toBe(false);
  expect(result.coverage).toBe("partial");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"dyld","extract"');
  expect(calls).toContain('"UIKit"');
});

test("requires an explicit cache when a directory holds several", async () => {
  const { launcher, root } = await providerFor(
    { manifest: { images: [] } },
    { configureCache: false },
  );
  const cacheDirectory = join(root, "dyld");
  await mkdir(cacheDirectory, { recursive: true });
  await writeFile(join(cacheDirectory, "dyld_shared_cache_arm64e"), "one");
  await writeFile(join(cacheDirectory, "dyld_shared_cache_arm64"), "two");
  const provider = new IpswProvider({
    environment: {
      REA_IPSW_COMMAND: launcher,
      REA_IPSW_DSC_PATH: cacheDirectory,
    },
  });
  const result = await provider.execute({
    operation: "extract_dyld_shared_cache_images",
    input: {
      output_directory: join(root, "out"),
      max_images: 4,
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  expect(result.error.userMessage).toContain("shared caches");
  await provider.close();
});

test("dumps Objective-C class metadata as structure with a bounded table", async () => {
  const { provider, root } = await providerFor({
    classes: {
      classes: [
        {
          name: "FixtureController",
          superclass: "UIViewController",
          protocols: ["UITableViewDelegate", { name: "FixtureProtocol" }],
          instanceMethods: [
            {
              name: "viewDidLoad",
              returnType: "void",
              parameters: ["self", "_cmd"],
            },
            "reloadData",
          ],
          classMethods: [{ name: "shared", is_class: true }],
          ivars: [
            { name: "_count", type: "NSUInteger", offset: 8 },
            "nameOnlyIvar",
          ],
        },
        {
          name: "FixtureView",
          methods: [{ name: "layoutSubviews" }],
          fields: [{ name: "value", type: "Int" }],
        },
        { unnamed: true },
      ],
    },
  });
  const image = join(root, "UIKit");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await resultOf(provider, {
    operation: "dump_ios_class_metadata",
    input: { path: image, family: "objc", max_classes: 1 },
  });
  expect(result.family).toBe("objc");
  expect(result.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.class_count).toBe(1);
  expect(result.method_count).toBe(3);
  expect(result.ivar_count).toBe(2);
  expect(result.truncated).toBe(true);
  expect(result.unparsed_entries).toBe(1);
  expect(result.coverage).toBe("partial");
  const classes = result.classes as {
    name: string;
    superclass: string;
    protocols: string[];
    methods: { name: string; kind: string; parameter_types: string[] }[];
    ivars: { name: string; type: string; offset: number }[];
  }[];
  expect(classes[0]?.name).toBe("FixtureController");
  expect(classes[0]?.protocols).toEqual([
    "UITableViewDelegate",
    "FixtureProtocol",
  ]);
  expect(classes[0]?.methods[2]).toMatchObject({
    name: "shared",
    kind: "class",
  });
  expect(classes[0]?.ivars[0]).toMatchObject({
    name: "_count",
    type: "NSUInteger",
    offset: 8,
  });
  await provider.close();
});

test("symbolicates a crash report thread by thread", async () => {
  const { provider, root } = await providerFor({
    symbolicated: {
      threads: [
        {
          id: 0,
          name: "main",
          crashed: true,
          frames: [
            {
              image: "FixtureApp",
              symbol: "-[FixtureController viewDidLoad]",
              address: "0x100004000",
              offset: "0x120",
              source_file: "FixtureController.m",
              source_line: 42,
            },
            { imageName: "UIKit", address: "0x1a2b3c000" },
          ],
        },
        { thread: 1, stack: [{ symbol: "start" }] },
      ],
    },
  });
  const crash = join(root, "fixture-app.ips");
  await writeFile(crash, "CRASH-FIXTURE");
  const result = await resultOf(provider, {
    operation: "symbolicate_ios_crash",
    input: { crash },
  });
  expect(result.frame_count).toBe(3);
  expect(result.crash_bytes).toBe("CRASH-FIXTURE".length);
  expect(result.coverage).toBe("complete");
  const threads = result.threads as {
    id: number;
    crashed: boolean;
    frames: {
      index: number;
      image: string;
      symbol: string | null;
      address: string;
      offset: string | null;
      source_file: string | null;
      source_line: number | null;
    }[];
  }[];
  expect(threads[0]?.frames[0]).toMatchObject({
    index: 0,
    image: "FixtureApp",
    symbol: "-[FixtureController viewDidLoad]",
    address: "0x100004000",
    offset: "0x120",
    source_file: "FixtureController.m",
    source_line: 42,
  });
  expect(threads[0]?.frames[1]?.symbol).toBeNull();
  expect(threads[1]?.id).toBe(1);
  expect(threads[1]?.crashed).toBe(false);
  await provider.close();
});

test("reports entitlement keys and load commands without entitlement values", async () => {
  const { provider, root } = await providerFor({
    macho: {
      arch: "arm64e",
      type: "EXECUTE",
      entitlements: {
        "com.apple.developer.team-identifier": "ABCDE12345",
        "get-task-allow": true,
        "com.apple.security.cs.disable-library-validation": true,
      },
      load_commands: [
        { command: "LC_SEGMENT_64", size: 72, offset: 4096 },
        { cmd: "LC_CODE_SIGNATURE", cmdsize: 16 },
        { unexpected: true },
      ],
    },
  });
  const image = join(root, "FixtureApp");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await resultOf(provider, {
    operation: "inspect_macho_entitlements",
    input: { path: image },
  });
  expect(result.architecture).toBe("arm64e");
  expect(result.file_type).toBe("EXECUTE");
  expect(result.entitlement_count).toBe(3);
  expect(result.entitlements).toEqual([
    {
      key: "com.apple.developer.team-identifier",
      value_kind: "string",
    },
    { key: "get-task-allow", value_kind: "boolean" },
    {
      key: "com.apple.security.cs.disable-library-validation",
      value_kind: "boolean",
    },
  ]);
  expect(result.load_command_count).toBe(2);
  expect(result.unparsed_entries).toBe(1);
  expect(JSON.stringify(result)).not.toContain("ABCDE12345");
  expect(result.coverage).toBe("partial");
  await provider.close();
});

test("reports unparseable class metadata as a protocol failure", async () => {
  const { provider, root } = await providerFor({
    classes: "headers, not JSON\n",
  });
  const image = join(root, "FixtureApp");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await provider.execute({
    operation: "dump_ios_class_metadata",
    input: { path: image, family: "objc", max_classes: 10 },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe("unreadable_output");
  await provider.close();
});

test("retains a staging root whose removal cannot be confirmed", async () => {
  const { launcher, cachePath, root } = await providerFor({
    manifest: {
      images: [{ name: "UIKit", path: "/usr/lib/UIKit", address: 1, size: 2 }],
    },
    extractFiles: { UIKit: "UIKIT-BYTES" },
  });
  const staging = join(root, "staging");
  await mkdir(staging, { recursive: true });
  const provider = new IpswProvider({
    environment: {
      REA_IPSW_COMMAND: launcher,
      REA_IPSW_DSC_PATH: cachePath,
    },
    createRuntimeRoot: async () => ({
      path: staging,
      close: async () => {
        throw new Error("staging root busy");
      },
    }),
  });
  const result = await provider.execute({
    operation: "extract_dyld_shared_cache_images",
    input: {
      output_directory: join(root, "out"),
      images: ["UIKit"],
      max_images: 2,
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error).code).toBe("cleanup_incomplete");
  await expect(provider.close()).rejects.toBeDefined();
});

test("withholds raw entitlement documents on unparseable output", async () => {
  const secret = "ABCDE12345";
  const { provider, root } = await providerFor({
    macho: `<?xml version="1.0"?><plist><dict><key>com.apple.developer.team-identifier</key><string>${secret}</string></dict></plist>`,
  });
  const image = join(root, "FixtureApp");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await provider.execute({
    operation: "inspect_macho_entitlements",
    input: { path: image },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  const projected = projectAnalysisError(result.error);
  expect(JSON.stringify(projected)).not.toContain(secret);
  expect(JSON.stringify(projected)).not.toContain("stdout_excerpt");
  expect(projected.captured_output).toBeUndefined();
  await provider.close();
});

test("withholds captured output when the entitlements command fails", async () => {
  const secret = "ABCDE12345";
  const { provider, root } = await providerFor({
    machoFailure: {
      exit: 1,
      stdout: `com.apple.developer.team-identifier=${secret}`,
      stderr: `parse failed near ${secret}`,
    },
  });
  const image = join(root, "FixtureApp");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await provider.execute({
    operation: "inspect_macho_entitlements",
    input: { path: image },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  const projected = projectAnalysisError(result.error);
  expect(JSON.stringify(projected)).not.toContain(secret);
  expect(projected.captured_output).toBeUndefined();
  await provider.close();
});

test("reports a recognized empty class table as empty, not unreadable", async () => {
  const { provider, root } = await providerFor({ classes: { classes: [] } });
  const image = join(root, "PlainMachO");
  await writeFile(image, "MACHO-FIXTURE");
  const result = await resultOf(provider, {
    operation: "dump_ios_class_metadata",
    input: { path: image, family: "objc", max_classes: 10 },
  });
  expect(result.classes).toEqual([]);
  expect(result.class_count).toBe(0);
  expect(result.truncated).toBe(false);
  expect(result.coverage).toBe("complete");
  await provider.close();
});

test("reports a recognized empty thread list as empty, not unreadable", async () => {
  const { provider, root } = await providerFor({
    symbolicated: { threads: [] },
  });
  const crash = join(root, "fixture-app.ips");
  await writeFile(crash, "CRASH-FIXTURE");
  const result = await resultOf(provider, {
    operation: "symbolicate_ios_crash",
    input: { crash },
  });
  expect(result.threads).toEqual([]);
  expect(result.frame_count).toBe(0);
  expect(result.coverage).toBe("complete");
  await provider.close();
});

test("reports a recognized empty cache manifest as empty, not unreadable", async () => {
  const { provider, root } = await providerFor({
    manifest: { arch: "arm64e", images: [] },
  });
  const result = await resultOf(provider, {
    operation: "extract_dyld_shared_cache_images",
    input: { output_directory: join(root, "out"), max_images: 4 },
  });
  expect(result.image_count).toBe(0);
  expect(result.manifest).toEqual([]);
  expect(result.requested).toEqual([]);
  expect(result.published).toEqual([]);
  expect(result.coverage).toBe("complete");
  expect((await stat(result.output_directory as string)).isDirectory()).toBe(
    true,
  );

  const requested = await provider.execute({
    operation: "extract_dyld_shared_cache_images",
    input: {
      output_directory: join(root, "out2"),
      images: ["UIKit"],
      max_images: 4,
    },
  });
  expect(requested.ok).toBe(false);
  if (requested.ok) return;
  expect(requested.error._tag).toBe("AnalysisInputError");
  await provider.close();
});

test("reports the ipsw client as available only after a version probe", async () => {
  const { provider } = await providerFor({});
  const available = await provider.inspectAvailability();
  expect(available.status).toBe("available");
  expect(available.diagnostics).toMatchObject({ version: "3.1.575" });
  await provider.close();

  const unconfigured = new IpswProvider({ environment: {} });
  const unavailable = await unconfigured.inspectAvailability();
  expect(unavailable).toMatchObject({
    status: "unavailable",
    code: "not_configured",
  });
  await unconfigured.close();
});

test("keeps caller cancellation typed before any process starts", async () => {
  const { provider } = await providerFor({});
  const controller = new AbortController();
  controller.abort(new Error("caller window closed"));
  const result = await provider.execute(
    { operation: "inspect_ipsw", input: { path: "/tmp/fixture.ipsw" } },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisCancelledError");
  await provider.close();
});

test("publishes nothing when a selector matches no manifest image", async () => {
  const { provider, root } = await providerFor({
    manifest: {
      images: [{ name: "UIKit", path: "/usr/lib/UIKit", address: 1, size: 2 }],
    },
  });
  const result = await provider.execute({
    operation: "extract_dyld_shared_cache_images",
    input: {
      output_directory: join(root, "out"),
      images: ["Foundation"],
      max_images: 2,
    },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error._tag).toBe("AnalysisInputError");
  // Nothing was materialized for a request that selected no image.
  await expect(stat(join(root, "out"))).rejects.toMatchObject({
    code: "ENOENT",
  });
  await provider.close();
});
