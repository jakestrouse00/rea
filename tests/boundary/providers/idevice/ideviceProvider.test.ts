import { expect, test } from "vitest";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { IdeviceProvider } from "../../../../src/idevice/IdeviceProvider.js";
import { inspectIdeviceProvider } from "../../../../src/idevice/IdeviceDoctor.js";
import type { RetainedResourceScope } from "../../../../src/application/AnalysisProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import {
  FIXTURE_APP_BUNDLE,
  FIXTURE_UDID,
  writeFakeIdevice,
  type FakeIdeviceBehavior,
} from "./fakeIdevice.js";

const doctorOptions = {
  resourceScope: {
    retain: () => undefined,
    run: (op: () => unknown) => op(),
  } as unknown as RetainedResourceScope,
};

const providerFor = async (
  behavior: FakeIdeviceBehavior,
): Promise<{
  provider: IdeviceProvider;
  callsPath: string;
  root: string;
}> => {
  const root = await createTestTempDirectory("rea-idevice-");
  const { launcher, callsPath } = await writeFakeIdevice(root, behavior);
  return {
    provider: new IdeviceProvider({
      environment: { REA_IPHONE_PMD3_COMMAND: launcher },
    }),
    callsPath,
    root,
  };
};

const resultOf = async (
  provider: IdeviceProvider,
  request: Parameters<IdeviceProvider["execute"]>[0],
): Promise<Record<string, unknown>> => {
  const result = await provider.execute(request);
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

const refusalOf = async (
  provider: IdeviceProvider,
  request: Parameters<IdeviceProvider["execute"]>[0],
): Promise<ReturnType<typeof projectAnalysisError>> => {
  const result = await provider.execute(request);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  return projectAnalysisError(result.error);
};

test("doctor reports an available launcher and preserves the unverified lane", async () => {
  const root = await createTestTempDirectory("rea-idevice-doctor-");
  const { launcher } = await writeFakeIdevice(root, {});
  const inspection = await inspectIdeviceProvider(
    { REA_IPHONE_PMD3_COMMAND: launcher } as unknown as NodeJS.ProcessEnv,
    process.platform,
    doctorOptions,
  );
  expect(inspection.id).toBe("idevice");
  expect(inspection.configured).toBe(true);
  expect(inspection.available).toBe(true);
  expect(inspection.providerVersion).toBe("4.6.2");
  expect(inspection.checks[0]?.detail).toContain("unverified");
  expect(inspection.registrationEnvironment).toEqual({
    REA_IPHONE_PMD3_COMMAND: launcher,
  });
});

test("doctor refuses plainly without unverified success claims", async () => {
  const inspection = await inspectIdeviceProvider(
    {} as unknown as NodeJS.ProcessEnv,
    process.platform,
    doctorOptions,
  );
  expect(inspection.available).toBe(false);
  expect(inspection.configured).toBe(false);
  expect(inspection.checks[0]?.classification).toBe("missing_analysis_engine");
});

test("lists an empty inventory on an unpaired host without erroring", async () => {
  const { provider } = await providerFor({ devices: [] });
  const result = (await resultOf(provider, {
    operation: "list_ios_devices",
    input: {},
  })) as Record<string, unknown>;
  expect(result.devices).toEqual([]);
  expect(result.coverage).toBe("complete");
  await provider.close();
});

test("inventories and inspects a paired device through lockdown", async () => {
  const { provider, callsPath } = await providerFor({
    devices: [
      {
        DeviceID: FIXTURE_UDID,
        DeviceName: "Fixture iPhone",
        ConnectionType: "USB",
        paired: true,
      },
    ],
    lockdownInfo: {
      DeviceID: FIXTURE_UDID,
      DeviceName: "Fixture iPhone",
      ProductType: "iPhone17,1",
      ProductVersion: "18.3.1",
      ConnectionType: "USB",
    },
  });
  const listed = (await resultOf(provider, {
    operation: "list_ios_devices",
    input: {},
  })) as Record<string, unknown>;
  expect(listed.devices).toHaveLength(1);
  const device = (listed.devices as Record<string, unknown>[])[0]!;
  expect(device.udid).toBe(FIXTURE_UDID);
  expect(device.pairing).toBe("paired");
  expect(device.connection).toBe("usb");
  const inspected = (await resultOf(provider, {
    operation: "inspect_ios_device",
    input: { udid: FIXTURE_UDID },
  })) as Record<string, unknown>;
  expect(inspected.device_name).toBe("Fixture iPhone");
  expect(inspected.product_type).toBe("iPhone17,1");
  expect(inspected.ios_version).toBe("18.3.1");
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain(`"-u","${FIXTURE_UDID}"`);
});

test("reads a bounded syslog dump with a process filter", async () => {
  const { provider } = await providerFor({
    syslog: {
      lines: [
        "Oct 19 10:00:01 host fixture-app[42]: started",
        "Oct 19 10:00:02 host other[77]: noise",
      ],
    },
  });
  const result = (await resultOf(provider, {
    operation: "read_ios_syslog",
    input: {
      udid: FIXTURE_UDID,
      timeout_seconds: 5,
      process_filter: "fixture-app",
    },
  })) as Record<string, unknown>;
  expect(result.lines).toEqual([
    "Oct 19 10:00:01 host fixture-app[42]: started",
  ]);
  expect(result.timeout_seconds).toBe(5);
  expect(result.process_filter).toBe("fixture-app");
  await provider.close();
});

test("captures a screenshot through the private runtime root and digests it", async () => {
  const { provider, callsPath, root } = await providerFor({
    screenshotBytes: "FAKE-PNG-BYTES",
  });
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const result = (await resultOf(provider, {
    operation: "capture_ios_screenshot",
    input: { udid: FIXTURE_UDID, output_directory: outputDirectory },
  })) as Record<string, unknown>;
  const published = result.local_path as string;
  expect(await readFile(published, "utf8")).toBe("FAKE-PNG-BYTES\n");
  expect(result.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(await readdir(outputDirectory)).toEqual([
    published.slice(outputDirectory.length + 1),
  ]);
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  // The staged screenshot path lived inside REA's private runtime root.
  expect(calls).toContain('/idevice-screenshot.png"');
  expect(calls).toContain("rea-provider-");
  // The caller-selected device reached the launcher argv like every other
  // device-targeted operation.
  expect(calls).toContain(`"-u","${FIXTURE_UDID}"`);
});

test("refuses to replace an existing published screenshot", async () => {
  const { provider, root } = await providerFor({ screenshotBytes: "PNG" });
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  await writeFile(
    join(outputDirectory, `rea-idevice-${FIXTURE_UDID}.png`),
    "old",
  );
  const refusal = await refusalOf(provider, {
    operation: "capture_ios_screenshot",
    input: { udid: FIXTURE_UDID, output_directory: outputDirectory },
  });
  expect(refusal.message).toContain("already exists");
  expect(
    await readFile(
      join(outputDirectory, `rea-idevice-${FIXTURE_UDID}.png`),
      "utf8",
    ),
  ).toBe("old");
  await provider.close();
});

test("lists crash reports and pulls one as a digested artifact", async () => {
  const { provider, root, callsPath } = await providerFor({
    crashList: [
      "fixture-app-2026-10-19-120000.ips",
      "other-2026-10-19-130000.ips",
    ],
    crashCopy: {
      fileName: "fixture-app-2026-10-19-120000.ips",
      bytes: "CRASH-BYTES",
    },
  });
  const listed = (await resultOf(provider, {
    operation: "list_ios_crash_reports",
    input: { udid: FIXTURE_UDID },
  })) as Record<string, unknown>;
  expect(listed.reports).toHaveLength(2);
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const pulled = (await resultOf(provider, {
    operation: "inspect_ios_crash",
    input: {
      udid: FIXTURE_UDID,
      report: "fixture-app-2026-10-19-120000.ips",
      output_directory: outputDirectory,
    },
  })) as Record<string, unknown>;
  expect(await readFile(pulled.local_path as string, "utf8")).toBe(
    "CRASH-BYTES\n",
  );
  expect(pulled.sha256).toMatch(/^[a-f0-9]{64}$/u);
  await provider.close();
  const calls = await readFile(callsPath, "utf8");
  expect(calls).toContain('"copy","fixture-app-2026-10-19-120000.ips"');
});

test("refuses an inspect_ios_crash launcher run that stages nothing", async () => {
  const { provider, root } = await providerFor({
    crashList: ["fixture.ips"],
    crashCopy: { empty: true },
  });
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const refusal = await refusalOf(provider, {
    operation: "inspect_ios_crash",
    input: {
      udid: FIXTURE_UDID,
      report: "fixture.ips",
      output_directory: outputDirectory,
    },
  });
  expect(refusal.code).toBe("unreadable_output");
  await provider.close();
});

test("lists installed apps and preserves unknown signer state", async () => {
  const { provider } = await providerFor({
    apps: [
      {
        CFBundleIdentifier: FIXTURE_APP_BUNDLE,
        CFBundleName: "Fixture",
        CFBundleShortVersionString: "2.1.0",
      },
      { CFBundleIdentifier: "com.other.app" },
    ],
  });
  const result = (await resultOf(provider, {
    operation: "list_ios_apps",
    input: { udid: FIXTURE_UDID },
  })) as Record<string, unknown>;
  expect(result.apps).toEqual([
    {
      bundle_id: FIXTURE_APP_BUNDLE,
      name: "Fixture",
      version: "2.1.0",
      signer_restricted: null,
    },
    {
      bundle_id: "com.other.app",
      name: null,
      version: null,
      signer_restricted: null,
    },
  ]);
  await provider.close();
});

test("creates a missing output directory and validates it before publication", async () => {
  const { provider, root } = await providerFor({
    screenshotBytes: "FRESH-PNG-BYTES",
  });
  const outputDirectory = join(root, "fresh", "out");
  const result = (await resultOf(provider, {
    operation: "capture_ios_screenshot",
    input: { udid: FIXTURE_UDID, output_directory: outputDirectory },
  })) as Record<string, unknown>;
  expect(await readFile(result.local_path as string, "utf8")).toBe(
    "FRESH-PNG-BYTES\n",
  );
  await provider.close();
});

test("refuses an output directory that cannot be used with a typed input error", async () => {
  const { provider, root } = await providerFor({ screenshotBytes: "PNG" });
  const occupied = join(root, "occupied");
  await writeFile(occupied, "occupied");
  const refusal = await refusalOf(provider, {
    operation: "capture_ios_screenshot",
    input: { udid: FIXTURE_UDID, output_directory: occupied },
  });
  expect(refusal.code).toBe("unreadable_output");
  expect(JSON.stringify(refusal.details)).toContain("output directory");
  await provider.close();
});

test("joins active operations during close and dedupes concurrent closes", async () => {
  const { provider } = await providerFor({ syslog: { hang: true } });
  const controller = new AbortController();
  const running = provider.execute(
    {
      operation: "read_ios_syslog",
      input: { udid: FIXTURE_UDID, timeout_seconds: 30 },
    },
    { signal: controller.signal },
  );
  setTimeout(() => controller.abort(new Error("caller window closed")), 150);
  const closing = provider.close();
  expect(provider.close()).toBe(closing);
  await Promise.all([running, closing]);
  const refused = await provider.execute({
    operation: "list_ios_devices",
    input: {},
  });
  expect(refused.ok).toBe(false);
  if (refused.ok) throw new Error("expected refusal after close");
  expect(refused.error).toMatchObject({ _tag: "AnalysisCancelledError" });
});

test("reports provisioning metadata the launcher declares and unknowns otherwise", async () => {
  const { provider } = await providerFor({
    apps: [
      {
        CFBundleIdentifier: FIXTURE_APP_BUNDLE,
        CFBundleName: "Fixture",
        team_name: "Fixture Team",
        team_identifier: "TEAMID9",
        provisioned_profiles: ["UUID-1"],
      },
    ],
  });
  const found = (await resultOf(provider, {
    operation: "inspect_ios_provisioning",
    input: { udid: FIXTURE_UDID, bundle_id: FIXTURE_APP_BUNDLE },
  })) as Record<string, unknown>;
  expect(found.app_found).toBe(true);
  expect(found.team_name).toBe("Fixture Team");
  expect(found.provision_fields).toEqual([
    { key: "team_name", value: "Fixture Team" },
    { key: "team_identifier", value: "TEAMID9" },
    { key: "provisioned_profiles", value: null },
  ]);
  await provider.close();
  const absent = await providerFor({ apps: [] });
  const missing = (await resultOf(absent.provider, {
    operation: "inspect_ios_provisioning",
    input: { udid: FIXTURE_UDID, bundle_id: FIXTURE_APP_BUNDLE },
  })) as Record<string, unknown>;
  expect(missing.app_found).toBe(false);
  await absent.provider.close();
});

test("refuses malformed inventory output as unreadable rather than empty", async () => {
  const { provider } = await providerFor({
    devicesRaw: "usbmux error: not found\n",
  });
  const refusal = await refusalOf(provider, {
    operation: "list_ios_devices",
    input: {},
  });
  expect(refusal.code).toBe("unreadable_output");
  await provider.close();
});

test("refuses an unusable launcher before any device contact", async () => {
  const root = await createTestTempDirectory("rea-idevice-badver-");
  const { launcher } = await writeFakeIdevice(root, {
    version: { exit: 3 },
  });
  const provider = new IdeviceProvider({
    environment: { REA_IPHONE_PMD3_COMMAND: launcher },
  });
  const refusal = await refusalOf(provider, {
    operation: "list_ios_devices",
    input: {},
  });
  expect(refusal.code).toBe("capability_unavailable");
  await provider.close();
});

test("keeps cancellation typed when the syslog stream hangs and is aborted", async () => {
  const { provider } = await providerFor({ syslog: { hang: true } });
  const controller = new AbortController();
  const pending = provider.execute(
    {
      operation: "read_ios_syslog",
      input: { udid: FIXTURE_UDID, timeout_seconds: 30 },
    },
    { signal: controller.signal },
  );
  setTimeout(() => controller.abort(new Error("caller window closed")), 150);
  const result = await pending;
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error).toMatchObject({ _tag: "AnalysisCancelledError" });
  await provider.close();
});
