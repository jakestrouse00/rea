import { createHash } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { expect, onTestFinished, test } from "vitest";

import { AdbProvider } from "../../../../src/adb/AdbProvider.js";
import { projectAnalysisError } from "../../../../src/domain/analysisErrorProjection.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";
import type { AdbRequest } from "../../../../src/domain/adb/adbDeviceAnalysis.js";

const it = test.skipIf(process.platform === "win32");

const TRACE_BYTES = "REA-PERFETTO-FIXTURE-TRACE-BYTES-0123456789";
const PROFILE_BYTES = "REA-SIMPLEPERF-FIXTURE-PROFILE-BYTES";

interface StubOptions {
  readonly simpleperfRefusal?: boolean;
  readonly missingArtifact?: boolean;
}

/**
 * Scripted fake adb: one line per invocation in `<root>/calls` records the
 * exact command shape the provider composed. The fake device tree lives at
 * `<root>/device`; `/data/local/tmp/<name>` maps to `device/tmp/<name>`.
 */
const writeAdbStub = async (
  options: StubOptions = {},
): Promise<{ readonly binary: string; readonly root: string }> => {
  const root = await createTestTempDirectory("rea-adb-profiler-");
  const binary = join(root, "adb");
  const writeDeviceFile = options.missingArtifact ? "false" : "true";
  const refuse = options.simpleperfRefusal ? "true" : "false";
  const script = String.raw`#!/bin/sh
ROOT="$(cd "$(dirname "$0")" && pwd)"
printf '%s\n' "$*" >> "$ROOT/calls"
case "$1" in
  version)
    printf 'Android Debug Bridge version 1.0.41\nVersion 34.0.5-profiler-stub\n'
    exit 0 ;;
esac
if [ "$1" = "-s" ]; then shift 2; fi
verb="$1"; shift
device_path() {
  printf '%s/%s' "$ROOT/device/tmp" "$(basename "$1")"
}
case "$verb" in
  shell)
    case "$1" in
      perfetto)
        out=""; prev=""
        for arg in "$@"; do
          [ "$prev" = "-o" ] && out="$arg"
          prev="$arg"
        done
        ${writeDeviceFile} && printf '%s' "${TRACE_BYTES}" > "$(device_path "$out")"
        echo "Perfetto traced 10s, Wrote trace to file $out"
        exit 0 ;;
      simpleperf)
        ${refuse} && {
          echo "Attach failed: Cannot attach to the process (pid 4242)" >&2
          exit 1
        }
        out=""; prev=""
        for arg in "$@"; do
          [ "$prev" = "-o" ] && out="$arg"
          prev="$arg"
        done
        ${writeDeviceFile} && printf '%s' "${PROFILE_BYTES}" > "$(device_path "$out")"
        echo "record: captured 42 records on cpu 0"
        exit 0 ;;
      rm)
        shift
        for path in "$@"; do
          rm -f "$(device_path "$path")"
        done
        exit 0 ;;
    esac ;;
  pull)
    remote="$1"; dest="$2"
    fake="$(device_path "$remote")"
    [ -f "$fake" ] || { echo "remote object '$remote' does not exist" >&2; exit 1; }
    cp "$fake" "$dest/$(basename "$remote")"
    echo "$(basename "$remote"): 1 file pulled, 0 skipped."
    exit 0 ;;
  push)
    cp "$1" "$(device_path "$2")"
    echo "1 file pushed, 0 skipped."
    exit 0 ;;
esac
echo "unmodeled adb invocation: $verb $*" >&2
exit 3
`;
  await writeFile(binary, script, { mode: 0o755 });
  await chmod(binary, 0o755);
  await mkdir(join(root, "device", "tmp"), { recursive: true });
  onTestFinished(() => rm(join(root, "calls"), { force: true }));
  return { binary, root };
};

const evidenceResult = async (
  provider: AdbProvider,
  request: AdbRequest,
): Promise<Record<string, unknown>> => {
  const result = await provider.execute(request);
  if (!result.ok) throw new Error(result.error.message);
  return result.value.result as Record<string, unknown>;
};

const refusalOf = async (
  provider: AdbProvider,
  request: AdbRequest,
): Promise<ReturnType<typeof projectAnalysisError>> => {
  const result = await provider.execute(request);
  if (result.ok) throw new Error("expected a refusal");
  return projectAnalysisError(result.error);
};

it("captures a bounded perfetto trace with a digest and cleans both sides", async () => {
  const { binary, root } = await writeAdbStub();
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const result = (await evidenceResult(provider, {
    operation: "capture_android_perfetto",
    input: {
      serial: "emulator-5554",
      output_directory: outputDirectory,
      duration_seconds: 10,
      tags: ["sched", "freq"],
    },
  })) as Record<string, unknown>;

  const localPath = result.local_path as string;
  expect(result.outcome).toBe("duration-elapsed");
  expect(result.duration_requested_seconds).toBe(10);
  expect(typeof result.duration_elapsed_ms).toBe("number");
  expect(result.sha256).toBe(
    createHash("sha256").update(TRACE_BYTES).digest("hex"),
  );
  expect(await readFile(localPath, "utf8")).toBe(TRACE_BYTES);
  // Exactly one published file; the private staging directory is gone.
  expect(await readdir(outputDirectory)).toEqual([
    localPath.slice(outputDirectory.length + 1),
  ]);
  await provider.close();
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).toContain("shell perfetto -o /data/local/tmp/rea-perfetto-");
  expect(calls).toContain("-t 10s");
  expect(calls).toContain(" sched freq");
  expect(calls).toContain("pull /data/local/tmp/rea-perfetto-");
  expect(calls).toMatch(
    /shell rm -f \/data\/local\/tmp\/rea-perfetto-[0-9a-f-]+\.pftrace\r?\n?$/mu,
  );
});

it("records a simpleperf profile for the selected pid with the requested events", async () => {
  const { binary, root } = await writeAdbStub();
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const result = (await evidenceResult(provider, {
    operation: "capture_android_simpleperf",
    input: {
      serial: "emulator-5554",
      pid: 4242,
      output_directory: outputDirectory,
      duration_seconds: 5,
      events: ["cpu-cycles", "sched:sched_switch"],
    },
  })) as Record<string, unknown>;

  expect(result.outcome).toBe("duration-elapsed");
  expect(result.pid).toBe(4242);
  expect(result.events).toEqual(["cpu-cycles", "sched:sched_switch"]);
  expect(await readFile(result.local_path as string, "utf8")).toBe(
    PROFILE_BYTES,
  );
  await provider.close();
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).toContain("record -p 4242 --duration 5");
  expect(calls).toContain("-e cpu-cycles -e sched:sched_switch");
  expect(calls).toContain("shell rm -f /data/local/tmp/rea-simpleperf-");
});

it("keeps the device refusal for a non-debuggable pid as an unsupported target", async () => {
  const { binary, root } = await writeAdbStub({ simpleperfRefusal: true });
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const refusal = await refusalOf(provider, {
    operation: "capture_android_simpleperf",
    input: {
      serial: "emulator-5554",
      pid: 4242,
      output_directory: join(root, "out"),
      duration_seconds: 5,
      events: ["cpu-cycles"],
    },
  });
  expect(refusal.code).toBe("unsupported_target");
  expect(refusal.message).toContain("Cannot attach to the process");
  await provider.close();
  // No staged device file is requested for removal after an attach refusal.
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).not.toContain("shell rm -f");
});

it("refuses a perfetto config_path that is not an existing regular file", async () => {
  const { binary, root } = await writeAdbStub();
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const refusal = await refusalOf(provider, {
    operation: "capture_android_perfetto",
    input: {
      serial: "emulator-5554",
      output_directory: join(root, "out"),
      duration_seconds: 5,
      config_path: join(root, "missing.perf.txt"),
    },
  });
  expect(refusal.code).toBe("invalid_request");
  expect(refusal.message).toContain("config_path");
  await provider.close();
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).not.toContain("push");
});

it("pushes a caller config into the device tmp and removes it with the trace", async () => {
  const { binary, root } = await writeAdbStub();
  const outputDirectory = join(root, "out");
  await mkdir(outputDirectory, { recursive: true });
  const configPath = join(root, "config.perf.txt");
  await writeFile(configPath, "buffers: { size_kb: 1024 }\n");
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const result = (await evidenceResult(provider, {
    operation: "capture_android_perfetto",
    input: {
      serial: "emulator-5554",
      output_directory: outputDirectory,
      duration_seconds: 5,
      config_path: configPath,
    },
  })) as Record<string, unknown>;
  expect(await readFile(result.local_path as string, "utf8")).toBe(TRACE_BYTES);
  await provider.close();
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).toContain(`push ${configPath} `);
  expect(calls).toContain("-c /data/local/tmp/rea-perfetto-config-");
  const rmLine = calls
    .split("\n")
    .find((line) => line.includes("shell rm -f "));
  expect(rmLine).toContain("rea-perfetto-config-");
  expect(rmLine).toContain("rea-perfetto-");
});

it("keeps a missing device artifact as a typed error and removes staged device files", async () => {
  const { binary, root } = await writeAdbStub({ missingArtifact: true });
  await mkdir(join(root, "out"), { recursive: true });
  const provider = new AdbProvider({ environment: { REA_ADB_PATH: binary } });
  const refusal = await refusalOf(provider, {
    operation: "capture_android_simpleperf",
    input: {
      serial: "emulator-5554",
      pid: 77,
      output_directory: join(root, "out"),
      duration_seconds: 2,
      events: ["cpu-cycles"],
    },
  });
  expect(refusal.code).toBe("unreadable_output");
  await provider.close();
  const calls = await readFile(join(root, "calls"), "utf8");
  expect(calls).toContain("shell rm -f /data/local/tmp/rea-simpleperf-");
  expect((await readdir(join(root, "out"))).length).toBe(0);
});
