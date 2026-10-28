import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";

import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";
import { captureRequestSchema, type CaptureInput } from "./CaptureAnalysis.js";
import { executePacketCapture, formatFromMagic } from "./CaptureExecution.js";

const CLASSIC_PCAP_LE = Buffer.concat([
  Buffer.from([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00]),
  Buffer.alloc(56, 0xab),
]);
const CLASSIC_PCAP_BE = Buffer.from([
  0xa1, 0xb2, 0xc3, 0xd4, 0x02, 0x00, 0x04, 0x00,
]);
const NANOSECOND_PCAP_LE = Buffer.from([
  0x4d, 0x3c, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00,
]);
const NANOSECOND_PCAP_BE = Buffer.from([
  0xa1, 0xb2, 0x3c, 0x4d, 0x02, 0x00, 0x04, 0x00,
]);
const PCAPNG = Buffer.from([0x0a, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00]);
const GARBAGE = Buffer.from("not a capture file at all");

const validInput = (outputPath: string): CaptureInput => ({
  output_path: outputPath,
  duration_seconds: 1,
  authorize_capture: true,
});

const fixtureLauncher =
  (bytes: Buffer): DiscoveryProcessLauncher =>
  async (request: {
    readonly executable: string;
    readonly arguments: readonly string[];
  }) => {
    await writeFile(request.arguments[0]!, bytes);
    return { stdout: "", stderr: "listening on lo0\n" };
  };

const exitFailure = (code: number, stderr: string) => {
  const error = new Error(`exit ${String(code)}`);
  Reflect.set(error, "stdout", "");
  Reflect.set(error, "stderr", stderr);
  Reflect.set(error, "code", code);
  Reflect.set(error, "signal", null);
  Reflect.set(error, "killed", false);
  return error;
};

const deadlineKill = (stderr: string) => {
  const error = new Error("Command timed out");
  Reflect.set(error, "code", "ETIMEDOUT");
  Reflect.set(error, "stdout", "");
  Reflect.set(error, "stderr", stderr);
  Reflect.set(error, "signal", "SIGTERM");
  Reflect.set(error, "killed", true);
  return error;
};

describe("formatFromMagic", () => {
  it("recognizes classic pcap in microsecond and nanosecond byte orders", () => {
    expect(formatFromMagic(CLASSIC_PCAP_LE)).toBe("pcap");
    expect(formatFromMagic(CLASSIC_PCAP_BE)).toBe("pcap");
    expect(formatFromMagic(NANOSECOND_PCAP_LE)).toBe("pcap");
    expect(formatFromMagic(NANOSECOND_PCAP_BE)).toBe("pcap");
  });

  it("recognizes pcapng by its block-type magic", () => {
    expect(formatFromMagic(PCAPNG)).toBe("pcapng");
  });

  it("keeps unrecognized or truncated heads unknown", () => {
    expect(formatFromMagic(GARBAGE)).toBe("unknown");
    expect(formatFromMagic(CLASSIC_PCAP_LE.subarray(0, 3))).toBe("unknown");
    expect(formatFromMagic(new Uint8Array())).toBe("unknown");
  });
});

describe("executePacketCapture", () => {
  it("appends only the output path to the preconfigured command", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    let seenExecutable: string | undefined;
    let seenArguments: readonly string[] | undefined;
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput(outputPath),
      undefined,
      async (request) => {
        seenExecutable = request.executable;
        seenArguments = [...request.arguments];
        await writeFile(outputPath, CLASSIC_PCAP_LE);
        return { stdout: "", stderr: "" };
      },
    );
    expect(seenExecutable).toBe("/caller/tcpdump-wrapper");
    expect(seenArguments).toEqual([outputPath]);
    expect(report.ok).toBe(true);
  });

  it("reports the retained file with bytes, digest, magic and format", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      {
        output_path: outputPath,
        duration_seconds: 3,
        authorize_capture: true,
      },
      undefined,
      fixtureLauncher(CLASSIC_PCAP_LE),
    );
    expect(report.ok).toBe(true);
    if (report.ok) {
      expect(report.value.output_path).toBe(outputPath);
      expect(report.value.file_bytes).toBe(CLASSIC_PCAP_LE.byteLength);
      expect(report.value.sha256).toBe(
        createHash("sha256").update(CLASSIC_PCAP_LE).digest("hex"),
      );
      expect(report.value.format).toBe("pcap");
      expect(report.value.magic_hex).toBe("d4c3b2a1");
      expect(report.value.duration_seconds).toBe(3);
      expect(report.value.command_stderr_tail).toBe("listening on lo0");
      expect(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/u.test(
          report.value.capture_started_at,
        ),
      ).toBe(true);
    }
  });

  it("treats the window-termination kill as the completed observation", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput(outputPath),
      undefined,
      async (request) => {
        await writeFile(request.arguments[0]!, PCAPNG);
        throw deadlineKill("");
      },
    );
    expect(report.ok).toBe(true);
    if (report.ok) {
      expect(report.value.format).toBe("pcapng");
      expect(report.value.magic_hex).toBe("0a0d0d0a");
    }
  });

  it("fails with the stderr tail when the child exits nonzero early", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    await writeFile(outputPath, CLASSIC_PCAP_BE);
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput(outputPath),
      undefined,
      async () => {
        throw exitFailure(2, "permission denied opening BPF device\n");
      },
    );
    expect(report.ok).toBe(false);
    if (!report.ok) {
      expect(report.error.message).toContain("permission denied opening BPF");
      expect(report.error.message).toContain("was not deleted");
    }
    expect(readFileSync(outputPath).equals(CLASSIC_PCAP_BE)).toBe(true);
  });

  it("reports unknown format and keeps the bytes when magic validation fails", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput(outputPath),
      undefined,
      fixtureLauncher(GARBAGE),
    );
    expect(report.ok).toBe(true);
    if (report.ok) {
      expect(report.value.format).toBe("unknown");
      expect(report.value.magic_hex).toBe("6e6f7420");
    }
    expect(readFileSync(outputPath).equals(GARBAGE)).toBe(true);
  });

  it("does not delete the output path when no readable file was written", async () => {
    const directory = await mkdtemp(join(tmpdir(), "rea-capture-"));
    const outputPath = join(directory, "capture.pcap");
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput(outputPath),
      undefined,
      async () => ({ stdout: "", stderr: "" }),
    );
    expect(report.ok).toBe(false);
    if (!report.ok) expect(report.error.message).toContain(outputPath);
    expect(existsSync(outputPath)).toBe(false);
  });

  it("requires the authorization acknowledgment before spawning", async () => {
    const unauthorized = {
      output_path: "/tmp/rea-no-capture.pcap",
      duration_seconds: 1,
      authorize_capture: false,
    } as unknown as CaptureInput;
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      unauthorized,
      undefined,
      async () => {
        throw new Error("the capture must not run without authorization");
      },
    );
    expect(report.ok).toBe(false);
  });

  it("reports cancellation for an already-aborted signal", async () => {
    const controller = new AbortController();
    controller.abort();
    const report = await executePacketCapture(
      "/caller/tcpdump-wrapper",
      validInput("/tmp/rea-no-capture.pcap"),
      controller.signal,
      undefined,
    );
    expect(report.ok).toBe(false);
    if (!report.ok)
      expect(report.error).toMatchObject({ _tag: "AnalysisCancelledError" });
  });
});

const tcpdumpAvailable = (): boolean => {
  if (process.platform !== "darwin") return false;
  if (!existsSync("/usr/sbin/tcpdump")) return false;
  try {
    accessSync("/dev/bpf0", constants.R_OK | constants.W_OK);
    return true;
  } catch {
    return false;
  }
};

describe.skipIf(!tcpdumpAvailable())(
  "executePacketCapture live loopback",
  () => {
    it("captures a real loopback pcap without root through a caller wrapper", async () => {
      const directory = await mkdtemp(join(tmpdir(), "rea-capture-live-"));
      const wrapperPath = join(directory, "capture.sh");
      await writeFile(
        wrapperPath,
        '#!/bin/sh\nexec /usr/sbin/tcpdump -i lo0 -nn -w "$@"\n',
        { mode: 0o700 },
      );
      const outputPath = join(directory, "live.pcap");
      const report = await executePacketCapture(
        wrapperPath,
        {
          output_path: outputPath,
          duration_seconds: 1,
          authorize_capture: true,
        },
        undefined,
      );
      expect(report.ok).toBe(true);
      if (report.ok) {
        expect(report.value.format).toBe("pcap");
        expect(report.value.magic_hex).toBe("d4c3b2a1");
        expect(report.value.file_bytes).toBeGreaterThanOrEqual(24);
        expect(report.value.sha256).toMatch(/^[a-f0-9]{64}$/u);
        expect(existsSync(outputPath)).toBe(true);
      }
    });
  },
);
