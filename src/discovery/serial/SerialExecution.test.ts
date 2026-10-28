import { spawn } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";
import {
  renderHexPreview,
  SERIAL_PREVIEW_BYTE_LIMIT,
} from "./SerialDeviceOutput.js";
import {
  LIST_SERIAL_PORTS_OPERATION,
  OBSERVE_SERIAL_PORT_LIMITATIONS,
  OBSERVE_SERIAL_PORT_OPERATION,
  STTY_PATH,
  executeListSerialPorts,
  executeObserveSerialPort,
  type SerialDeviceIo,
} from "./SerialExecution.js";

const staticLauncher =
  (response: { stdout: string; stderr: string }): DiscoveryProcessLauncher =>
  async () =>
    response;

const makeDevTemp = (entries: readonly string[]): string => {
  const directory = mkdtempSync(join(tmpdir(), "rea-serial-dev-"));
  for (const entry of entries) writeFileSync(join(directory, entry), "");
  return directory;
};

const quietIo: SerialDeviceIo = {
  open: () => ({ ok: true, value: 7 }),
  read: () => "again",
  close: () => undefined,
};

describe("executeListSerialPorts", () => {
  it("runs system_profiler with the ports datatype and joins device nodes by name", async () => {
    const recorded: Array<{
      executable: string;
      arguments: readonly string[];
    }> = [];
    const launcher: DiscoveryProcessLauncher = async (request) => {
      recorded.push({
        executable: request.executable,
        arguments: request.arguments,
      });
      return {
        stdout: JSON.stringify({
          SPPortsDataType: [
            {
              _name: "Bluetooth-Incoming-Port",
              description: "Bluetooth serial",
            },
          ],
        }),
        stderr: "",
      };
    };
    const devDirectory = makeDevTemp([
      "cu.Bluetooth-Incoming-Port",
      "tty.Bluetooth-Incoming-Port",
      "cu.debug-console",
      "ttys003",
    ]);
    try {
      const ran = await executeListSerialPorts(
        "/usr/sbin/system_profiler",
        undefined,
        { devDirectory, launcher },
      );
      expect(ran.ok).toBe(true);
      if (ran.ok) {
        expect(ran.value.tools).toEqual({
          system_profiler: "/usr/sbin/system_profiler",
          stty: null,
        });
        expect(ran.value.ports).toEqual([
          {
            device_path: `${devDirectory}/cu.Bluetooth-Incoming-Port`,
            name: "Bluetooth-Incoming-Port",
            interface_type: null,
            description: "Bluetooth serial",
            in_use: null,
          },
          {
            device_path: `${devDirectory}/cu.debug-console`,
            name: null,
            interface_type: null,
            description: null,
            in_use: null,
          },
          {
            device_path: `${devDirectory}/tty.Bluetooth-Incoming-Port`,
            name: "Bluetooth-Incoming-Port",
            interface_type: null,
            description: "Bluetooth serial",
            in_use: null,
          },
        ]);
        expect(ran.value.unmatched_port_names).toEqual([]);
        expect(ran.value.unparsed_lines).toEqual([]);
        expect(ran.value.coverage).toBe("complete");
      }
      expect(recorded).toEqual([
        {
          executable: "/usr/sbin/system_profiler",
          arguments: ["SPPortsDataType", "-json"],
        },
      ]);
    } finally {
      rmSync(devDirectory, { recursive: true, force: true });
    }
  });

  it("lists system_profiler rows no device node matches and reports partial coverage", async () => {
    const launcher = staticLauncher({
      stdout: JSON.stringify({
        SPPortsDataType: [{ _name: "OrphanPort", product: "AX88179" }, "stray"],
      }),
      stderr: "",
    });
    const devDirectory = makeDevTemp(["cu.debug-console"]);
    try {
      const ran = await executeListSerialPorts(
        "/usr/sbin/system_profiler",
        undefined,
        { devDirectory, launcher },
      );
      expect(ran.ok).toBe(true);
      if (ran.ok) {
        expect(ran.value.unmatched_port_names).toEqual(["OrphanPort"]);
        expect(ran.value.unparsed_lines).toEqual(["stray"]);
        expect(ran.value.ports[0]?.name).toBeNull();
        expect(ran.value.coverage).toBe("partial");
      }
    } finally {
      rmSync(devDirectory, { recursive: true, force: true });
    }
  });

  it("refuses unrecognizable system_profiler output as a protocol error", async () => {
    const ran = await executeListSerialPorts(
      "/usr/sbin/system_profiler",
      undefined,
      { launcher: staticLauncher({ stdout: "not json", stderr: "" }) },
    );
    expect(ran.ok).toBe(false);
    if (!ran.ok)
      expect((ran.error as Error).message).toContain("not recognizable");
  });

  it("exposes the operation names for the provider switch", () => {
    expect(LIST_SERIAL_PORTS_OPERATION).toBe("list_serial_ports");
    expect(OBSERVE_SERIAL_PORT_OPERATION).toBe("observe_serial_port");
  });
});

describe("executeObserveSerialPort", () => {
  it("records stty line-discipline arguments only, never a payload", async () => {
    const recorded: Array<readonly string[]> = [];
    const launcher: DiscoveryProcessLauncher = async (request) => {
      recorded.push(request.arguments);
      return { stdout: "", stderr: "" };
    };
    const ran = await executeObserveSerialPort(
      {
        device_path: "/dev/cu.debug-console",
        duration_seconds: 1,
        baud_rate: 9600,
      },
      undefined,
      { launcher, deviceIo: quietIo },
    );
    expect(ran.ok).toBe(true);
    expect(recorded).toEqual([
      ["-f", "/dev/cu.debug-console", "9600", "cs8", "-cstopb", "-parenb"],
    ]);
    expect(OBSERVE_SERIAL_PORT_LIMITATIONS.join(" ")).toContain(
      "rx-only window; no bytes were transmitted",
    );
  });

  it("stops at the deadline with an empty complete window", async () => {
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.quiet", duration_seconds: 1, baud_rate: 9600 },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: quietIo,
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.bytes_observed).toBe(0);
      expect(ran.value.stop_reason).toBe("deadline");
      expect(ran.value.stop_detail).toBeNull();
      expect(ran.value.hex_preview).toBeNull();
      expect(ran.value.printable_preview).toBeNull();
      expect(ran.value.unparsed_lines).toEqual([]);
      expect(ran.value.coverage).toBe("complete");
      expect(ran.value.tools.stty).toBe(STTY_PATH);
    }
  });
});

describe("executeObserveSerialPort stop reasons", () => {
  it("stops early on device close and keeps the observed bytes", async () => {
    let reads = 0;
    const ran = await executeObserveSerialPort(
      {
        device_path: "/dev/tty.going-away",
        duration_seconds: 5,
        baud_rate: 115200,
      },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: {
          open: () => ({ ok: true, value: 3 }),
          read: (_fd, buffer) => {
            reads += 1;
            if (reads > 1) return 0;
            buffer[0] = 0x68;
            buffer[1] = 0x00;
            buffer[2] = 0xff;
            buffer[3] = 0x0a;
            return 4;
          },
          close: () => undefined,
        },
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.bytes_observed).toBe(4);
      expect(ran.value.hex_preview).toBe("68 00 ff 0a");
      expect(ran.value.printable_preview).toBe("h\n");
      expect(ran.value.stop_reason).toBe("closed");
      expect(ran.value.stop_detail).toContain("closed before the window");
      expect(ran.value.coverage).toBe("partial");
      expect(ran.value.baud_rate).toBe(115200);
    }
  });

  it("stops early on a read error and preserves its reason", async () => {
    const ran = await executeObserveSerialPort(
      {
        device_path: "/dev/tty.erroring",
        duration_seconds: 5,
        baud_rate: 9600,
      },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: {
          open: () => ({ ok: true, value: 11 }),
          read: () => {
            const error = new Error(
              "Input/output error",
            ) as NodeJS.ErrnoException;
            error.code = "EIO";
            throw error;
          },
          close: () => undefined,
        },
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.bytes_observed).toBe(0);
      expect(ran.value.stop_reason).toBe("read_error");
      expect(ran.value.stop_detail).toContain("EIO");
      expect(ran.value.coverage).toBe("partial");
    }
  });
});

describe("executeObserveSerialPort byte previews", () => {
  it("rejoins multi-chunk reads into one preview within the window", async () => {
    const payload = Buffer.from("serial lane rx", "utf8");
    let reads = 0;
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.lively", duration_seconds: 1, baud_rate: 9600 },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: {
          open: () => ({ ok: true, value: 7 }),
          read: (fd, buffer) => {
            if (reads === 0) {
              reads = 1;
              buffer.set(payload.subarray(0, 6));
              return 6;
            }
            if (reads === 1) {
              reads = 2;
              buffer.set(payload.subarray(6));
              return payload.byteLength - 6;
            }
            return "again";
          },
          close: () => undefined,
        },
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.bytes_observed).toBe(payload.byteLength);
      expect(ran.value.printable_preview).toBe("serial lane rx");
      expect(ran.value.hex_preview).toBe(
        renderHexPreview(Buffer.from("serial lane rx", "utf8")),
      );
      expect(ran.value.stop_reason).toBe("deadline");
      expect(ran.value.coverage).toBe("complete");
    }
  });

  it("stops at the retained-byte bound instead of growing unbounded", async () => {
    const ran = await executeObserveSerialPort(
      {
        device_path: "/dev/cu.firehose",
        duration_seconds: 15,
        baud_rate: 9600,
      },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: {
          open: () => ({ ok: true, value: 7 }),
          read: (fd, buffer) => {
            buffer[0] = 0x41;
            return 1;
          },
          close: () => undefined,
        },
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.stop_reason).toBe("byte_bound");
      expect(ran.value.stop_detail).toContain("retained-byte bound");
      expect(ran.value.bytes_observed).toBeGreaterThanOrEqual(1_048_576);
      expect(ran.value.coverage).toBe("partial");
    }
  });

  it("preserves the beyond-budget bytes as overflow lines", async () => {
    const payload = Buffer.alloc(SERIAL_PREVIEW_BYTE_LIMIT + 6, 0x41);
    let reads = 0;
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.flooded", duration_seconds: 1, baud_rate: 9600 },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: {
          open: () => ({ ok: true, value: 7 }),
          read: (fd, buffer) => {
            if (reads === 0) {
              reads = 1;
              buffer.set(payload.subarray(0, 200));
              return 200;
            }
            if (reads === 1) {
              reads = 2;
              buffer.set(payload.subarray(200));
              return payload.byteLength - 200;
            }
            return "again";
          },
          close: () => undefined,
        },
      },
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.bytes_observed).toBe(payload.byteLength);
      expect(ran.value.hex_preview?.split(" ")).toHaveLength(
        SERIAL_PREVIEW_BYTE_LIMIT,
      );
      expect(ran.value.unparsed_lines).toEqual(["AAAAAA"]);
      expect(ran.value.coverage).toBe("partial");
    }
  });
});

describe("executeObserveSerialPort refusals", () => {
  const refusingIo = (failure: {
    code: string;
    message: string;
  }): SerialDeviceIo => ({
    open: () => ({ ok: false, error: failure }),
    read: () => "again",
    close: () => undefined,
  });

  it("refuses a busy open with a typed input error and no write", async () => {
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.held", duration_seconds: 1, baud_rate: 9600 },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: refusingIo({ code: "EBUSY", message: "Device busy" }),
      },
    );
    expect(ran.ok).toBe(false);
    if (!ran.ok) {
      expect(ran.error.userMessage ?? "").toContain("EBUSY");
      expect(ran.error.userMessage ?? "").toContain("No bytes were written");
    }
  });

  it("refuses a missing node with a typed input error", async () => {
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.absent", duration_seconds: 1, baud_rate: 9600 },
      undefined,
      {
        launcher: staticLauncher({ stdout: "", stderr: "" }),
        deviceIo: refusingIo({
          code: "ENOENT",
          message: "No such file or directory",
        }),
      },
    );
    expect(ran.ok).toBe(false);
    if (!ran.ok) expect(ran.error.userMessage ?? "").toContain("ENOENT");
  });

  it("refuses before stty when the caller's signal is already aborted", async () => {
    const controller = new AbortController();
    controller.abort();
    let launcherCalls = 0;
    const ran = await executeObserveSerialPort(
      { device_path: "/dev/cu.late", duration_seconds: 1, baud_rate: 9600 },
      controller.signal,
      {
        launcher: async () => {
          launcherCalls += 1;
          return { stdout: "", stderr: "" };
        },
      },
    );
    expect(ran.ok).toBe(false);
    if (!ran.ok) expect((ran.error as Error).message).toContain("cancelled");
    expect(launcherCalls).toBe(0);
  });
});

const canCreatePty =
  process.platform === "darwin" &&
  existsSync("/usr/bin/expect") &&
  existsSync("/bin/stty");

const beforeTtySet = (): Set<string> =>
  new Set(readdirSync("/dev").filter((name) => name.startsWith("ttys")));

const waitForNewTty = async (
  before: ReadonlySet<string>,
  timeoutMs: number,
): Promise<string | null> => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const entry = readdirSync("/dev").find(
      (name) => name.startsWith("ttys") && !before.has(name),
    );
    if (entry !== undefined) return join("/dev", entry);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return null;
};

describe.skipIf(!canCreatePty)(
  "executeObserveSerialPort against a real pty",
  () => {
    it("receives bytes a writer sent while the node was stty-configured", async () => {
      const before = beforeTtySet();
      const child = spawn(
        "/usr/bin/expect",
        [
          "-c",
          'spawn -noecho /bin/sleep 12; send -- "REA-pty-serial-lane\\n"; sleep 10; exit 0',
        ],
        { stdio: ["ignore", "ignore", "ignore"] },
      );
      expect(child.pid).toBeDefined();
      try {
        const devicePath = await waitForNewTty(before, 2000);
        expect(devicePath).not.toBeNull();
        const ran = await executeObserveSerialPort(
          { device_path: devicePath!, duration_seconds: 2, baud_rate: 9600 },
          undefined,
        );
        expect(ran.ok).toBe(true);
        if (!ran.ok) return;
        expect(ran.value.stop_reason).toBe("deadline");
        expect(ran.value.bytes_observed).toBeGreaterThanOrEqual(20);
        expect(
          ran.value.printable_preview?.includes("REA-pty-serial-lane"),
        ).toBe(true);
        expect(ran.value.tools.stty).toBe(STTY_PATH);
        expect(ran.value.coverage).toBe("complete");
      } finally {
        child.kill("SIGKILL");
      }
    }, 15_000);
  },
);

describe("the device seam", () => {
  it("exposes no write operation", () => {
    expect(Object.keys(quietIo)).toEqual(["open", "read", "close"]);
  });
});
