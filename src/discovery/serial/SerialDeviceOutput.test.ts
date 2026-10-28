import { describe, expect, it } from "vitest";

import {
  joinSerialPorts,
  parseDevEntries,
  parseSystemProfilerPorts,
  renderHexPreview,
  renderOverflowLines,
  renderPrintablePreview,
  SERIAL_PREVIEW_BYTE_LIMIT,
} from "./SerialDeviceOutput.js";

describe("parseSystemProfilerPorts", () => {
  it("flattens the port tree keeping producer strings verbatim", () => {
    const parsed = parseSystemProfilerPorts({
      SPPortsDataType: [
        {
          _name: "Bluetooth-Incoming-Port",
          description: "Bluetooth serial",
        },
        {
          _name: "USB31Bus",
          items: [
            {
              _name: "USB 10/100/1000 LAN",
              product: "AX88179",
              interface_type: "ethernet",
              items: [{ _name: "Nested" }],
            },
          ],
        },
      ],
    });
    expect(parsed.items).toEqual([
      {
        name: "Bluetooth-Incoming-Port",
        interface_type: null,
        description: "Bluetooth serial",
      },
      { name: "USB31Bus", interface_type: null, description: null },
      {
        name: "USB 10/100/1000 LAN",
        interface_type: "ethernet",
        description: "AX88179",
      },
      { name: "Nested", interface_type: null, description: null },
    ]);
    expect(parsed.unparsedLines).toEqual([]);
  });

  it("treats an empty or missing producer payload as an empty inventory", () => {
    expect(parseSystemProfilerPorts({ SPPortsDataType: [] }).items).toEqual([]);
    expect(
      parseSystemProfilerPorts({ SPPortsDataType: [] }).unparsedLines,
    ).toEqual([]);
    expect(parseSystemProfilerPorts({}).items).toEqual([]);
    expect(parseSystemProfilerPorts(null).items).toEqual([]);
  });

  it("preserves scalar nodes as unparsed rows", () => {
    const parsed = parseSystemProfilerPorts(["stray", 12]);
    expect(parsed.items).toEqual([]);
    expect(parsed.unparsedLines).toEqual(["stray", "12"]);
  });
});

describe("parseDevEntries", () => {
  it("keeps only cu. and tty. nodes with their paths and kinds", () => {
    const parsed = parseDevEntries(
      [
        "ttys000",
        "tty.Bluetooth-Incoming-Port",
        "cu.debug-console",
        "console",
        "null",
        "ttyf",
        "stdin",
        "cu.BoseNC700HP",
      ],
      "/dev",
    );
    expect(parsed).toEqual([
      { path: "/dev/cu.BoseNC700HP", name: "cu.BoseNC700HP", kind: "cu" },
      { path: "/dev/cu.debug-console", name: "cu.debug-console", kind: "cu" },
      {
        path: "/dev/tty.Bluetooth-Incoming-Port",
        name: "tty.Bluetooth-Incoming-Port",
        kind: "tty",
      },
    ]);
  });
});

describe("joinSerialPorts", () => {
  it("joins both cu and tty sides of one port name and leaves device-only rows null", () => {
    const joined = joinSerialPorts(
      [
        {
          name: "Bluetooth-Incoming-Port",
          interface_type: null,
          description: "Bluetooth serial",
        },
      ],
      [
        {
          path: "/dev/cu.Bluetooth-Incoming-Port",
          name: "cu.Bluetooth-Incoming-Port",
          kind: "cu",
        },
        {
          path: "/dev/tty.Bluetooth-Incoming-Port",
          name: "tty.Bluetooth-Incoming-Port",
          kind: "tty",
        },
      ],
    );
    expect(joined.ports).toEqual([
      {
        device_path: "/dev/cu.Bluetooth-Incoming-Port",
        name: "Bluetooth-Incoming-Port",
        interface_type: null,
        description: "Bluetooth serial",
        in_use: null,
      },
      {
        device_path: "/dev/tty.Bluetooth-Incoming-Port",
        name: "Bluetooth-Incoming-Port",
        interface_type: null,
        description: "Bluetooth serial",
        in_use: null,
      },
    ]);
    expect(joined.unmatchedPortNames).toEqual([]);
  });

  it("keeps unmatched device rows with null facts and lists unmatched port names", () => {
    const joined = joinSerialPorts(
      [
        {
          name: "OnlyInSystemProfiler",
          interface_type: "wired",
          description: null,
        },
      ],
      [{ path: "/dev/cu.debug-console", name: "cu.debug-console", kind: "cu" }],
    );
    expect(joined.ports).toEqual([
      {
        device_path: "/dev/cu.debug-console",
        name: null,
        interface_type: null,
        description: null,
        in_use: null,
      },
    ]);
    expect(joined.unmatchedPortNames).toEqual(["OnlyInSystemProfiler"]);
  });

  it("matches case-insensitively without inventing a stronger join", () => {
    const joined = joinSerialPorts(
      [
        {
          name: "bluetooth-incoming-port",
          interface_type: null,
          description: null,
        },
      ],
      [
        {
          path: "/dev/tty.Bluetooth-Incoming-Port",
          name: "tty.Bluetooth-Incoming-Port",
          kind: "tty",
        },
      ],
    );
    expect(joined.ports[0]?.name).toBe("bluetooth-incoming-port");
    expect(joined.unmatchedPortNames).toEqual([]);
  });
});

describe("renderHexPreview", () => {
  it("renders lowercase hex pairs and nulls empty windows", () => {
    expect(renderHexPreview(Buffer.from([0x68, 0x69, 0x00, 0xff]))).toBe(
      "68 69 00 ff",
    );
    expect(renderHexPreview(Buffer.alloc(0))).toBeNull();
  });

  it("bounds the render to the preview limit", () => {
    const bytes = Buffer.alloc(SERIAL_PREVIEW_BYTE_LIMIT + 10, 0xab);
    expect(renderHexPreview(bytes)).toHaveLength(
      SERIAL_PREVIEW_BYTE_LIMIT * 3 - 1,
    );
  });
});

describe("renderPrintablePreview and renderOverflowLines", () => {
  it("prints printable bytes and drops non-printable ones", () => {
    expect(renderPrintablePreview(Buffer.from("REA\x01rx\n"))).toBe("REArx\n");
    expect(renderPrintablePreview(Buffer.alloc(0))).toBeNull();
    expect(renderPrintablePreview(Buffer.from([0x01, 0x02]))).toBeNull();
  });

  it("returns no overflow lines when the window fits the budget", () => {
    expect(
      renderOverflowLines(Buffer.from("fits"), SERIAL_PREVIEW_BYTE_LIMIT),
    ).toEqual([]);
  });

  it("preserves lines beyond the preview budget", () => {
    const first = "first\n".repeat(SERIAL_PREVIEW_BYTE_LIMIT / 6);
    const bytes = Buffer.concat([
      Buffer.from(first),
      Buffer.from("second\nthird\n"),
    ]);
    const lines = renderOverflowLines(bytes, SERIAL_PREVIEW_BYTE_LIMIT);
    expect(lines.length).toBeGreaterThan(0);
    expect(lines.at(-1)).toBe("third");
    expect(lines[0]).toBe("nd");
  });
});
