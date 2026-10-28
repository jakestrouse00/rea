import { describe, expect, it } from "vitest";

import type { DiscoveryProcessLauncher } from "../DiscoveryCommand.js";
import {
  BLE_SCAN_GRACE_MS,
  BLE_SCAN_OPERATION,
  executeBleScan,
} from "./BleScanExecution.js";

const SCAN_INPUT = { scan_seconds: 5, address_filter: null } as const;

const staticLauncher =
  (response: { stdout: string; stderr: string }): DiscoveryProcessLauncher =>
  async (request) => {
    expect(request.executable).toBe("/usr/local/bin/ble-scan");
    return response;
  };

describe("executeBleScan", () => {
  it("runs the helper with the seconds bound and normalizes its rows", async () => {
    const recorded: Array<{
      arguments: readonly string[];
      timeoutMs: number;
      signal?: AbortSignal;
    }> = [];
    const launcher: DiscoveryProcessLauncher = async (request) => {
      recorded.push({
        arguments: request.arguments,
        timeoutMs: request.timeoutMs,
        ...(request.signal === undefined ? {} : { signal: request.signal }),
      });
      return {
        stdout: [
          '{"event":"discovered","ts":"2026-10-27T12:00:00.000Z","address_or_uuid":"A1","name":"Tile Mate","rssi":-62,"connectable":true,"manufacturer_hex":"4c0002","service_uuids":[],"flags_description":null}',
          '{"event":"updated","ts":"2026-10-27T12:00:01.000Z","address_or_uuid":"A1","name":"Tile Mate","rssi":-70,"connectable":null,"manufacturer_hex":null,"service_uuids":["180F"],"flags_description":null}',
        ].join("\n"),
        stderr: "",
      };
    };
    const ran = await executeBleScan(
      "/usr/local/bin/ble-scan",
      SCAN_INPUT,
      undefined,
      launcher,
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.scan_seconds).toBe(5);
      expect(ran.value.address_filter).toBeNull();
      expect(ran.value.advertisements.map((row) => row.event)).toEqual([
        "discovered",
        "updated",
      ]);
      expect(ran.value.advertisements[0]?.rssi).toBe(-62);
      expect(ran.value.window_exhausted).toBe(false);
      expect(ran.value.exit_code).toBe(0);
      expect(ran.value.unparsed_lines).toEqual([]);
      expect(ran.value.coverage).toBe("complete");
    }
    expect(recorded).toHaveLength(1);
    expect(recorded[0]?.arguments).toEqual(["--seconds", "5"]);
    expect(recorded[0]?.timeoutMs).toBe(5 * 1000 + BLE_SCAN_GRACE_MS);
  });

  it("passes an identifier filter through as --address", async () => {
    let seenArguments: readonly string[] | null = null;
    const launcher: DiscoveryProcessLauncher = async (request) => {
      seenArguments = request.arguments;
      return { stdout: "", stderr: "" };
    };
    const ran = await executeBleScan(
      "/usr/local/bin/ble-scan",
      { scan_seconds: 4, address_filter: "A1B2" },
      undefined,
      launcher,
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) expect(ran.value.advertisements).toEqual([]);
    expect(seenArguments).toEqual(["--seconds", "4", "--address", "A1B2"]);
  });

  it("merges unparsed rows and reports partial coverage", async () => {
    const ran = await executeBleScan(
      "/usr/local/bin/ble-scan",
      SCAN_INPUT,
      undefined,
      staticLauncher({
        stdout: [
          '{"event":"discovered","ts":null,"address_or_uuid":"A1","name":null,"rssi":-88,"connectable":null,"manufacturer_hex":null,"service_uuids":[],"flags_description":null}',
          "some unexpected diagnostic line",
        ].join("\n"),
        stderr: "",
      }),
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.unparsed_lines).toEqual([
        "some unexpected diagnostic line",
      ]);
      expect(ran.value.coverage).toBe("partial");
    }
  });

  it("reports a deadline-killed window as an exhausted empty partial scan", async () => {
    const ran = await executeBleScan(
      "/usr/local/bin/ble-scan",
      SCAN_INPUT,
      undefined,
      staticLauncher({ stdout: "", stderr: "" }),
    );
    expect(ran.ok).toBe(true);
    if (ran.ok) {
      expect(ran.value.advertisements).toEqual([]);
      expect(ran.value.coverage).toBe("complete");
    }
  });

  it("refuses a TCC Bluetooth authorization denial as a structural error", async () => {
    const ran = await executeBleScan(
      "/usr/local/bin/ble-scan",
      SCAN_INPUT,
      undefined,
      staticLauncher({
        stdout: "",
        stderr: '{"event":"authorization_denied"}',
      }),
    );
    expect(ran.ok).toBe(false);
    if (!ran.ok) {
      expect(ran.error._tag).toBe("ProviderAdapterError");
      expect(ran.error.userMessage).toContain("Bluetooth authorization");
      expect(ran.error.capturedOutput?.stderr).toBe(
        '{"event":"authorization_denied"}',
      );
    }
  });

  it("keeps the operation name the provider switch will use", () => {
    expect(BLE_SCAN_OPERATION).toBe("scan_ble_advertisements");
  });
});
