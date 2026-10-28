import { describe, expect, it } from "vitest";

import {
  executeListSerialPorts,
  executeObserveSerialPort,
  STTY_PATH,
} from "./SerialExecution.js";

const LIVE = process.env.REA_LIVE_HOST_VERIFY === "1";

describe.skipIf(!LIVE)(
  "live host verification (REA_LIVE_HOST_VERIFY=1)",
  () => {
    it("lists this host's serial device nodes", async () => {
      const ran = await executeListSerialPorts("/usr/sbin/system_profiler");
      expect(ran.ok).toBe(true);
      if (!ran.ok) return;
      const devicePaths = ran.value.ports
        .map((row) => row.device_path)
        .filter((path) => path !== null);
      expect(devicePaths).toContain("/dev/cu.Bluetooth-Incoming-Port");
      expect(devicePaths).toContain("/dev/cu.BoseNC700HP");
      expect(devicePaths).toContain("/dev/cu.debug-console");
      expect(devicePaths).toContain("/dev/tty.debug-console");
      for (const path of devicePaths)
        expect(path).toMatch(/^\/dev\/(cu|tty)\.[^/]+$/u);
      expect(ran.value.unmatched_port_names).toEqual([]);
    }, 40_000);

    it("configures a real cu device's line discipline with stty without transmitting", async () => {
      const ran = await executeObserveSerialPort(
        {
          device_path: "/dev/cu.debug-console",
          duration_seconds: 1,
          baud_rate: 9600,
        },
        undefined,
      );
      expect(ran.ok).toBe(true);
      if (!ran.ok) return;
      expect(ran.value.tools.stty).toBe(STTY_PATH);
      expect(ran.value.stop_reason).toBe("deadline");
      expect(ran.value.bytes_observed).toBe(0);
      expect(ran.value.coverage).toBe("complete");
    }, 40_000);
  },
);
