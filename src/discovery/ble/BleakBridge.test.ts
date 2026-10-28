import { describe, expect, it } from "vitest";

import {
  BLEAK_BRIDGE_PATH,
  gattHelperRemediation,
  selectGattHelper,
} from "./BleakBridge.js";
import {
  GattSessionManager,
  GattSessionUnknownError,
  type GattChild,
} from "./GattSessionManager.js";
import {
  executeGattEnumerate,
  executeGattSubscribe,
  GATT_ENUMERATE_OPERATION,
  GATT_SUBSCRIBE_OPERATION,
} from "./GattSessionOperations.js";

const CONNECTED_LINE = JSON.stringify({
  event: "connected",
  name: "Fake Peripheral",
  services: [
    {
      uuid: "180A",
      characteristics: [{ uuid: "2A29", properties: ["read"] }],
    },
  ],
});

class FakeChild implements GattChild {
  readonly written: string[] = [];
  kills: string[] = [];
  readonly stdin = {
    write: (text: string) => {
      this.written.push(text);
    },
    end: () => {},
  };
  readonly onStdoutLineHandlers: ((line: string) => void)[] = [];
  readonly onExitHandlers: ((report: {
    readonly code: number | null;
  }) => void)[] = [];
  stderr = "";

  onStdoutLine(listener: (line: string) => void): void {
    this.onStdoutLineHandlers.push(listener);
  }

  onExit(listener: (report: { readonly code: number | null }) => void): void {
    this.onExitHandlers.push(listener);
  }

  stderrTail(): string {
    return this.stderr;
  }

  kill(signal: "SIGTERM" | "SIGKILL"): void {
    this.kills.push(signal);
  }

  emit(line: string): void {
    for (const listener of this.onStdoutLineHandlers) listener(line);
  }

  exit(code: number | null): void {
    for (const listener of this.onExitHandlers.splice(0)) listener({ code });
  }

  lastCommand(): Record<string, unknown> {
    const text = this.written.at(-1) ?? "";
    return JSON.parse(text) as Record<string, unknown>;
  }
}

const openFixture = async (
  leadingArguments: readonly string[] = [],
): Promise<{
  readonly manager: GattSessionManager;
  readonly child: FakeChild;
  readonly sessionId: string;
  readonly spawnRequests: {
    readonly executable: string;
    readonly arguments: readonly string[];
  }[];
}> => {
  const child = new FakeChild();
  const spawnRequests: {
    readonly executable: string;
    readonly arguments: readonly string[];
  }[] = [];
  const manager = new GattSessionManager({
    spawnChild: (request) => {
      spawnRequests.push(request);
      return child;
    },
  });
  const openPromise = manager.open(
    "/usr/bin/python3",
    { peripheral_id: "83230DAD", connect_timeout_ms: 1000 },
    undefined,
    "connect_ble_gatt",
    leadingArguments,
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  child.emit(CONNECTED_LINE);
  const opened = await openPromise;
  if (!opened.ok) throw new Error("the fixture's session open failed");
  return { manager, child, sessionId: opened.value.session_id, spawnRequests };
};

describe("GATT helper selection", () => {
  it("prefers a caller-built CoreBluetooth helper over the bundled bridge", () => {
    expect(
      selectGattHelper({
        bleGatt: "/opt/rea/bin/gatt",
        bleakPython: "/usr/bin/python3",
      }),
    ).toEqual({
      transport: "corebluetooth",
      executable: "/opt/rea/bin/gatt",
      leadingArguments: [],
    });
  });

  it("selects the bundled bridge through the caller's interpreter", () => {
    expect(
      selectGattHelper({ bleGatt: null, bleakPython: "/usr/bin/python3" }),
    ).toEqual({
      transport: "bleak",
      executable: "/usr/bin/python3",
      leadingArguments: [BLEAK_BRIDGE_PATH],
    });
    expect(BLEAK_BRIDGE_PATH).toMatch(/bridge\/ble\/bleak_bridge\.py$/u);
  });

  it("returns null, never a guessed interpreter, when neither is selected", () => {
    expect(selectGattHelper({ bleGatt: null, bleakPython: null })).toBeNull();
    expect(gattHelperRemediation()).toContain("REA_BLEAK_PYTHON");
    expect(gattHelperRemediation()).toContain("REA_BLE_GATT_PATH");
  });

  it("spawns the bridge with its script before the helper's own flags", async () => {
    const { spawnRequests } = await openFixture([BLEAK_BRIDGE_PATH]);
    expect(spawnRequests).toEqual([
      {
        executable: "/usr/bin/python3",
        arguments: [
          BLEAK_BRIDGE_PATH,
          "--peripheral-id",
          "83230DAD",
          "--timeout-ms",
          "1000",
          "--max-output-bytes",
          String(2 * 1024 * 1024),
        ],
      },
    ]);
  });
});

describe("enumerate_gatt_services", () => {
  it("returns the live tree the helper published, bounded by the caller", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattEnumerate(
      manager,
      {
        session_id: sessionId,
        max_services: 16,
        max_characteristics_per_service: 64,
      },
      undefined,
      2_000,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const request = child.lastCommand();
    expect(request.op).toBe("enumerate");
    child.emit(
      JSON.stringify({
        event: "services",
        id: request.id,
        services: [
          {
            uuid: "180F",
            characteristics: [
              { uuid: "2A19", properties: ["read", "notify"] },
              { uuid: "2A1A", properties: ["read"] },
            ],
          },
          {
            uuid: "180A",
            characteristics: [{ uuid: "2A29", properties: ["read"] }],
          },
        ],
      }),
    );
    const result = await pending;
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.peripheral_id).toBe("83230DAD");
    expect(result.value.service_count).toBe(2);
    expect(result.value.characteristics_omitted).toBe(0);
    expect(result.value.services_truncated).toBe(false);
    expect(result.value.services).toEqual([
      {
        uuid: "180F",
        characteristics: [
          { uuid: "2A19", properties: ["read", "notify"] },
          { uuid: "2A1A", properties: ["read"] },
        ],
      },
      {
        uuid: "180A",
        characteristics: [{ uuid: "2A29", properties: ["read"] }],
      },
    ]);
  });

  it("counts the characteristics it does not retain", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattEnumerate(
      manager,
      {
        session_id: sessionId,
        max_services: 1,
        max_characteristics_per_service: 1,
      },
      undefined,
      2_000,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const request = child.lastCommand();
    child.emit(
      JSON.stringify({
        event: "services",
        id: request.id,
        services: [
          {
            uuid: "180F",
            characteristics: [
              { uuid: "2A19", properties: ["read"] },
              { uuid: "2A1A", properties: ["read"] },
            ],
          },
          { uuid: "180A", characteristics: [] },
        ],
      }),
    );
    const result = await pending;
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.services).toHaveLength(1);
    expect(result.value.service_count).toBe(2);
    expect(result.value.characteristics_omitted).toBe(1);
    expect(result.value.services_truncated).toBe(true);
  });

  it("refuses an unknown session before any helper command", async () => {
    const { manager } = await openFixture();
    await expect(
      executeGattEnumerate(
        manager,
        {
          session_id: "00000000-0000-4000-8000-000000000999",
          max_services: 4,
          max_characteristics_per_service: 4,
        },
        undefined,
        2_000,
      ),
    ).resolves.toMatchObject({ ok: false });
    let caught: unknown;
    try {
      await executeGattEnumerate(
        manager,
        {
          session_id: "00000000-0000-4000-8000-000000000999",
          max_services: 4,
          max_characteristics_per_service: 4,
        },
        undefined,
        2_000,
      );
    } catch (cause: unknown) {
      caught = cause;
    }
    // The operation reports the refusal as a typed input error rather than throwing.
    expect(
      caught === undefined || caught instanceof GattSessionUnknownError,
    ).toBe(true);
  });
});

describe("subscribe_characteristic", () => {
  const notification = (
    id: unknown,
    payloadHex: string,
    index: number,
  ): string =>
    JSON.stringify({
      event: "notification",
      id,
      ts: `2026-10-28T00:00:0${String(index % 10)}Z`,
      payload_hex: payloadHex,
    });

  it("reports digest-only rows with the window's stop reason", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattSubscribe(
      manager,
      {
        session_id: sessionId,
        service_uuid: "180F",
        characteristic_uuid: "2A19",
        observe_seconds: 2,
        max_notifications: 10,
        include_payload_hex: false,
      },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const request = child.lastCommand();
    expect(request).toMatchObject({
      op: "subscribe",
      service: "180F",
      characteristic: "2A19",
      seconds: 2,
      max_notifications: 10,
    });
    child.emit(notification(request.id, "33101100", 1));
    child.emit(notification(request.id, "aabbccdd", 2));
    child.emit(
      JSON.stringify({
        event: "window_end",
        id: request.id,
        stop_reason: "deadline",
      }),
    );
    const result = await pending;
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.notification_count).toBe(2);
    expect(result.value.buffer_full).toBe(false);
    expect(result.value.window_exhausted).toBe(true);
    expect(result.value.stop_reason).toBe("deadline");
    expect(result.value.notifications.map(({ len }) => len)).toEqual([4, 4]);
    expect(result.value.notifications[0]!.payload_hex).toBeNull();
    expect(result.value.notifications[0]!.sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(JSON.stringify(result.value)).not.toContain("33101100");
  });

  it("stops retaining at the buffer bound and counts later rows", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattSubscribe(
      manager,
      {
        session_id: sessionId,
        service_uuid: "180F",
        characteristic_uuid: "2A19",
        observe_seconds: 2,
        max_notifications: 2,
        include_payload_hex: false,
      },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const request = child.lastCommand();
    for (let index = 0; index < 5; index += 1)
      child.emit(notification(request.id, "00112233", index));
    child.emit(
      JSON.stringify({
        event: "window_end",
        id: request.id,
        stop_reason: "buffer_full",
      }),
    );
    const result = await pending;
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.notifications).toHaveLength(2);
    expect(result.value.notification_count).toBe(5);
    expect(result.value.buffer_full).toBe(true);
    expect(result.value.window_exhausted).toBe(false);
    expect(result.value.stop_reason).toBe("buffer_full");
  });

  it("reports a peer disconnect during the window as an adapter failure", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattSubscribe(
      manager,
      {
        session_id: sessionId,
        service_uuid: "180F",
        characteristic_uuid: "2A19",
        observe_seconds: 2,
        max_notifications: 4,
        include_payload_hex: false,
      },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    child.exit(1);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error._tag).toBe("ProviderAdapterError");
  });

  it("names the operation it refused for a helper error row", async () => {
    const { manager, child, sessionId } = await openFixture();
    const pending = executeGattSubscribe(
      manager,
      {
        session_id: sessionId,
        service_uuid: "180F",
        characteristic_uuid: "2A19",
        observe_seconds: 2,
        max_notifications: 4,
        include_payload_hex: false,
      },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const request = child.lastCommand();
    child.emit(
      JSON.stringify({
        event: "error",
        id: request.id,
        message: "characteristic is not notifiable",
      }),
    );
    const result = await pending;
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.userMessage).toContain(GATT_SUBSCRIBE_OPERATION);
    expect(result.error.userMessage).toContain("not notifiable");
    expect(GATT_ENUMERATE_OPERATION).toBe("enumerate_gatt_services");
  });
});
