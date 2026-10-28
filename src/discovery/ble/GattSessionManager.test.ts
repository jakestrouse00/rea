import { describe, expect, it } from "vitest";

import {
  GattSessionManager,
  GattSessionUnknownError,
  type GattChild,
} from "./GattSessionManager.js";

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

  stderr = "";

  emit(line: string): void {
    for (const listener of this.onStdoutLineHandlers) listener(line);
  }

  exit(code: number | null): void {
    for (const listener of this.onExitHandlers.splice(0)) listener({ code });
  }
}

const managerWithChild = (child: FakeChild) => {
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
  return { manager, spawnRequests };
};

/**
 * Open one session through the fake child's handshake so each command or
 * close test starts from a connected session.
 */
const openFixture = async (child: FakeChild) => {
  const { manager, spawnRequests } = managerWithChild(child);
  const openPromise = manager.open(
    "/opt/rea/bin/gatt",
    { peripheral_id: "83230DAD", connect_timeout_ms: 1000 },
    undefined,
  );
  await new Promise((resolve) => setTimeout(resolve, 10));
  child.emit(CONNECTED_LINE);
  const opened = await openPromise;
  if (!opened.ok) throw new Error("the fixture's session open failed");
  return { manager, opened: opened.value, spawnRequests };
};

const commandLimits = {
  deadlineMs: 2000,
  signal: undefined,
  includePayloadHex: false,
  collectNotifications: false,
} as const;

describe("GattSessionManager.open", () => {
  it("spawns the helper with the peripheral contract and records the session", async () => {
    const gattChild = new FakeChild();
    const { manager, spawnRequests } = managerWithChild(gattChild);
    const openPromise = manager.open(
      "/opt/rea/bin/gatt",
      { peripheral_id: "83230DAD", connect_timeout_ms: 4000 },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit(CONNECTED_LINE);
    const opened = await openPromise;
    expect(opened.ok).toBe(true);
    if (!opened.ok) return;
    expect(spawnRequests).toEqual([
      {
        executable: "/opt/rea/bin/gatt",
        arguments: [
          "--peripheral-id",
          "83230DAD",
          "--timeout-ms",
          "4000",
          "--max-output-bytes",
          String(2 * 1024 * 1024),
        ],
      },
    ]);
    expect(opened.value.name).toBe("Fake Peripheral");
    expect(opened.value.session_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
    );
    const firstService = opened.value.services[0];
    expect(firstService?.characteristics[0]?.properties).toEqual(["read"]);
    expect(manager.has(opened.value.session_id)).toBe(true);
  });

  it("reports an authorization denial as a structured failure and stops the child", async () => {
    const gattChild = new FakeChild();
    gattChild.stderr = '{"event":"authorization_denied"}';
    const { manager } = managerWithChild(gattChild);
    const openPromise = manager.open(
      "/opt/rea/bin/gatt",
      { peripheral_id: "83230DAD", connect_timeout_ms: 1000 },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.exit(2);
    const opened = await openPromise;
    expect(opened.ok).toBe(false);
    if (opened.ok) return;
    expect((opened.error as { code?: string }).code).toBe(
      "authorization_denied",
    );
    expect(gattChild.kills.length).toBeGreaterThan(0);
  });

  it("reports a refused handshake with the peer's own reason", async () => {
    const gattChild = new FakeChild();
    const { manager } = managerWithChild(gattChild);
    const openPromise = manager.open(
      "/opt/rea/bin/gatt",
      { peripheral_id: "missing", connect_timeout_ms: 1000 },
      undefined,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit(
      '{"event":"connection_failed","code":"refused","message":"peripheral identifier not known to this host"}',
    );
    gattChild.exit(3);
    const opened = await openPromise;
    expect(opened.ok).toBe(false);
    if (opened.ok) return;
    expect((opened.error as { code?: string }).code).toBe("connect_refused");
    expect((opened.error as { reason?: string }).reason).toContain(
      "peripheral identifier not known to this host",
    );
    expect(gattChild.kills.length).toBeGreaterThan(0);
  });

  it("cancels under an abort signal and stops the child", async () => {
    const gattChild = new FakeChild();
    const { manager } = managerWithChild(gattChild);
    const controller = new AbortController();
    const openPromise = manager.open(
      "/opt/rea/bin/gatt",
      { peripheral_id: "83230DAD", connect_timeout_ms: 1000 },
      controller.signal,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    controller.abort();
    const opened = await openPromise;
    expect(opened.ok).toBe(false);
    if (opened.ok) return;
    expect(opened.error).toBeInstanceOf(Error);
    expect(gattChild.kills).toContain("SIGKILL");
  });
});

describe("GattSessionManager notification rows", () => {
  it("collects notification rows up to the window's end", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const observePromise = manager.command(
      opened.session_id,
      "observe_gatt_notifications",
      { op: "observe", service: "180A", characteristic: "2A29", seconds: 2 },
      {
        deadlineMs: 10_000,
        signal: undefined,
        includePayloadHex: true,
        collectNotifications: true,
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit(
      '{"event":"notification","ts":"2026-10-28T05:00:00.000Z","payload_hex":"aa"}',
    );
    gattChild.emit(
      '{"event":"notification","ts":"2026-10-28T05:00:01.000Z","payload_hex":"bbcc"}',
    );
    gattChild.emit('{"event":"stray","payload_hex":"zz"}');
    gattChild.emit('{"event":"window_end"}');
    const window = await observePromise;
    expect(window.ok).toBe(true);
    if (!window.ok) return;
    expect(window.value.notifications.map((row) => row.payload_hex)).toEqual([
      "aa",
      "bbcc",
    ]);
    expect(
      window.value.notifications.every((row) =>
        /^[0-9a-f]{64}$/u.test(row.sha256),
      ),
    ).toBe(true);
    expect(window.value.unparsed_lines).toEqual([
      '{"event":"stray","payload_hex":"zz"}',
    ]);
    // The row's framing survives; its bytes reach Evidence only through the
    // opted-in payload_hex field, never through raw.
    expect(window.value.notifications.map((row) => row.raw)).toEqual([
      '{"event":"notification","ts":"2026-10-28T05:00:00.000Z"}',
      '{"event":"notification","ts":"2026-10-28T05:00:01.000Z"}',
    ]);
  });

  it("withholds notification bytes from raw when the caller did not opt in", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const observePromise = manager.command(
      opened.session_id,
      "observe_gatt_notifications",
      { op: "observe", service: "180A", characteristic: "2A29", seconds: 2 },
      {
        deadlineMs: 10_000,
        signal: undefined,
        includePayloadHex: false,
        collectNotifications: true,
      },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit(
      '{"event":"notification","ts":"2026-10-28T05:00:00.000Z","payload_hex":"c0ffee"}',
    );
    gattChild.emit('{"event":"window_end"}');
    const window = await observePromise;
    expect(window.ok).toBe(true);
    if (!window.ok) return;
    expect(window.value.notifications[0]!.payload_hex).toBeNull();
    expect(JSON.stringify(window.value)).not.toContain("c0ffee");
  });
});

describe("GattSessionManager.command", () => {
  it("collects one read digest and drops the payload hex unless opted in", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const readPromise = manager.command(
      opened.session_id,
      "read_gatt_characteristic",
      { op: "read", service: "180A", characteristic: "2A29" },
      commandLimits,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(gattChild.written.at(-1)).toContain('"op":"read"');
    gattChild.emit('{"event":"value","payload_hex":"31302f"}');
    const value = await readPromise;
    expect(value.ok).toBe(true);
    if (!value.ok) return;
    expect(value.value.payload).toMatchObject({
      len: 3,
      payload_hex: null,
    });
    expect(value.value.payload?.sha256).toEqual(
      expect.stringMatching(/^[0-9a-f]{64}$/u),
    );
  });

  it("maps the helper's refusal of a command to a structured failure", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const writePromise = manager.command(
      opened.session_id,
      "write_gatt_characteristic",
      {
        op: "write",
        service: "180A",
        characteristic: "2A29",
        payload_hex: "aa",
      },
      commandLimits,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit(
      '{"event":"error","message":"characteristic cannot write with response"}',
    );
    const written = await writePromise;
    expect(written.ok).toBe(false);
    if (written.ok) return;
    expect((written.error as { code?: string }).code).toBe("command_refused");
    expect((written.error as { reason?: string }).reason).toContain(
      "cannot write with response",
    );
  });

  it("reports a helper exit mid-command as a disconnected peer", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const readPromise = manager.command(
      opened.session_id,
      "read_gatt_characteristic",
      { op: "read", service: "180A", characteristic: "2A29" },
      { ...commandLimits, deadlineMs: 5000 },
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.exit(1);
    const value = await readPromise;
    expect(value.ok).toBe(false);
    if (value.ok) return;
    expect((value.error as { code?: string }).code).toBe("peer_disconnected");
  });

  it("serializes concurrent commands on the same session", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const first = manager.command(
      opened.session_id,
      "read_gatt_characteristic",
      { op: "read", service: "180A", characteristic: "2A29" },
      commandLimits,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    const second = manager.command(
      opened.session_id,
      "read_gatt_characteristic",
      { op: "read", service: "180A", characteristic: "2A29" },
      commandLimits,
    );
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(
      gattChild.written.filter((text) => text.includes('"op":"read"')),
    ).toHaveLength(1);
    gattChild.emit('{"event":"value","payload_hex":"01"}');
    const firstDone = await first;
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit('{"event":"value","payload_hex":"02"}');
    const secondDone = await second;
    expect(firstDone.ok && secondDone.ok).toBe(true);
    if (firstDone.ok && secondDone.ok) {
      expect(firstDone.value.payload?.sha256).not.toBe(
        secondDone.value.payload?.sha256,
      );
    }
  });
});

describe("GattSessionManager.close", () => {
  it("disconnects cleanly when the helper acknowledges and exits", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const closePromise = manager.close(opened.session_id, undefined);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(gattChild.written.at(-1)).toContain('"op":"disconnect"');
    gattChild.emit('{"event":"disconnected"}');
    gattChild.exit(0);
    const closed = await closePromise;
    expect(closed.ok).toBe(true);
    if (!closed.ok) return;
    expect(closed.value.clean).toBe(true);
    expect(closed.value.detail).toBeNull();
    expect(manager.has(opened.session_id)).toBe(false);
  });

  it("escalates to SIGTERM and reports cleanup uncertainty", async () => {
    const gattChild = new FakeChild();
    const { manager, opened } = await openFixture(gattChild);
    const closePromise = manager.close(opened.session_id, undefined);
    await new Promise((resolve) => setTimeout(resolve, 10));
    gattChild.emit('{"event":"error","message":"radio gone"}');
    await closePromise;
    expect(gattChild.kills).toContain("SIGTERM");
    expect(manager.has(opened.session_id)).toBe(false);
  });
});

describe("GattSessionManager.unknown sessions", () => {
  it("throws synchronously for an unknown session id", () => {
    const manager = new GattSessionManager({
      spawnChild: () => new FakeChild(),
    });
    expect(() =>
      manager.command(
        "00000000-0000-4000-8000-000000000000",
        "read_gatt_characteristic",
        { op: "read", service: "180A", characteristic: "2A29" },
        commandLimits,
      ),
    ).toThrow(GattSessionUnknownError);
  });
});
