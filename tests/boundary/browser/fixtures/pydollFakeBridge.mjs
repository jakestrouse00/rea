#!/usr/bin/env node
// Offline pydoll-bridge stand-in: happy protocol behaviors. The probe test's
// probe-failing and broken-advertising variants live in sibling fixtures.

const ADVERTISING = {
  advertising: {
    protocol: 1,
    pydoll_version: "3.0.0-fake",
    capabilities: {
      emulation: true,
      keyboard: true,
      select_option: true,
      downloads: false,
      popups: false,
      workers: false,
    },
  },
};

let fakeMode = "launch";

const write = (value) => {
  process.stdout.write(`${JSON.stringify(value)}\n`);
};

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const handlers = {
  open_session: (id, params) => {
    fakeMode = params.mode === "connect" ? "connect" : "launch";
    write({
      id,
      ok: true,
      result: {
        product: "Chromium",
        version: "Fake Chromium 140",
        target_id: "FAKE_TARGET",
        initial_url: "about:blank",
        owned_browser_pid: 4242,
        applied_environment: ["timezone", "viewport"],
        skipped_environment: ["locale"],
        event_domains_enabled: ["Page", "Network"],
      },
    });
    write({
      event: "scenario",
      params: {
        family: "network",
        data: {
          kind: "request",
          request_id: "7",
          url: "https://app.example.test/",
          method: "GET",
          resource_type: "Document",
        },
      },
    });
    write({
      event: "scenario",
      params: {
        family: "console",
        data: { kind: "console", level: "log", text: "boot", url: "" },
      },
    });
    // Exercises the bridge's bounded-queue reporting path end to end.
    write({
      event: "scenario",
      params: {
        family: "omissions",
        data: { kind: "event_queue_overflow", count: 3 },
      },
    });
    return true;
  },
  perform: (id, params) => {
    const action = params.action ?? {};
    if (action.action === "goto") {
      write({
        event: "scenario",
        params: {
          family: "network",
          data: {
            kind: "response",
            request_id: "7",
            url: "https://app.example.test/",
            status: 200,
            headers: { "content-type": "text/html" },
          },
        },
      });
    }
    write({
      id,
      ok: true,
      result: {
        final_url: "https://app.example.test/after",
        notes: ["fill dispatched synthetic input and change events"],
      },
    });
    return true;
  },
  capture: (id, params) => {
    const requested = Array.isArray(params.requested) ? params.requested : [];
    if (requested.includes("history")) {
      write({
        id,
        ok: true,
        result: {
          artifacts: [
            {
              kind: "history",
              length: 2,
              raw_entries: [
                { type: "navigate", url: "https://app.example.test/" },
                { type: "navigate", url: "https://app.example.test/after" },
              ],
            },
          ],
          notes: [],
        },
      });
      return true;
    }
    if (requested.includes("storage")) {
      write({
        id,
        ok: true,
        result: {
          artifacts: [
            {
              kind: "storage",
              cookies: [
                {
                  name: "session",
                  value: "token-value",
                  domain: "app.example.test",
                  path: "/",
                  secure: true,
                  http_only: false,
                  same_site: "Lax",
                  same_site_raw: "Lax",
                },
              ],
              local_storage: [],
              session_storage: [],
            },
            { kind: "url", raw_url: "https://app.example.test/after" },
          ],
          notes: [],
        },
      });
      return true;
    }
    write({
      id,
      ok: true,
      result: {
        artifacts: [{ kind: "url", raw_url: "https://app.example.test/after" }],
        notes: [],
      },
    });
    return true;
  },
  seed_storage: (id) => {
    write({
      id,
      ok: true,
      result: {
        applied: ["cookies"],
        notes: ["Page domain enabled for the one-shot seed removal"],
      },
    });
    return true;
  },
  close_session: (id) => {
    write({
      id,
      ok: true,
      result: {
        outcome:
          fakeMode === "connect"
            ? "disconnected-external"
            : "terminated-owned-process",
        profile_removed: false,
      },
    });
    process.exit(0);
  },
};

const dispatch = (line) => {
  let request;
  try {
    request = JSON.parse(line);
  } catch {
    return;
  }
  if (typeof request.id !== "number" || typeof request.method !== "string")
    return;
  const handler = handlers[request.method];
  if (handler === undefined) {
    write({
      id: request.id,
      ok: false,
      error: { reason: "method_unknown", message: "no such method" },
    });
    return;
  }
  handler(request.id, request.params ?? {});
};

const main = async () => {
  if (process.argv.includes("--check")) {
    write(ADVERTISING);
    process.exit(0);
  }
  write(ADVERTISING);
  let buffer = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    for (;;) {
      const boundary = buffer.indexOf("\n");
      if (boundary < 0) break;
      const line = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 1);
      dispatch(line);
    }
  });
  process.stdin.on("close", () => process.exit(0));
  void delay(600_000);
};

main();
