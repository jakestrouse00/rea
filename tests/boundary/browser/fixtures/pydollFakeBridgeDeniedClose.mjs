#!/usr/bin/env node
// Offline pydoll-bridge stand-in: open_session is happy and reports the
// interpreter pid through the perform reply notes; close_session is denied.
// In launch mode the child lingers so the parent must escalate with SIGTERM;
// in connect mode the child exits after the denial like a completed teardown.

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
        skipped_environment: [],
        event_domains_enabled: ["Page", "Network"],
      },
    });
    return true;
  },
  perform: (id) => {
    write({
      id,
      ok: true,
      result: {
        final_url: "https://app.example.test/after",
        notes: ["interpreter pid " + process.pid],
      },
    });
    return true;
  },
  capture: (id) => {
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
      result: { applied: [], notes: [] },
    });
    return true;
  },
  close_session: (id) => {
    write({
      id,
      ok: false,
      error: {
        reason: "close_denied",
        message:
          "close denied by the bridge interpreter (pid " + process.pid + ")",
      },
    });
    if (fakeMode === "connect") {
      process.exit(0);
    }
    void delay(600_000);
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
