import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { CdpBrowserProvider } from "../../../src/browser/CdpBrowserProvider.js";
import {
  analyzeBrowserMutation,
  browserEndpoint,
  expectBrowserMutation,
} from "./cdpBrowserMutation.support.js";
import {
  startFakeCdpBrowser,
  type FakeCdpBrowser,
} from "../../fixtures/fakeCdpBrowser.js";
import { trackBrowser } from "./cdpBrowserProvider.support.js";

const directories: string[] = [];

afterEach(async () => {
  await Promise.all(
    directories
      .splice(0)
      .map(async (directory) =>
        rm(directory, { recursive: true, force: true }),
      ),
  );
});

const temporaryDirectory = async (): Promise<string> => {
  const directory = await mkdtemp(join(tmpdir(), "rea-browser-fetch-"));
  directories.push(directory);
  return directory;
};

const pageAnswer = (body: string) => ({
  result: {
    type: "object",
    value: {
      state: "response",
      status: 200,
      headers: [
        ["content-type", "application/json"],
        ["x-served-by", "fake-page"],
      ],
      body_base64: Buffer.from(body).toString("base64"),
      body_truncated: false,
    },
  },
});

const providerFor = (browser: FakeCdpBrowser): CdpBrowserProvider =>
  new CdpBrowserProvider({ mutationOrigins: [browser.allowedOrigin] });

const fetchInput = (
  browser: FakeCdpBrowser,
  input: Record<string, unknown> = {},
) => ({
  cdp_endpoint: browserEndpoint(browser),
  allowed_origins: [browser.allowedOrigin],
  target_id: "allowed-page",
  method: "GET",
  url: `${browser.allowedOrigin}/api/session?token=page-secret`,
  headers: [],
  body: { kind: "none" as const },
  timeout_ms: 5_000,
  overwrite: false,
  ...input,
});

describe("browser_fetch composition with the replay send core", () => {
  it("dispatches once from the page and keeps the echoed form value-free", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate"
          ? pageAnswer('{"ok":true}')
          : undefined,
    });
    trackBrowser(browser);
    const provider = providerFor(browser);
    try {
      const result = await expectBrowserMutation(
        provider.fetchPage(
          fetchInput(browser, {
            headers: [
              { name: "accept", value: "application/json" },
              { name: "cookie", value: "session=header-secret" },
            ],
          }),
        ),
      );
      expect(result).toMatchObject({
        outcome: "response",
        retry: "none",
        target: { target_id: "allowed-page", origin: browser.allowedOrigin },
        request: {
          method: "GET",
          origin: browser.allowedOrigin,
          credential_header_names: ["cookie"],
          body_present: false,
        },
        response: {
          status: 200,
          status_class: "success",
          content_type_class: "json",
          header_names: ["content-type", "x-served-by"],
          size_class: "up_to_1_kib",
          bytes_observed: 11,
          body_truncated: false,
          dump: null,
        },
        redirect_chain: [
          {
            step: 0,
            method: "GET",
            origin: browser.allowedOrigin,
            status: 200,
            status_class: "success",
            location: null,
          },
        ],
        failure: null,
      });
      expect(result.browser_managed_header_names).toEqual(["cookie"]);
      expect(JSON.stringify(result)).not.toContain("header-secret");
      const evaluated = browser.commands.find(
        (command) => command.method === "Runtime.evaluate",
      );
      const expression = String(evaluated?.params.expression);
      expect(expression).toContain('credentials: "include"');
      expect(expression).toContain('redirect: "manual"');
      expect(expression).not.toContain("header-secret");
      expect(
        browser.commands.filter(
          (command) => command.method === "Runtime.evaluate",
        ),
      ).toHaveLength(1);
    } finally {
      await provider.close();
    }
  });
});

describe("browser_fetch refusals and retained bytes", () => {
  it("refuses when the operator allowlist is empty or excludes the origin", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate" ? pageAnswer("{}") : undefined,
    });
    trackBrowser(browser);
    const disabled = new CdpBrowserProvider();
    const scoped = providerFor(browser);
    try {
      const refused = await analyzeBrowserMutation(
        disabled.fetchPage(fetchInput(browser)),
      );
      expect(`${refused.message} ${refused.userMessage ?? ""}`).toContain(
        "REA_REPLAY_ALLOWED_ORIGINS",
      );
      const outside = await analyzeBrowserMutation(
        scoped.fetchPage(
          fetchInput(browser, {
            url: "https://unapproved.example.test/api/session",
          }),
        ),
      );
      expect(`${outside.message} ${outside.userMessage ?? ""}`).toContain(
        "outside this session's approved origins",
      );
      expect(
        browser.commands.some(
          (command) => command.method === "Runtime.evaluate",
        ),
      ).toBe(false);
    } finally {
      await disabled.close();
      await scoped.close();
    }
  });

  it("refuses a foreign tab before dispatch", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate" ? pageAnswer("{}") : undefined,
    });
    trackBrowser(browser);
    const provider = providerFor(browser);
    try {
      const refused = await analyzeBrowserMutation(
        provider.fetchPage(
          fetchInput(browser, {
            target_id: "disallowed-page",
            allowed_origins: [],
          }),
        ),
      );
      expect(`${refused.message} ${refused.userMessage ?? ""}`).toContain(
        "target_not_allowed",
      );
      expect(
        browser.commands.some(
          (command) => command.method === "Runtime.evaluate",
        ),
      ).toBe(false);
    } finally {
      await provider.close();
    }
  });

  it("reports an opaque page redirect as a terminal no-response", async () => {
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate"
          ? { result: { type: "object", value: { state: "opaque-redirect" } } }
          : undefined,
    });
    trackBrowser(browser);
    const provider = providerFor(browser);
    try {
      const result = await expectBrowserMutation(
        provider.fetchPage(fetchInput(browser)),
      );
      expect(result.outcome).toBe("no_response");
      expect(result.response).toBeNull();
      expect(result.redirect_chain).toEqual([]);
      expect(result.failure).toMatchObject({ kind: "other" });
      expect(result.failure?.message).toContain("opaque");
    } finally {
      await provider.close();
    }
  });

  it("writes owner-only response bytes to the caller-selected dump path", async () => {
    const directory = await temporaryDirectory();
    const dumpPath = join(directory, "response.bin");
    const body = '{"ok":true}';
    const browser = await startFakeCdpBrowser({
      commandResult: (command) =>
        command.method === "Runtime.evaluate" ? pageAnswer(body) : undefined,
    });
    trackBrowser(browser);
    const provider = providerFor(browser);
    try {
      const result = await expectBrowserMutation(
        provider.fetchPage(
          fetchInput(browser, { dump_path: dumpPath, timeout_ms: 5_000 }),
        ),
      );
      expect(result.response?.dump).toMatchObject({
        path: dumpPath,
        bytes: Buffer.byteLength(body),
        truncated: false,
      });
      expect(await readFile(dumpPath, "utf8")).toBe(body);
      expect((await stat(dumpPath)).mode & 0o777).toBe(0o600);
      const reused = await analyzeBrowserMutation(
        provider.fetchPage(
          fetchInput(browser, { dump_path: dumpPath, timeout_ms: 5_000 }),
        ),
      );
      expect(`${reused.message} ${reused.userMessage ?? ""}`).toContain(
        "already exists",
      );
      expect(
        browser.commands.filter(
          (command) => command.method === "Runtime.evaluate",
        ),
      ).toHaveLength(1);
    } finally {
      await provider.close();
    }
  });
});
