#!/usr/bin/env node
/**
 * Scripted stand-in for `mitmdump` used by the offline interception-lane tests.
 *
 * It reads one scenario file, writes the startup advertisement and the listed
 * structure-stream frames on stdout, and can retain entry records and bodies in
 * REA_MITM_HOLD_DIR the way the generated addon does. It opens no socket and
 * makes no request.
 *
 * Scenario shape:
 *   {
 *     "ready": { ... } | null,          // null/absent: advertise from the env
 *     "mode": "linger" | "exit",        // default linger
 *     "steps": [
 *       { "kind": "emit", "line": {...} },
 *       { "kind": "raw", "text": "..." },
 *       { "kind": "sleep", "ms": 20 },
 *       { "kind": "entry", "sequence": 1,
 *         "request": {"method", "url", "headers", "body"},
 *         "response": {"status", "body"} | null },
 *       { "kind": "entryAndFlow", "sequence": 1, "line": {...},
 *         "request": {...}, "response": {...} | null }
 *     ]
 *   }
 *
 * `entryAndFlow` writes the record first and replaces the emitted line's
 * `entry` with the retained file's real path, size, and digest.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";

const scenarioPath = process.argv[2];
const scenario = JSON.parse(readFileSync(scenarioPath, "utf8"));

const write = (value) => {
  process.stdout.write(`${JSON.stringify(value)}\n`);
};

const holdDirectory = () => process.env.REA_MITM_HOLD_DIR ?? "";

const retain = (relative, bytes) => {
  const directory = holdDirectory();
  if (directory === "") return null;
  const target = join(directory, relative);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  writeFileSync(target, bytes, { mode: 0o600 });
  chmodSync(target, 0o600);
  return {
    path: target,
    bytes: bytes.length,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
};

const ready =
  scenario.ready === undefined
    ? {
        type: "ready",
        protocol: 1,
        addon: { id: "rea-mitm-addon", version: 1 },
        mitmproxy: { version: "12.2.3" },
        listen: {
          host: "127.0.0.1",
          port: Number(process.env.REA_MITM_LISTEN_PORT ?? "8080"),
        },
      }
    : scenario.ready;

if (ready !== false) write(ready);

const writeEntry = (step) => {
  const request = step.request;
  const requestBody = Buffer.from(request.body ?? "", "utf8");
  const requestHold =
    requestBody.length === 0
      ? null
      : retain(join("bodies", `${step.sequence}.req.bin`), requestBody);
  const responseBody =
    step.response === null || step.response === undefined
      ? Buffer.alloc(0)
      : Buffer.from(step.response.body ?? "", "utf8");
  const responseHold =
    responseBody.length === 0
      ? null
      : retain(join("bodies", `${step.sequence}.res.bin`), responseBody);
  const record = {
    version: 1,
    sequence: step.sequence,
    method: request.method,
    url: request.url,
    headers: request.headers ?? [],
    body: {
      path: requestHold?.path ?? null,
      bytes: requestBody.length,
      sha256: requestHold?.sha256 ?? null,
    },
    response:
      step.response === null || step.response === undefined
        ? null
        : {
            status: step.response.status,
            body: {
              path: responseHold?.path ?? null,
              bytes: responseBody.length,
              sha256: responseHold?.sha256 ?? null,
            },
          },
  };
  return retain(
    join("entries", `${step.sequence}.json`),
    Buffer.from(JSON.stringify(record)),
  );
};

const run = async () => {
  for (const step of scenario.steps ?? []) {
    if (step.kind === "emit") write(step.line);
    else if (step.kind === "raw") process.stdout.write(step.text);
    else if (step.kind === "sleep")
      await new Promise((resolve) => setTimeout(resolve, step.ms));
    else if (step.kind === "entry") writeEntry(step);
    else if (step.kind === "entryAndFlow")
      write({ ...step.line, sequence: step.sequence, entry: writeEntry(step) });
  }
  if (scenario.mode === "exit") process.exit(0);
};

process.on("SIGTERM", () => process.exit(0));
process.on("SIGINT", () => process.exit(0));

await run();
setInterval(() => undefined, 1 << 30);
