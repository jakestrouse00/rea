import { expect, it } from "vitest";
import { MitmproxyCaptureAdapter } from "./MitmproxyCaptureAdapter.js";
import { AnalysisCapabilityUnavailableError } from "../../domain/analysisErrorCore.js";
import { MITMPROXY_CAPTURE_PROVIDER_IDENTITY } from "./CaptureRelease.js";

const requestPath = "/runtime/request.json";
const runtimePath = "/runtime";
// Any existing regular executable file admits the command-building tests
// without a real mitmdump installation; this one is the test runner itself.
const env = { REA_MITMDUMP_COMMAND: process.execPath };

it("builds the owned offline decoder command on Linux", async () => {
  const command = await new MitmproxyCaptureAdapter(env, "linux").command(
    requestPath,
    runtimePath,
  );
  expect(command.command).toBe(process.execPath);
  expect(command.arguments).toContain("--no-server");
  expect(command.arguments.join(" ")).toContain("capture.py");
});

it("builds the same offline decoder command on macOS with the same bounds", async () => {
  const command = await new MitmproxyCaptureAdapter(env, "darwin").command(
    requestPath,
    runtimePath,
  );
  const linux = await new MitmproxyCaptureAdapter(env, "linux").command(
    requestPath,
    runtimePath,
  );
  expect(command).toEqual(linux);
  expect(
    new MitmproxyCaptureAdapter(env, "darwin").limitations.join(" "),
  ).toContain("not enforce RLIMIT_AS");
  expect(MITMPROXY_CAPTURE_PROVIDER_IDENTITY.version).toBe("12.2.3");
});

it.each([
  ["win32", env],
  ["darwin", {}],
  ["darwin", { REA_MITMDUMP_COMMAND: "relative/mitmdump" }],
])(
  "rejects unsupported or unconfigured platforms and paths (%s, %j)",
  async (platform, environment) => {
    await expect(
      new MitmproxyCaptureAdapter(
        environment,
        platform as NodeJS.Platform,
      ).command(requestPath, runtimePath),
    ).rejects.toThrow(AnalysisCapabilityUnavailableError);
  },
);

it("names both supported hosts in the unavailable requirement", async () => {
  await expect(
    new MitmproxyCaptureAdapter({}, "darwin").command(requestPath, runtimePath),
  ).rejects.toThrow(/Linux or macOS/u);
});
