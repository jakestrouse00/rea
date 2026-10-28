import { describe, expect, it } from "vitest";

import {
  SANDBOX_DISABLE_ENV,
  SANDBOX_PROFILE_EXECUTABLE,
  SandboxProfileRejection,
  sandboxDisableState,
  sandboxLaunchPlan,
  sandboxProfileSource,
} from "./sandboxProfiles.js";

const base = {
  workspace_root: "/tmp/rea-loop-1",
  executable_paths: ["/usr/bin/true"],
} as const;

describe("deny-default sandbox profiles", () => {
  it("starts from deny default and confines writes to the workspace", () => {
    const source = sandboxProfileSource(base);
    expect(source.split("\n")[0]).toBe("(version 1)");
    expect(source.split("\n")[1]).toBe("(deny default)");
    expect(source).not.toContain("(allow default)");
    expect(source).toContain('(allow file-write* (subpath "/tmp/rea-loop-1"))');
    expect(source).toContain('(allow process-exec (literal "/usr/bin/true"))');
  });

  it("admits no Mach lookup and no network unless the loop declares them", () => {
    const source = sandboxProfileSource(base);
    expect(source).toContain("(deny mach-lookup)");
    expect(source).toContain("(deny network-outbound)");
    expect(source).not.toContain("(allow mach-lookup");
    expect(source).not.toContain("(allow network-outbound");
  });

  it("admits only the declared destinations and named services", () => {
    const source = sandboxProfileSource({
      ...base,
      network_allowlist: [
        { host: "127.0.0.1", port: 8080 },
        { host: "::1", port: 8081 },
      ],
      mach_lookup: ["com.apple.system.logger"],
      readable_paths: ["/tmp/rea-fixtures"],
    });
    expect(source).toContain(
      '(allow network-outbound (remote ip "127.0.0.1:8080") (remote ip "::1:8081"))',
    );
    expect(source).toContain(
      '(allow mach-lookup (global-name "com.apple.system.logger"))',
    );
    expect(source).toContain('(subpath "/tmp/rea-fixtures")');
  });

  it("keeps the workspace writable even when the caller lists another directory", () => {
    const source = sandboxProfileSource({
      ...base,
      workspace_root: "/tmp/loop",
      writable_paths: ["/tmp/results"],
    });
    expect(source).toContain(
      '(allow file-write* (subpath "/tmp/loop") (subpath "/tmp/results"))',
    );
  });

  it("rejects requests SBPL cannot represent instead of widening them", () => {
    const rejections = [
      () => sandboxProfileSource({ ...base, workspace_root: "tmp/loop" }),
      () => sandboxProfileSource({ ...base, workspace_root: "/tmp/a/../b" }),
      () => sandboxProfileSource({ ...base, workspace_root: "/tmp/a\nb" }),
      () => sandboxProfileSource({ ...base, executable_paths: [] }),
      () =>
        sandboxProfileSource({
          ...base,
          network_allowlist: [{ host: "example.com", port: 443 }],
        }),
      () =>
        sandboxProfileSource({
          ...base,
          network_allowlist: [{ host: "127.0.0.1", port: 0 }],
        }),
    ];
    for (const reject of rejections)
      expect(reject).toThrow(SandboxProfileRejection);
  });

  it("escapes quotes and backslashes rather than truncating the path", () => {
    const source = sandboxProfileSource({
      ...base,
      readable_paths: ['/tmp/we"ird\\name'],
    });
    expect(source).toContain('(subpath "/tmp/we\\"ird\\\\name")');
  });
});

describe("emergency sandbox exit", () => {
  it("reports confinement only when the variable is absent or disabled explicitly", () => {
    expect(sandboxDisableState({})).toEqual({ kind: "enabled" });
    for (const value of ["0", "false", "off", ""])
      expect(sandboxDisableState({ [SANDBOX_DISABLE_ENV]: value })).toEqual({
        kind: "enabled",
      });
  });

  it("states the unconfined limitation instead of silently skipping the profile", () => {
    const state = sandboxDisableState({ [SANDBOX_DISABLE_ENV]: "1" });
    expect(state.kind).toBe("disabled");
    if (state.kind !== "disabled") return;
    expect(state.limitation).toContain("not confined");
    expect(state.limitation).toContain(SANDBOX_DISABLE_ENV);
  });

  it("refuses an unrecognized value instead of guessing", () => {
    const state = sandboxDisableState({ [SANDBOX_DISABLE_ENV]: "maybe" });
    expect(state).toMatchObject({ kind: "invalid" });
  });
});

describe("sandbox launch plan", () => {
  it("wraps the launch in sandbox-exec with the rendered profile", () => {
    const plan = sandboxLaunchPlan({
      executable: "/usr/bin/true",
      args: ["--flag"],
      profile: base,
      environment: {},
    });
    expect(plan.executable).toBe(SANDBOX_PROFILE_EXECUTABLE);
    expect(plan.args.slice(0, 2)).toEqual(["-p", sandboxProfileSource(base)]);
    expect(plan.args.slice(2)).toEqual(["/usr/bin/true", "--flag"]);
    expect(plan.limitations).toEqual([]);
  });

  it("returns the bare argv with the recorded limitation when disabled", () => {
    const plan = sandboxLaunchPlan({
      executable: "/usr/bin/true",
      args: ["--flag"],
      profile: base,
      environment: { [SANDBOX_DISABLE_ENV]: "true" },
    });
    expect(plan.executable).toBe("/usr/bin/true");
    expect(plan.args).toEqual(["--flag"]);
    expect(plan.limitations).toHaveLength(1);
  });

  it("refuses an invalid emergency-exit value before rendering a profile", () => {
    expect(() =>
      sandboxLaunchPlan({
        executable: "/usr/bin/true",
        args: [],
        profile: base,
        environment: { [SANDBOX_DISABLE_ENV]: "2" },
      }),
    ).toThrow(SandboxProfileRejection);
  });
});
