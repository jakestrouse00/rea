import {
  chmod,
  mkdir,
  readdir,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import type { Evidence } from "../domain/evidence.js";
import {
  LAB_VM_COMMAND_ENV,
  LAB_VM_MAX_COMMAND_BYTES,
} from "../domain/vmlab/labVm.js";
import {
  labVmCommandResultSchema,
  labVmStartResultSchema,
  labVmStopResultSchema,
} from "../domain/vmlab/labVmObservation.js";
import { LabVmSessionManager } from "./LabVmSessionManager.js";

const managers: LabVmSessionManager[] = [];

afterEach(async () => {
  await Promise.all(managers.splice(0).map((manager) => manager.closeAll()));
});

const temporaryRoot = (): Promise<string> => createTestTempDirectory("lab-vm-");

interface Harness {
  readonly root: string;
  readonly workspace: string;
  readonly runtimeRoot: string;
  readonly logPath: string;
  readonly manager: LabVmSessionManager;
}

/** A scripted stand-in for limactl: it records argv, then runs the behaviour. */
type Behaviour = string | ((context: Harness) => string);

const harness = async (
  behaviour: Behaviour,
  options: {
    readonly supported?: boolean;
    /** Replace the template-root release so a partial cleanup can be exercised. */
    readonly closeRoot?: () => Promise<void>;
  } = {},
): Promise<Harness> => {
  const root = await temporaryRoot();
  const workspace = join(root, "workspace");
  const runtimeRoot = join(root, "runtime");
  await Promise.all([
    mkdir(workspace, { recursive: true }),
    mkdir(runtimeRoot, { recursive: true }),
  ]);
  const command = join(root, "limactl");
  const logPath = join(root, "argv.log");
  const manager = new LabVmSessionManager({
    environment: { [LAB_VM_COMMAND_ENV]: command },
    createRuntimeRoot: async () => ({
      path: runtimeRoot,
      close:
        options.closeRoot ??
        (async () => {
          await rm(runtimeRoot, { recursive: true, force: true });
        }),
    }),
    ...(options.supported === false
      ? { platform: "linux" as const, arch: "x64" }
      : {}),
  });
  managers.push(manager);
  const created: Harness = { root, workspace, runtimeRoot, logPath, manager };
  const source = typeof behaviour === "string" ? behaviour : behaviour(created);
  await writeFile(
    command,
    `#!/bin/sh\nprintf '%s\\n' "$@" >> "${logPath}"\n${source}\n`,
    { mode: 0o700 },
  );
  await chmod(command, 0o700);
  return created;
};

const loggedArguments = async (logPath: string): Promise<readonly string[]> => {
  try {
    return (await readFile(logPath, "utf8")).split("\n").filter(Boolean);
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw cause;
  }
};

const waitForFile = async (path: string): Promise<void> => {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    try {
      await stat(path);
      return;
    } catch (cause) {
      if ((cause as NodeJS.ErrnoException).code !== "ENOENT") throw cause;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${path}`);
};

const waitForArguments = async (
  logPath: string,
  token: string,
): Promise<void> => {
  for (let attempt = 0; attempt < 500; attempt += 1) {
    if ((await loggedArguments(logPath)).includes(token)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${token} to reach ${logPath}`);
};

/**
 * A stand-in that models instance state: `start` records the instance name,
 * `list --json` reports that instance while it exists, so absence is a real
 * observation rather than an inference from a failed command.
 */
const statefulLimactl = (
  context: { readonly root: string },
  deleteCase: string,
): string => {
  const state = join(context.root, "state");
  return [
    `state="${state}"`,
    'mkdir -p "$state"',
    'if [ "$1" = "start" ]; then printf \'%s\' "$4" > "$state/name"; exit 0; fi',
    'if [ "$1" = "list" ]; then',
    '  if [ -f "$state/name" ] && [ ! -f "$state/gone" ]; then',
    '    printf \'{"name":"%s","status":"Running"}\\n\' "$(cat "$state/name")"',
    "  fi",
    "  exit 0",
    "fi",
    `if [ "$1" = "delete" ]; then ${deleteCase}; fi`,
    "exit 0",
  ].join("\n");
};

const sessionIdOf = (evidence: Evidence): string =>
  labVmStartResultSchema.parse(evidence.normalized_result).session_id;

const startSession = async (created: Harness): Promise<string> => {
  const started = await created.manager.start({
    workspacePath: created.workspace,
  });
  if (!started.ok) throw started.error;
  return sessionIdOf(started.value);
};

describe("lab VM configuration", () => {
  it("reports the selection it observed without probing a version", async () => {
    const created = await harness("exit 0");
    expect(created.manager.inspectAvailability()).toMatchObject({
      status: "available",
      code: null,
      diagnostics: {
        selected_command: join(created.root, "limactl"),
        version_probed: false,
        driver: "vz",
      },
    });
    expect(created.manager.defaultCommandTimeoutMs).toBe(120_000);
  });

  it("fails closed when no limactl is selected", async () => {
    const manager = new LabVmSessionManager({ environment: {} });
    managers.push(manager);
    expect(manager.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "not_configured",
    });
    const started = await manager.start({ workspacePath: "/tmp" });
    expect(started.ok).toBe(false);
    if (started.ok) return;
    expect(started.error._tag).toBe("AnalysisCapabilityUnavailableError");
  });

  it("refuses a relative selection and a non-executable file", async () => {
    const root = await temporaryRoot();
    const relative = new LabVmSessionManager({
      environment: { [LAB_VM_COMMAND_ENV]: "limactl" },
    });
    managers.push(relative);
    expect(relative.inspectAvailability()).toMatchObject({
      status: "unavailable",
      diagnostics: { setting: LAB_VM_COMMAND_ENV },
    });
    const plain = join(root, "limactl");
    await writeFile(plain, "#!/bin/sh\n", { mode: 0o600 });
    const notExecutable = new LabVmSessionManager({
      environment: { [LAB_VM_COMMAND_ENV]: plain },
    });
    managers.push(notExecutable);
    expect(notExecutable.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "not_configured",
      reason: expect.stringContaining("denied"),
    });
  });

  it("reports an unsupported host before reading the selection", async () => {
    const created = await harness("exit 0", { supported: false });
    expect(created.manager.inspectAvailability()).toMatchObject({
      status: "unavailable",
      code: "unsupported_host",
    });
    const started = await created.manager.start({
      workspacePath: created.workspace,
    });
    expect(started.ok).toBe(false);
    if (started.ok) return;
    expect(started.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(await loggedArguments(created.logPath)).toEqual([]);
  });
});

describe("start_lab_vm", () => {
  it("writes one private template and reports the issued session identity", async () => {
    const created = await harness("exit 0");
    const started = await created.manager.start({
      workspacePath: created.workspace,
    });
    if (!started.ok) throw started.error;
    const result = labVmStartResultSchema.parse(
      started.value.normalized_result,
    );
    expect(result).toMatchObject({
      guest_workspace: "/workspace",
      driver: "vz",
      rosetta: true,
      boot: { exit_type: "exited", exit_code: 0 },
      workspace_path: created.workspace,
    });
    expect(result.session_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
    const files = await readdir(created.runtimeRoot);
    expect(files).toHaveLength(1);
    const templatePath = join(created.runtimeRoot, files[0] ?? "");
    const template = await readFile(templatePath, "utf8");
    expect(template).toContain("vmType: vz");
    expect(template).toContain("  enabled: true");
    expect(template).toContain(`location: "${created.workspace}"`);
    expect((await stat(templatePath)).mode & 0o777).toBe(0o600);
    expect(await loggedArguments(created.logPath)).toEqual([
      "start",
      "--tty=false",
      "--name",
      `rea-lab-${result.session_id.slice(0, 8)}`,
      templatePath,
    ]);
  });

  it("rejects a workspace that is not an existing directory", async () => {
    const root = await temporaryRoot();
    const file = join(root, "not-a-directory");
    await writeFile(file, "x");
    const created = await harness("exit 0");
    const started = await created.manager.start({ workspacePath: file });
    expect(started.ok).toBe(false);
    if (started.ok) return;
    expect(started.error._tag).toBe("AnalysisInputError");
    expect(await loggedArguments(created.logPath)).toEqual([]);
  });

  it("rolls back a failed boot and reports the observed start failure", async () => {
    const created = await harness(
      'if [ "$1" = "start" ]; then echo "guest image unavailable" >&2; exit 4; fi\nexit 0',
    );
    const started = await created.manager.start({
      workspacePath: created.workspace,
    });
    expect(started.ok).toBe(false);
    if (started.ok) return;
    expect(started.error.userMessage).toContain("guest image unavailable");
    expect((await loggedArguments(created.logPath)).join(" ")).toContain(
      "delete",
    );
    await expect(stat(created.runtimeRoot)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("owns at most one live lab VM per server", async () => {
    const created = await harness("exit 0");
    await startSession(created);
    const second = await created.manager.start({
      workspacePath: created.workspace,
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.error._tag).toBe("AnalysisResourceConstraintError");
  });
});

describe("run_lab_vm_command", () => {
  it("reports the workspace paths the guest command produced, changed, and removed", async () => {
    // The stand-in mutates the mounted workspace exactly as a guest command
    // would through Lima's shared mount.
    const created = await harness(({ workspace }) =>
      [
        'if [ "$1" != "shell" ]; then exit 0; fi',
        `mkdir -p "${workspace}/out"`,
        `printf 'built' > "${workspace}/out/report.txt"`,
        `printf 'changed' > "${workspace}/kept.txt"`,
        `rm -f "${workspace}/gone.txt"`,
      ].join("\n"),
    );
    await Promise.all([
      writeFile(join(created.workspace, "kept.txt"), "before"),
      writeFile(join(created.workspace, "gone.txt"), "before"),
    ]);
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "make release",
      timeoutMs: 10_000,
    });
    if (!run.ok) throw run.error;
    const result = labVmCommandResultSchema.parse(run.value.normalized_result);
    expect(result).toMatchObject({
      exit_type: "exited",
      exit_code: 0,
      produced_paths: ["out/report.txt"],
      modified_paths: ["kept.txt"],
      removed_paths: ["gone.txt"],
      changes_truncated: false,
    });
    expect(
      run.value.locations.map((location) =>
        location.kind === "artifact-path" ? location.path : location.kind,
      ),
    ).toEqual([
      `${created.workspace}/kept.txt`,
      `${created.workspace}/out/report.txt`,
    ]);
    expect((await loggedArguments(created.logPath)).join(" ")).toContain(
      "--workdir /workspace",
    );
  });

  it("publishes no guest output bytes in the observation", async () => {
    const created = await harness(
      'if [ "$1" = "shell" ]; then echo "compiler chatter on stdout"; echo diagnostic >&2; fi\nexit 0',
    );
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "cc --version",
      timeoutMs: 10_000,
    });
    if (!run.ok) throw run.error;
    const result = labVmCommandResultSchema.parse(run.value.normalized_result);
    expect(result).toMatchObject({
      exit_type: "exited",
      exit_code: 0,
      output_truncated: false,
    });
    expect(result.stdout_bytes).toBeGreaterThan(0);
    expect(JSON.stringify(run.value)).not.toContain("compiler chatter");
    expect(JSON.stringify(run.value)).not.toContain("diagnostic");
  });

  it("keeps a non-zero exit as a typed failure with the observed facts", async () => {
    const created = await harness(
      'if [ "$1" = "shell" ]; then echo "no such target" >&2; exit 7; fi\nexit 0',
    );
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "make test",
      timeoutMs: 10_000,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error._tag).toBe("ProviderAdapterError");
    const partial = labVmCommandResultSchema.parse(
      (run.error.partialObservation as Evidence).normalized_result,
    );
    expect(partial).toMatchObject({ exit_type: "exited", exit_code: 7 });
  });

  it("reports a timeout as a partial observation that keeps the deadline", async () => {
    const created = await harness(
      'if [ "$1" = "shell" ]; then exec sleep 5; fi\nexit 0',
    );
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "fuzz-loop",
      timeoutMs: 100,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error._tag).toBe("AnalysisTimeoutError");
    const partial = labVmCommandResultSchema.parse(
      (run.error.partialObservation as Evidence).normalized_result,
    );
    expect(partial).toMatchObject({ exit_type: "timeout", timeout_ms: 100 });
  }, 20_000);

  it("keeps the caller's cancellation identity and the observed facts", async () => {
    const created = await harness(
      'if [ "$1" = "shell" ]; then exec sleep 5; fi\nexit 0',
    );
    const sessionId = await startSession(created);
    const controller = new AbortController();
    const pending = created.manager.run(
      { sessionId, command: "long-build", timeoutMs: 10_000 },
      { signal: controller.signal },
    );
    await waitForArguments(created.logPath, "shell");
    controller.abort(new Error("analyst stopped the build"));
    const run = await pending;
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error._tag).toBe("AnalysisCancelledError");
    expect((run.error.cause as Error).message).toBe(
      "analyst stopped the build",
    );
    const partial = labVmCommandResultSchema.parse(
      (run.error.partialObservation as Evidence).normalized_result,
    );
    expect(partial).toMatchObject({ exit_type: "cancelled" });
  }, 20_000);
});

describe("run_lab_vm_command admission and limits", () => {
  it("stops a command that exceeds the retained-output budget", async () => {
    const created = await harness(
      'if [ "$1" = "shell" ]; then head -c 5000000 /dev/zero | tr \'\\0\' x; fi\nexit 0',
    );
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "verbose-build",
      timeoutMs: 10_000,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error).toBeInstanceOf(AnalysisResourceConstraintError);
    if (!(run.error instanceof AnalysisResourceConstraintError)) return;
    expect(run.error.reportedLimits).toMatchObject({
      max_output_bytes: 4 * 1024 * 1024,
    });
    const partial = labVmCommandResultSchema.parse(
      (run.error.partialObservation as Evidence).normalized_result,
    );
    expect(partial).toMatchObject({
      exit_type: "output_truncated",
      output_truncated: true,
    });
    expect(run.error.userMessage ?? run.error.message).toContain(
      "retained budget",
    );
  }, 20_000);

  it("reports a launch that never produced a process as not_started", async () => {
    const created = await harness("exit 0");
    const sessionId = await startSession(created);
    // The file stays an executable regular file, so admission passes; its
    // interpreter does not exist, so the spawn itself fails.
    await writeFile(
      join(created.root, "limactl"),
      "#!/nonexistent/rea-interpreter\nexit 0\n",
      { mode: 0o700 },
    );
    const run = await created.manager.run({
      sessionId,
      command: "uname -a",
      timeoutMs: 5_000,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error._tag).toBe("AnalysisCapabilityUnavailableError");
    expect(run.error.diagnostics).toMatchObject({
      boundary: "provider-launch",
      system_code: "ENOENT",
    });
    const partial = labVmCommandResultSchema.parse(
      (run.error.partialObservation as Evidence).normalized_result,
    );
    expect(partial).toMatchObject({
      exit_type: "not_started",
      exit_code: null,
      stdout_bytes: 0,
      stderr_bytes: 0,
    });
  });

  it("refuses a command line longer than one argv element", async () => {
    const created = await harness("exit 0");
    const sessionId = await startSession(created);
    const run = await created.manager.run({
      sessionId,
      command: "a".repeat(LAB_VM_MAX_COMMAND_BYTES + 1),
      timeoutMs: 1_000,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error).toBeInstanceOf(AnalysisInputError);
    if (!(run.error instanceof AnalysisInputError)) return;
    expect(run.error.issues).toEqual([
      expect.objectContaining({ path: ["command"], reason: "out_of_range" }),
    ]);
    expect(await loggedArguments(created.logPath)).not.toContain("shell");
  });

  it("refuses an unknown session identity without running a command", async () => {
    const created = await harness("exit 0");
    await startSession(created);
    const run = await created.manager.run({
      sessionId: "00000000-0000-4000-8000-000000000001",
      command: "true",
      timeoutMs: 1_000,
    });
    expect(run.ok).toBe(false);
    if (run.ok) return;
    expect(run.error._tag).toBe("AnalysisInputError");
    expect(await loggedArguments(created.logPath)).not.toContain("shell");
  });
});

describe("stop_lab_vm", () => {
  it("stops and removes the instance, then releases the session and template", async () => {
    const created = await harness("exit 0");
    const sessionId = await startSession(created);
    const stopped = await created.manager.stop({ sessionId });
    if (!stopped.ok) throw stopped.error;
    expect(
      labVmStopResultSchema.parse(stopped.value.normalized_result),
    ).toMatchObject({
      session_id: sessionId,
      deleted: true,
      stop: { exit_type: "exited", exit_code: 0 },
    });
    const args = await loggedArguments(created.logPath);
    expect(args).toContain("stop");
    expect(args).toContain("delete");
    await expect(stat(created.runtimeRoot)).rejects.toMatchObject({
      code: "ENOENT",
    });
    const second = await created.manager.stop({ sessionId });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.error._tag).toBe("AnalysisInputError");
  });

  it("retains ownership after a failed removal and releases it on retry", async () => {
    const created = await harness((context) =>
      statefulLimactl(
        context,
        'if [ ! -f "$state/allow" ]; then echo "instance busy" >&2; exit 3; fi; : > "$state/gone"',
      ),
    );
    const marker = join(created.root, "state", "allow");
    const sessionId = await startSession(created);
    const stopped = await created.manager.stop({ sessionId });
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error.cleanupIncomplete).toBe(true);
    expect(
      labVmStopResultSchema.parse(
        (stopped.error.partialObservation as Evidence).normalized_result,
      ),
    ).toMatchObject({ deleted: false });
    const blocked = await created.manager.run({
      sessionId,
      command: "true",
      timeoutMs: 1_000,
    });
    expect(blocked.ok).toBe(false);
    if (blocked.ok) return;
    expect(blocked.error.userMessage).toContain("cleanup failed");
    await writeFile(marker, "");
    const retried = await created.manager.stop({ sessionId });
    if (!retried.ok) throw retried.error;
    expect(
      labVmStopResultSchema.parse(retried.value.normalized_result),
    ).toMatchObject({ session_id: sessionId, stop: null, deleted: true });
    const released = await created.manager.stop({ sessionId });
    expect(released.ok).toBe(false);
  });

  it("keeps a cancellation that arrives during final removal, then retries cleanup", async () => {
    const created = await harness(({ root }) =>
      [
        'if [ "$1" = "delete" ]; then',
        `  : > "${join(root, "delete-started")}"`,
        `  while [ ! -f "${join(root, "release-delete")}" ]; do sleep 0.05; done`,
        "fi",
        "exit 0",
      ].join("\n"),
    );
    const sessionId = await startSession(created);
    const controller = new AbortController();
    const stopping = created.manager.stop(
      { sessionId },
      { signal: controller.signal },
    );
    await waitForFile(join(created.root, "delete-started"));
    controller.abort(new Error("analyst closed the session"));
    const stopped = await stopping;
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error._tag).toBe("AnalysisCancelledError");
    expect(stopped.error.cleanupIncomplete).toBe(true);
    expect(
      labVmStopResultSchema.parse(
        (stopped.error.partialObservation as Evidence).normalized_result,
      ),
    ).toMatchObject({ deleted: false, stop: { exit_code: 0 } });
    await writeFile(join(created.root, "release-delete"), "");
    const retried = await created.manager.stop({ sessionId });
    if (!retried.ok) throw retried.error;
    expect(
      labVmStopResultSchema.parse(retried.value.normalized_result),
    ).toMatchObject({ deleted: true });
  }, 20_000);
});

describe("stop_lab_vm retained cleanup", () => {
  it("re-runs only removal steps it has not observed", async () => {
    let closeAttempts = 0;
    let createdRuntimeRoot = "";
    const created = await harness(
      (context) => statefulLimactl(context, ': > "$state/gone"'),
      {
        closeRoot: async () => {
          closeAttempts += 1;
          if (closeAttempts === 1)
            throw new Error("template root is still busy");
          await rm(createdRuntimeRoot, { recursive: true, force: true });
        },
      },
    );
    createdRuntimeRoot = created.runtimeRoot;
    const sessionId = await startSession(created);
    const stopped = await created.manager.stop({ sessionId });
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error.cleanupResources).toContain(
      `lab-vm-template:${created.runtimeRoot}`,
    );
    expect(closeAttempts).toBe(1);
    const retried = await created.manager.stop({ sessionId });
    if (!retried.ok) throw retried.error;
    expect(
      labVmStopResultSchema.parse(retried.value.normalized_result),
    ).toMatchObject({ session_id: sessionId, stop: null, deleted: true });
    expect(closeAttempts).toBe(2);
    // The instance was already removed, so no retry may delete it again.
    expect(
      (await loggedArguments(created.logPath)).filter(
        (argument) => argument === "delete",
      ),
    ).toHaveLength(1);
    await expect(stat(created.runtimeRoot)).rejects.toMatchObject({
      code: "ENOENT",
    });
  });

  it("releases an instance an operator already removed", async () => {
    const created = await harness((context) =>
      statefulLimactl(
        context,
        'if [ -f "$state/gone" ]; then echo "instance not found" >&2; exit 3; fi; echo "instance busy" >&2; exit 3',
      ),
    );
    const sessionId = await startSession(created);
    const stopped = await created.manager.stop({ sessionId });
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(
      stopped.error.cleanupResources.some((resource) =>
        resource.startsWith("lab-vm:rea-lab-"),
      ),
    ).toBe(true);
    // The operator removes the instance by hand; the retry observes absence
    // through limactl list instead of re-running a doomed delete forever.
    await writeFile(join(created.root, "state", "gone"), "");
    const retried = await created.manager.stop({ sessionId });
    if (!retried.ok) throw retried.error;
    expect(
      labVmStopResultSchema.parse(retried.value.normalized_result),
    ).toMatchObject({ session_id: sessionId, stop: null, deleted: true });
    const released = await created.manager.stop({ sessionId });
    expect(released.ok).toBe(false);
  });

  it("serializes concurrent stops of one live session", async () => {
    const created = await harness((context) =>
      statefulLimactl(context, ': > "$state/gone"'),
    );
    const sessionId = await startSession(created);
    const outcomes = await Promise.all([
      created.manager.stop({ sessionId }),
      created.manager.stop({ sessionId }),
    ]);
    expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
    const refused = outcomes.find((outcome) => !outcome.ok);
    expect(refused?.error._tag).toBe("AnalysisInputError");
    const arguments_ = await loggedArguments(created.logPath);
    expect(arguments_.filter((argument) => argument === "stop")).toHaveLength(
      1,
    );
    expect(arguments_.filter((argument) => argument === "delete")).toHaveLength(
      1,
    );
  });

  it("serializes concurrent retries of one retained owner", async () => {
    const created = await harness((context) =>
      statefulLimactl(
        context,
        'if [ ! -f "$state/allow" ]; then echo "instance busy" >&2; exit 3; fi; : > "$state/gone"',
      ),
    );
    const sessionId = await startSession(created);
    const first = await created.manager.stop({ sessionId });
    expect(first.ok).toBe(false);
    await writeFile(join(created.root, "state", "allow"), "");
    const outcomes = await Promise.all([
      created.manager.stop({ sessionId }),
      created.manager.stop({ sessionId }),
    ]);
    expect(outcomes.map((outcome) => outcome.ok)).toEqual([true, true]);
    expect(
      (await loggedArguments(created.logPath)).filter(
        (argument) => argument === "delete",
      ),
    ).toHaveLength(2);
  });

  it("keeps a typed cancellation beside the cleanup that still owns the instance", async () => {
    const created = await harness("exit 0");
    const sessionId = await startSession(created);
    const controller = new AbortController();
    controller.abort(new Error("shutdown signal"));
    const stopped = await created.manager.stop(
      { sessionId },
      { signal: controller.signal },
    );
    expect(stopped.ok).toBe(false);
    if (stopped.ok) return;
    expect(stopped.error._tag).toBe("AnalysisCancelledError");
    expect(stopped.error.cleanupIncomplete).toBe(true);
    expect(
      stopped.error.cleanupResources.some((resource) =>
        resource.startsWith("lab-vm:rea-lab-"),
      ),
    ).toBe(true);
    const released = await created.manager.stop({ sessionId });
    expect(released.ok).toBe(true);
  });
});

describe("server shutdown", () => {
  it("reports a retained owner and refuses a replacement while it is owned", async () => {
    const created = await harness((context) =>
      statefulLimactl(context, "exit 9"),
    );
    await startSession(created);
    const closed = await created.manager.closeAll();
    expect(closed.ok).toBe(false);
    if (closed.ok) return;
    expect(closed.error.cleanupIncomplete).toBe(true);
    expect(
      closed.error.cleanupResources.some((resource) =>
        resource.startsWith("lab-vm:rea-lab-"),
      ),
    ).toBe(true);
    const restarted = await created.manager.start({
      workspacePath: created.workspace,
    });
    expect(restarted.ok).toBe(false);
    if (restarted.ok) return;
    expect(restarted.error._tag).toBe("AnalysisCapabilityUnavailableError");
  });
});
