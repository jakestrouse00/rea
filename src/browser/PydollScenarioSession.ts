import { access, chmod, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

import type { AnalysisCleanupResourceOwner } from "../domain/analysisErrorBase.js";
import {
  AnalysisCleanupLease,
  AnalysisCleanupLeaseGroup,
} from "../artifacts/AnalysisCleanupLease.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { cleanupOwnedProcessGroup } from "../process/ProcessOwnership.js";
import { AnalysisCapabilityUnavailableError } from "../domain/analysisErrorCore.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import { AnalysisError } from "../domain/analysisErrorBase.js";
import type { SanitizedBrowserUrl } from "../domain/browserObservation.js";
import type { BrowserScenario } from "../domain/browserScenario.js";
import type { BrowserScenarioAction } from "../domain/browserScenarioValues.js";
import type {
  BrowserScenarioEvent,
  BrowserScenarioEventOmissions,
  BrowserStepArtifacts,
} from "../domain/browserScenarioCaptureValues.js";
import type { BrowserScenarioSessionPort } from "./BrowserScenarioSessionPort.js";
import { BrowserScenarioSecrets } from "./BrowserScenarioSecrets.js";
import { PydollScenarioEvents } from "./PydollScenarioEvents.js";
import { capturePydollStepArtifacts } from "./PydollScenarioArtifacts.js";
import {
  PydollBridgeProcess,
  PydollBridgeProtocolError,
} from "./PydollBridgeProcess.js";
import {
  bridgeCaptureResultSchema,
  pydollOpenSessionResultSchema,
  pydollPerformResultSchema,
  pydollSeedStorageResultSchema,
  pydollCloseSessionResultSchema,
  type PydollBridgeAdvertising,
  type PydollCaptureResult,
  type PydollOpenSessionResult,
} from "./pydollBridgeProtocol.js";
import {
  withPlaywrightExecutionBoundary,
  PLAYWRIGHT_CLEANUP_CONFIRMATION_TIMEOUT_MS,
} from "./PlaywrightExecutionBoundary.js";
import {
  acquireAttachedScenario,
  allowedBrowserEnvironment,
  failBrowserScenarioOperation,
} from "./PlaywrightScenarioBrowser.js";
import { PYDOLL_BROWSER_SCENARIO_PROVIDER_IDENTITY } from "./providerIdentities.js";

const OPERATION = "capture_browser_scenario" as const;

export const PYDOLL_INTERPRETER_ENV = "REA_PYDOLL_COMMAND" as const;
export const PYDOLL_SCRIPT_ENV = "REA_PYDOLL_SCRIPT" as const;
/** Optional child-verbosity knob documented by the bridge script itself. */
export const PYDOLL_LOG_ENV = "REA_PYDOLL_BRIDGE_LOG" as const;
const DEFAULT_PYDOLL_INTERPRETER = "python3";
const PYDOLL_PROVIDER_ID = PYDOLL_BROWSER_SCENARIO_PROVIDER_IDENTITY.id;
const OPEN_SESSION_DEADLINE_MS = 120_000;
const CAPTURE_DEADLINE_MS = 120_000;
const DEFAULT_ACTION_DEADLINE_MS = 600_000;
const PROBE_EXIT_WAIT_MS = 10_000;
const BRIDGE_EXIT_WAIT_MS = 5_000;
const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
// Strictly dominates the bridge child's close-session budget (75s, including
// its internal browser.stop grace of 45s) so the child is never cut off first.
const PYDOLL_CLOSE_SESSION_DEADLINE_MS = 80_000;

const PYDOLL_REQUIREMENT =
  "Browser scenario driving with pydoll requires REA_PYDOLL_COMMAND to name an absolute Python interpreter with pydoll-python installed.";
const PYDOLL_ACTION_BOUND_NOTE =
  "The pydoll bridge bounds each action and capture with fixed deadlines; actions without caller timeouts are bounded rather than unbounded.";

const throwIfScenarioCancelled = (signal: AbortSignal | undefined): void => {
  if (signal?.aborted === true)
    throw new BrowserObservationError(OPERATION, "cancelled", {
      cause: signal?.reason,
    });
};

/**
 * Child environment additions; the browser environment allowlist stays separate
 * and the forwarded knob set stays this small.
 */
const bridgeExtraEnvironment = (
  environment: Readonly<Record<string, string | undefined>>,
): Record<string, string> => {
  const log = environment[PYDOLL_LOG_ENV];
  return log === undefined
    ? { PYTHONUNBUFFERED: "1" }
    : { PYTHONUNBUFFERED: "1", [PYDOLL_LOG_ENV]: log };
};

/** Absolute interpreter argv when configured; stdlib python3 otherwise. */
export const resolveBridgeCommand = (
  environment: Readonly<Record<string, string | undefined>>,
): { readonly command: string; readonly arguments: readonly string[] } => {
  const configured = environment[PYDOLL_INTERPRETER_ENV];
  if (configured === undefined)
    return { command: DEFAULT_PYDOLL_INTERPRETER, arguments: [] };
  const parts = configured.split(" ").filter((part) => part !== "");
  if (parts.length === 0 || !isAbsolute(parts[0]!))
    throw new AnalysisCapabilityUnavailableError(
      PYDOLL_PROVIDER_ID,
      OPERATION,
      PYDOLL_REQUIREMENT,
      { userMessage: PYDOLL_REQUIREMENT },
    );
  return { command: parts[0]!, arguments: parts.slice(1) };
};

const defaultPydollScriptPath = (): string =>
  fileURLToPath(
    new URL("../../bridge/pydoll/scenario_runner.py", import.meta.url),
  );

export const pydollScriptPath = (
  environment: Readonly<Record<string, string | undefined>>,
): string => environment[PYDOLL_SCRIPT_ENV] ?? defaultPydollScriptPath();

interface BridgeCommandVerification {
  readonly command: string;
  readonly arguments: readonly string[];
  readonly scriptPath: string;
}

/** Verify the interpreter exists and the bridge script answers its probe. */
const verifyBridgeCommand = async (
  environment: Readonly<Record<string, string | undefined>>,
  signal: AbortSignal | undefined,
): Promise<BridgeCommandVerification> => {
  const resolved = resolveBridgeCommand(environment);
  const scriptPath = pydollScriptPath(environment);
  try {
    await access(resolved.command, fsConstants.R_OK | fsConstants.X_OK);
    if (!(await stat(resolved.command)).isFile())
      throw new TypeError("Configured path is not a regular file");
    await access(scriptPath, fsConstants.R_OK);
  } catch (cause: unknown) {
    throw new AnalysisCapabilityUnavailableError(
      PYDOLL_PROVIDER_ID,
      OPERATION,
      "The configured pydoll interpreter or bridge script is unavailable.",
      {
        cause,
        userMessage: `${PYDOLL_REQUIREMENT} The bridge script ships at bridge/pydoll/scenario_runner.py.`,
      },
    );
  }
  let probe: PydollBridgeProcess | undefined;
  try {
    probe = await PydollBridgeProcess.start({
      command: resolved.command,
      arguments: resolved.arguments,
      scriptPath,
      runId: randomUUID(),
      hostEnvironment: allowedBrowserEnvironment(environment),
      extraEnvironment: bridgeExtraEnvironment(environment),
      check: true,
      ...(signal === undefined ? {} : { signal }),
    });
    const exited = await probe.waitForExit(PROBE_EXIT_WAIT_MS);
    if (!exited)
      throw new PydollBridgeProtocolError(
        "The pydoll bridge probe did not exit after advertising.",
      );
  } catch (probeFailure: unknown) {
    await probe?.terminate().catch(() => undefined);
    throw new AnalysisCapabilityUnavailableError(
      PYDOLL_PROVIDER_ID,
      OPERATION,
      `The pydoll bridge probe failed: ${
        probeFailure instanceof Error
          ? probeFailure.message
          : String(probeFailure)
      }`,
      { userMessage: PYDOLL_REQUIREMENT, cause: probeFailure },
    );
  }
  try {
    const exit = probe.snapshotExit();
    if (exit === undefined || exit.code !== 0)
      throw new AnalysisCapabilityUnavailableError(
        PYDOLL_PROVIDER_ID,
        OPERATION,
        `pydoll-python is not importable in the configured interpreter (probe exit ${exit?.code ?? "unknown"}). ${probe.stderrText}`,
        {
          userMessage: PYDOLL_REQUIREMENT,
          remediationAction: `Install pydoll-python into the interpreter named by ${PYDOLL_INTERPRETER_ENV}.`,
        },
      );
    if (probe.advertising === undefined)
      throw new AnalysisCapabilityUnavailableError(
        PYDOLL_PROVIDER_ID,
        OPERATION,
        "The pydoll bridge probe did not advertise its protocol.",
        { userMessage: PYDOLL_REQUIREMENT },
      );
  } finally {
    await probe.terminate().catch(() => undefined);
  }
  return { ...resolved, scriptPath };
};

const serializeAction = (
  action: BrowserScenarioAction,
  secrets: BrowserScenarioSecrets,
): Record<string, unknown> => {
  const timeout =
    action.action === "wait_for_timeout" || action.timeout_ms === undefined
      ? {}
      : { timeout_ms: action.timeout_ms };
  switch (action.action) {
    case "goto":
      return {
        action: "goto",
        step_id: action.step_id,
        ...timeout,
        destination: { url: secrets.url(action.destination), query: [] },
        wait_until: action.wait_until,
      };
    case "click":
      return {
        ...baseAction(action, timeout),
        locator: action.locator,
        button: action.button,
        click_count: action.click_count,
      };
    case "fill":
    case "select_option":
      return {
        ...baseAction(action, timeout),
        locator: action.locator,
        value: {
          source: "literal" as const,
          value: secrets.value(action.value),
        },
      };
    case "press":
      return {
        ...baseAction(action, timeout),
        locator: action.locator,
        key: action.key,
      };
    case "check":
    case "uncheck":
      return { ...baseAction(action, timeout), locator: action.locator };
    case "wait_for":
      return {
        ...baseAction(action, timeout),
        locator: action.locator,
        state: action.state,
      };
    case "wait_for_timeout":
      return {
        action: "wait_for_timeout",
        step_id: action.step_id,
        duration_ms: action.duration_ms,
      };
  }
};

const baseAction = (
  action: BrowserScenarioAction,
  timeout: Record<string, unknown>,
): Record<string, unknown> => ({
  action: action.action,
  step_id: action.step_id,
  ...timeout,
});

const serializeStorageSeeds = (
  scenario: BrowserScenario,
  secrets: BrowserScenarioSecrets,
) => ({
  cookies: scenario.storage.cookies.map((cookie) => ({
    name: cookie.name,
    value: secrets.value(cookie.value),
    domain: new URL(secrets.url(cookie.destination)).hostname,
    path: "/",
    secure: cookie.secure,
    http_only: cookie.http_only,
    same_site: cookie.same_site,
  })),
  local_storage: scenario.storage.local_storage.map((collection) => ({
    origin: collection.origin,
    entries: collection.entries.map((entry) => ({
      name: entry.name,
      value: secrets.value(entry.value),
    })),
  })),
  session_storage: scenario.storage.session_storage.map((collection) => ({
    origin: collection.origin,
    entries: collection.entries.map((entry) => ({
      name: entry.name,
      value: secrets.value(entry.value),
    })),
  })),
});

interface PydollCleanupResources {
  closeBridge: () => Promise<
    "terminated-owned-process" | "disconnected-external" | undefined
  >;
  removeProfile: (() => Promise<void>) | undefined;
  removeSessionDir: () => Promise<void>;
  onSettled?: (bridgeClosed: boolean) => void;
}

/** Owns one bridge child, optional private profile, and scratch directory through cleanup retries. */
class PydollScenarioCleanupOwner implements AnalysisCleanupResourceOwner {
  #bridgeClosed = false;
  #closeOutcome:
    | "terminated-owned-process"
    | "disconnected-external"
    | undefined;
  #profileRemoved: boolean;
  #sessionDirRemoved = false;
  #eventsFinalized = false;
  #eventFinalizationPromise: Promise<void> | undefined;
  readonly cleanupLease: AnalysisCleanupLease;

  constructor(private readonly resources: PydollCleanupResources) {
    this.#profileRemoved = resources.removeProfile === undefined;
    this.cleanupLease = new AnalysisCleanupLease(
      () =>
        this.#closeResources().finally(() =>
          this.resources.onSettled?.(this.#bridgeClosed),
        ),
      this,
    );
  }

  get bridgeClosed(): boolean {
    return this.#bridgeClosed;
  }

  /** The child's observed close_session outcome, when it replied. */
  get closeSessionOutcome():
    | "terminated-owned-process"
    | "disconnected-external"
    | undefined {
    return this.#closeOutcome;
  }

  get cleanupResources(): readonly string[] {
    return [
      ...(!this.#eventsFinalized ? ["browser_events"] : []),
      ...(!this.#bridgeClosed ? ["browser_transport"] : []),
      ...(!this.#profileRemoved && this.resources.removeProfile !== undefined
        ? ["browser_profile"]
        : []),
      ...(!this.#sessionDirRemoved ? ["bridge_scratch"] : []),
    ];
  }

  /** Await actual resource release; cleanup lease retries keep ownership. */
  release(finishEvents?: () => void): Promise<void> {
    this.#prepareEvents(finishEvents);
    return this.cleanupLease.release();
  }

  #prepareEvents(finishEvents?: () => void): void {
    this.#eventFinalizationPromise ??= Promise.resolve().then(() => {
      finishEvents?.();
      this.#eventsFinalized = true;
    });
  }

  async #closeResources(): Promise<void> {
    const failures: unknown[] = [];
    this.#prepareEvents();
    try {
      await this.#eventFinalizationPromise;
    } catch (cause: unknown) {
      failures.push(cause);
    }
    if (!this.#bridgeClosed) {
      try {
        const outcome = await this.resources.closeBridge();
        if (outcome !== undefined) this.#closeOutcome = outcome;
        this.#bridgeClosed = true;
      } catch (cause: unknown) {
        failures.push(cause);
      }
    }
    if (
      this.#bridgeClosed &&
      !this.#profileRemoved &&
      this.resources.removeProfile !== undefined
    ) {
      try {
        await this.resources.removeProfile();
        this.#profileRemoved = true;
      } catch (cause: unknown) {
        failures.push(cause);
      }
    }
    if (this.#bridgeClosed && !this.#sessionDirRemoved) {
      try {
        await this.resources.removeSessionDir();
        this.#sessionDirRemoved = true;
      } catch (cause: unknown) {
        failures.push(cause);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1)
      throw new AggregateError(failures, "Browser scenario cleanup failed");
  }
}

interface OpenedPydollScenario {
  readonly bridge: PydollBridgeProcess;
  readonly opened: PydollOpenSessionResult;
  readonly advertising: PydollBridgeAdvertising;
  readonly profilePath: string | undefined;
  readonly sessionDir: string;
  readonly cleanup: PydollScenarioCleanupOwner;
}

interface PydollSessionOptions {
  readonly sessionMode: "launch" | "connect";
  readonly secrets: BrowserScenarioSecrets;
  readonly events: PydollScenarioEvents;
  readonly signal: AbortSignal | undefined;
  readonly capabilityGaps: readonly string[];
  readonly seedNotes: readonly string[];
  readonly stopRequest: {
    readonly get: () => boolean;
    readonly set: (value: boolean) => void;
  };
  readonly currentUrl: string;
}

/** Controlled pydoll-driven browser scenario session over a supervised bridge child. */
export class PydollScenarioSession implements BrowserScenarioSessionPort {
  readonly driver = "pydoll" as const;
  readonly mode: "launch" | "connect";
  readonly processOwnership: "provider-owned" | "external";
  readonly product = "Chromium";
  readonly version: string;
  readonly initialUrl: string;
  readonly cleanupLease: AnalysisCleanupLease;

  readonly #opened: OpenedPydollScenario;
  readonly #secrets: BrowserScenarioSecrets;
  readonly #events: PydollScenarioEvents;
  readonly #signal: AbortSignal | undefined;
  readonly #capabilityGaps: readonly string[];
  readonly #sessionNotes: string[];
  readonly #stopRequest: {
    readonly get: () => boolean;
    readonly set: (value: boolean) => void;
  };
  #currentUrl: string;

  private constructor(
    opened: OpenedPydollScenario,
    options: PydollSessionOptions,
  ) {
    this.mode = options.sessionMode;
    this.processOwnership =
      options.sessionMode === "launch" ? "provider-owned" : "external";
    this.#opened = opened;
    this.#secrets = options.secrets;
    this.#events = options.events;
    this.#signal = options.signal;
    this.#capabilityGaps = options.capabilityGaps;
    this.#sessionNotes = [...options.seedNotes];
    this.#stopRequest = options.stopRequest;
    this.version = opened.opened.version;
    this.initialUrl = opened.opened.initial_url ?? "";
    this.#currentUrl = options.currentUrl;
    this.cleanupLease = new AnalysisCleanupLease(() => this.#closeResources(), {
      get cleanupResources() {
        return opened.cleanup.cleanupResources;
      },
    });
  }

  #noteCurrentUrl(value: string): void {
    if (value === "") return;
    this.#currentUrl = value;
  }

  currentUrl(): string {
    return this.#currentUrl;
  }

  sanitizeUrl(value: string): SanitizedBrowserUrl {
    return this.#secrets.sanitizeUrl(value);
  }

  setStep(index: number): void {
    this.#events.setStep(index);
  }

  nextEventSequence(): number {
    return this.#events.nextSequence();
  }

  lastEventSequence(): number {
    return this.#events.lastSequence();
  }

  events(): {
    readonly retained: number;
    readonly dropped: number;
    readonly items: readonly BrowserScenarioEvent[];
    readonly omissions: BrowserScenarioEventOmissions;
  } {
    return this.#events.result();
  }

  /** Event coverage gaps from the bridge capabilities and this session's choices. */
  eventLimitations(): readonly string[] {
    return [
      ...this.#events.limitations(),
      ...this.#capabilityGaps,
      ...this.#sessionNotes,
    ];
  }

  async perform(
    action: BrowserScenarioAction,
    signal?: AbortSignal,
  ): Promise<void> {
    const deadline = "timeout_ms" in action ? action.timeout_ms : undefined;
    const effectiveSignal = signal ?? this.#signal;
    await withPlaywrightExecutionBoundary(
      async () => {
        const result = pydollPerformResultSchema.parse(
          await this.#opened.bridge.request(
            "perform",
            { action: serializeAction(action, this.#secrets) },
            {
              deadlineMs: deadline ?? DEFAULT_ACTION_DEADLINE_MS,
              ...(effectiveSignal === undefined
                ? {}
                : { signal: effectiveSignal }),
            },
          ),
        );
        for (const note of result.notes) this.#noteSession(note);
        this.#noteCurrentUrl(result.final_url ?? "");
        return undefined;
      },
      deadline ?? DEFAULT_ACTION_DEADLINE_MS,
      effectiveSignal,
    );
  }

  #noteSession(note: string): void {
    if (!this.#sessionNotes.includes(note) && this.#sessionNotes.length < 64)
      this.#sessionNotes.push(note);
  }

  async capture(
    requested: ReadonlySet<
      BrowserScenario["capture"]["after_each_step"][number]
    >,
    signal?: AbortSignal,
  ): Promise<BrowserStepArtifacts> {
    const effectiveSignal = signal ?? this.#signal;
    return withPlaywrightExecutionBoundary(
      async () => {
        const result = bridgeCaptureResultSchema.parse(
          await this.#opened.bridge.request(
            "capture",
            { requested: [...requested] },
            {
              deadlineMs: CAPTURE_DEADLINE_MS,
              ...(effectiveSignal === undefined
                ? {}
                : { signal: effectiveSignal }),
            },
          ),
        ) as PydollCaptureResult;
        for (const note of result.notes) this.#noteSession(note);
        for (const artifact of result.artifacts)
          if (artifact.kind === "url" && artifact.raw_url !== null)
            this.#noteCurrentUrl(artifact.raw_url);
        return capturePydollStepArtifacts({
          result,
          requested,
          secrets: this.#secrets,
          sessionUrl: this.#currentUrl,
          sessionDir: this.#opened.sessionDir,
          maxArtifactBytes: MAX_ARTIFACT_BYTES,
        });
      },
      CAPTURE_DEADLINE_MS,
      effectiveSignal,
    );
  }

  async close(stopLoading = this.#signal?.aborted === true) {
    this.#stopRequest.set(this.#stopRequest.get() || stopLoading);
    try {
      await withPlaywrightExecutionBoundary(
        () => this.cleanupLease.release(),
        PLAYWRIGHT_CLEANUP_CONFIRMATION_TIMEOUT_MS,
      );
    } catch (cause: unknown) {
      const error = new BrowserObservationError(OPERATION, "cleanup_failed", {
        cause,
        cleanup: {
          reason: cause instanceof Error ? cause.message : String(cause),
          resources: this.cleanupLease.cleanupResources ?? [],
        },
      });
      new AnalysisCleanupLeaseGroup(error, [this.cleanupLease]);
      throw error;
    }
    return (
      this.#opened.cleanup.closeSessionOutcome ??
      (this.mode === "launch"
        ? ("terminated-owned-process" as const)
        : ("disconnected-external" as const))
    );
  }

  async #closeResources(): Promise<void> {
    await this.#opened.cleanup.release(() =>
      this.#events.finish(this.#signal?.aborted === true),
    );
  }

  redactError(error: unknown): string {
    return this.#secrets.redact(
      error instanceof Error ? error.message : "browser action failed",
    );
  }

  /** Probe, spawn, open, seed, and navigate to the start URL for one scenario. */
  static async open(
    scenario: BrowserScenario,
    environment: Readonly<Record<string, string | undefined>>,
    options: {
      readonly signal?: AbortSignal;
      readonly retainCleanup?: (lease: AnalysisCleanupLease) => void;
    },
  ): Promise<PydollScenarioSession> {
    throwIfScenarioCancelled(options.signal);
    const secrets = BrowserScenarioSecrets.resolve(scenario, environment);
    if (secrets === undefined)
      throw new BrowserObservationError(OPERATION, "secret_unavailable");
    const verified = await verifyBridgeCommand(environment, options.signal);
    const sessionDir = await mkdtemp(join(tmpdir(), "rea-pydoll-session-"));
    await chmod(sessionDir, 0o700);
    const profilePath =
      scenario.browser.mode === "launch"
        ? await mkdir(join(sessionDir, "profile"), { recursive: true })
        : undefined;
    if (profilePath !== undefined) await chmod(profilePath, 0o700);
    const stopRequest: { get: () => boolean; set: (value: boolean) => void } =
      (() => {
        let requested = false;
        return {
          get: () => requested,
          set: (value: boolean) => {
            requested ||= value;
          },
        };
      })();
    let admissionLease:
      | Awaited<ReturnType<typeof acquireAttachedScenario>>
      | undefined;
    let bridge: PydollBridgeProcess | undefined;
    let cleanup: PydollScenarioCleanupOwner | undefined;
    try {
      if (scenario.browser.mode === "connect")
        admissionLease = await acquireAttachedScenario(
          scenario.browser,
          options.signal,
        );
      const events = new PydollScenarioEvents({
        secrets,
        enabled: new Set(scenario.capture.events),
        network: scenario.capture.network,
        limits: scenario.capture.limits,
      });
      bridge = await PydollBridgeProcess.start({
        command: verified.command,
        arguments: verified.arguments,
        scriptPath: verified.scriptPath,
        runId: randomUUID(),
        hostEnvironment: allowedBrowserEnvironment(environment),
        extraEnvironment: bridgeExtraEnvironment(environment),
        onEvent: (params) => events.ingest(params),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      const opened = pydollOpenSessionResultSchema.parse(
        await bridge.request(
          "open_session",
          {
            mode: scenario.browser.mode,
            session_dir: sessionDir,
            ...(scenario.browser.mode === "launch"
              ? {
                  launch: {
                    executable_path: scenario.browser.executable_path,
                    headless: scenario.browser.headless,
                    user_data_dir: profilePath,
                    window_size: {
                      width: scenario.environment.viewport.width,
                      height: scenario.environment.viewport.height,
                    },
                  },
                }
              : {
                  connect: {
                    cdp_endpoint: scenario.browser.cdp_endpoint,
                    target_id: scenario.browser.target_id,
                  },
                }),
            environment: {
              locale: scenario.environment.locale,
              timezone: scenario.environment.timezone,
              color_scheme: scenario.environment.color_scheme,
              reduced_motion: scenario.environment.reduced_motion,
              viewport: scenario.environment.viewport,
            },
            capture: {
              events: [...scenario.capture.events],
              network: scenario.capture.network,
            },
          },
          {
            deadlineMs: OPEN_SESSION_DEADLINE_MS,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          },
        ),
      );
      const bridgeProcess = bridge;
      cleanup = new PydollScenarioCleanupOwner({
        closeBridge: () =>
          closeBridgeResources(scenario, bridgeProcess, stopRequest.get()),
        removeProfile:
          profilePath === undefined
            ? undefined
            : () =>
                rm(profilePath, {
                  recursive: true,
                  force: true,
                  maxRetries: 3,
                }),
        removeSessionDir: () =>
          rm(sessionDir, { recursive: true, force: true, maxRetries: 3 }),
        onSettled: (bridgeClosed) => {
          if (bridgeClosed) void admissionLease?.release();
        },
      });
      const seedNotes: string[] = [];
      if (
        scenario.storage.cookies.length > 0 ||
        scenario.storage.local_storage.length > 0 ||
        scenario.storage.session_storage.length > 0
      ) {
        const seed = pydollSeedStorageResultSchema.parse(
          await bridge.request(
            "seed_storage",
            serializeStorageSeeds(scenario, secrets),
            {
              deadlineMs: OPEN_SESSION_DEADLINE_MS,
              ...(options.signal === undefined
                ? {}
                : { signal: options.signal }),
            },
          ),
        );
        seedNotes.push(...seed.notes);
      }
      const startNavigation = pydollPerformResultSchema.parse(
        await bridge.request(
          "perform",
          {
            action: serializeAction(
              {
                action: "goto",
                step_id: "scenario_start",
                destination: scenario.start_url,
                wait_until: "load" as const,
              },
              secrets,
            ),
          },
          {
            deadlineMs: DEFAULT_ACTION_DEADLINE_MS,
            ...(options.signal === undefined ? {} : { signal: options.signal }),
          },
        ),
      );
      if (bridge.advertising === undefined)
        throw new BrowserObservationError(OPERATION, "protocol_error");
      const session = new PydollScenarioSession(
        {
          bridge,
          opened,
          advertising: bridge.advertising,
          profilePath,
          sessionDir,
          cleanup,
        },
        {
          sessionMode: scenario.browser.mode,
          secrets,
          events,
          signal: options.signal,
          capabilityGaps: capabilityLimitations(
            scenario,
            bridge.advertising,
            opened,
          ),
          seedNotes,
          stopRequest,
          currentUrl: startNavigation.final_url ?? "",
        },
      );
      return session;
    } catch (cause: unknown) {
      const recovery =
        cleanup?.cleanupLease ??
        new AnalysisCleanupLease(async () => {
          if (bridge !== undefined)
            await bridge.terminate().catch(() => undefined);
          await rm(sessionDir, {
            recursive: true,
            force: true,
            maxRetries: 3,
          }).catch(() => undefined);
          // A failed open acquired no browser resources; release the
          // connect-mode admission so a later scenario against the same
          // endpoint/target is not blocked by a stale lease.
          await admissionLease?.release();
        }, ["browser_transport", "bridge_scratch"]);
      const primary =
        cause instanceof AnalysisError
          ? cause
          : providerAdapterError(PYDOLL_PROVIDER_ID, cause);
      try {
        return await failBrowserScenarioOperation(recovery, primary);
      } catch (failure: unknown) {
        if (failure !== primary) options.retainCleanup?.(recovery);
        throw failure;
      }
    }
  }
}

const providerAdapterError = (
  providerId: string,
  cause: unknown,
): ProviderAdapterError =>
  new ProviderAdapterError(providerId, OPERATION, { cause });

const closeBridgeResources = async (
  scenario: BrowserScenario,
  bridge: PydollBridgeProcess,
  stopLoading: boolean,
): Promise<
  "terminated-owned-process" | "disconnected-external" | undefined
> => {
  let closeOutcome:
    | "terminated-owned-process"
    | "disconnected-external"
    | undefined;
  try {
    // Prefer the child's observed close outcome over a mode-based inference.
    closeOutcome = pydollCloseSessionResultSchema.parse(
      await bridge.request(
        "close_session",
        { stop_loading: stopLoading },
        // The deadline must strictly dominate the bridge child's 75s
        // close-session budget so the child is never abandoned mid-stop.
        { deadlineMs: PYDOLL_CLOSE_SESSION_DEADLINE_MS },
      ),
    ).outcome;
  } catch (closeFailure: unknown) {
    if (scenario.browser.mode === "connect") throw closeFailure;
  }
  if (scenario.browser.mode === "launch") {
    const exited = await bridge
      .waitForExit(BRIDGE_EXIT_WAIT_MS)
      .catch(() => false);
    if (!exited) {
      await bridge.terminate().catch(() => {
        throw new BrowserObservationError(OPERATION, "cleanup_failed", {
          detail:
            "The pydoll bridge interpreter did not stop after escalation.",
          cleanup: {
            reason: "bridge interpreter remained",
            resources: ["browser_transport"],
          },
        });
      });
      const ownership = bridge.ownership;
      if (ownership !== undefined) {
        const cleaned = await cleanupOwnedProcessGroup(ownership);
        if (!cleaned.cleaned)
          throw new BrowserObservationError(OPERATION, "cleanup_failed", {
            detail:
              "The owned browser process group did not stop after escalation.",
            cleanup: {
              reason: cleaned.reason ?? "browser process group remained",
              resources: ["browser_transport"],
            },
          });
      }
    }
  }
  return closeOutcome;
};

const capabilityLimitations = (
  scenario: BrowserScenario,
  advertising: PydollBridgeAdvertising,
  opened: PydollOpenSessionResult,
): readonly string[] => {
  const selected = new Set(scenario.capture.events);
  const gaps = [
    ...(opened.skipped_environment.length > 0
      ? [
          `The pydoll bridge did not apply ${opened.skipped_environment.join(", ")} emulation in this mode.`,
        ]
      : []),
    PYDOLL_ACTION_BOUND_NOTE,
  ];
  for (const [family, supported, gap] of [
    ["workers", advertising.capabilities.workers, "worker lifecycle events"],
    ["popups", advertising.capabilities.popups, "popup lifecycle events"],
    ["downloads", advertising.capabilities.downloads, "download events"],
  ] as const)
    if (!supported && selected.has(family))
      gaps.push(
        `The pydoll bridge does not capture ${gap}; the selected family is unavailable and event coverage is incomplete.`,
      );
  return gaps;
};
