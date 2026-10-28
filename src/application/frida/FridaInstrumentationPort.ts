import type {
  AnalysisError,
  AnalysisErrorOptions,
} from "../../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../../domain/analysisErrorCore.js";
import type { OptionalProviderLoadFailure } from "../OptionalObservationProviders.js";
import type { JsonValue } from "../../domain/jsonValue.js";
import type { Result } from "../../domain/result.js";
import type {
  FridaRpcExport,
  FridaRpcValueCaptureLimit,
} from "../../domain/fridaRpc.js";

export interface FridaRemoteConnection {
  readonly address: string;
  readonly token?: string;
  readonly certificate?: string;
  readonly origin?: string;
  readonly keepaliveInterval?: number;
}

export interface FridaDeviceSelector {
  readonly deviceId?: string;
  readonly remote?: FridaRemoteConnection;
}

export interface FridaDeviceObservation {
  readonly deviceId: string;
  readonly name: string;
  readonly type: string;
}

export interface FridaProcessObservation {
  readonly pid: number;
  readonly name: string;
  readonly identifier: string | null;
}

export type StartFridaSessionInput = FridaDeviceSelector &
  (
    | { readonly mode: "attach"; readonly pid: number }
    | {
        readonly mode: "spawn";
        readonly program: string;
        readonly argv?: readonly string[];
      }
  );

export type FridaScriptSource =
  | { readonly sourceKind: "inline"; readonly source: string }
  | { readonly sourceKind: "file"; readonly path: string };

export interface FridaSessionObservation {
  readonly sessionId: string;
  readonly deviceId: string;
  readonly target: string;
  readonly pid: number;
  readonly mode: "attach" | "spawn";
  readonly state: "paused" | "running" | "detached";
}

export interface FridaScriptObservation {
  readonly scriptId: string;
  readonly sourceKind: "inline" | "file";
  readonly sourcePath: string | null;
  /** Digest of selected file bytes, or the inline source encoded as UTF-8. */
  readonly sourceSha256: string;
  readonly sourceRepresentation?: {
    readonly encoding: "utf8";
    readonly decoding: "replacement";
    readonly loadedSourceSha256: string;
  };
  readonly messages: readonly JsonValue[];
  readonly messagesTruncated: boolean;
}

export class FridaScriptLoadCancelledError extends AnalysisCancelledError {
  readonly scriptHandleAcquired: boolean;

  constructor(
    readonly script: FridaScriptObservation,
    options?: AnalysisErrorOptions & {
      readonly scriptHandleAcquired?: boolean;
    },
  ) {
    super("load_frida_script", options);
    this.scriptHandleAcquired = options?.scriptHandleAcquired ?? true;
  }
}

export interface FridaSessionStatus extends FridaSessionObservation {
  /** True only after REA has successfully resumed this spawned target. */
  readonly targetResumeObserved: boolean;
  readonly scripts: readonly {
    readonly scriptId: string;
    readonly name: string;
  }[];
  readonly messages: readonly JsonValue[];
  readonly messagesTruncated: boolean;
}

export interface FridaSessionCleanupObservation {
  readonly targetResumeObserved: boolean;
}

/** One caller-selected remote-export call on a loaded script. */
export interface FridaRpcCallRequest {
  readonly method: string;
  readonly arguments: readonly JsonValue[];
  readonly timeoutMs: number;
}

/** The bounded reply REA observed for one remote-export call. */
export interface FridaRpcCallObservation {
  readonly sessionId: string;
  readonly scriptId: string;
  readonly method: string;
  /** The session's start mode; an RPC call never widens it. */
  readonly mode: "attach" | "spawn";
  readonly value: JsonValue;
  readonly valueTruncated: boolean;
  readonly valueCaptureLimit: FridaRpcValueCaptureLimit | null;
  readonly durationMs: number;
}

export type { FridaRpcExport };

/** The remote-export surface REA recorded for one live script. */
export interface FridaRpcInventory {
  readonly state: "observed" | "unreported";
  readonly exports: readonly FridaRpcExport[];
  readonly exportsTruncated: boolean;
}

/** Shared application boundary for Frida runtime instrumentation workflows. */
export interface FridaInstrumentationPort {
  availabilityFailure?(): OptionalProviderLoadFailure | undefined;
  listDevices(remote?: FridaRemoteConnection): Promise<
    Result<
      {
        readonly devices: readonly FridaDeviceObservation[];
        readonly cleanupError: string | null;
      },
      AnalysisError
    >
  >;
  listProcesses(selector: FridaDeviceSelector): Promise<
    Result<
      {
        readonly deviceId: string;
        readonly processes: readonly FridaProcessObservation[];
        readonly cleanupError: string | null;
      },
      AnalysisError
    >
  >;
  startSession(
    input: StartFridaSessionInput,
  ): Promise<Result<FridaSessionObservation, AnalysisError>>;
  /** Own cancellation and new-script cleanup before returning a final load outcome. */
  loadScript(
    sessionId: string,
    source: FridaScriptSource,
    signal?: AbortSignal,
  ): Promise<Result<FridaScriptObservation, AnalysisError>>;
  resumeSession(
    sessionId: string,
    signal?: AbortSignal,
  ): Promise<Result<null, AnalysisError>>;
  unloadScript(
    sessionId: string,
    scriptId: string,
    signal?: AbortSignal,
  ): Promise<Result<null, AnalysisError>>;
  /**
   * Read the remote-export inventory this session's owner recorded for one
   * live script. A released script is not owned, even by its known ID.
   */
  rpcInventory(
    sessionId: string,
    scriptId: string,
  ): Result<FridaRpcInventory, AnalysisError>;
  /** Invoke one reported remote export under the session's start-mode grant. */
  callRpc(
    sessionId: string,
    scriptId: string,
    request: FridaRpcCallRequest,
    signal?: AbortSignal,
  ): Promise<Result<FridaRpcCallObservation, AnalysisError>>;
  status(sessionId: string): FridaSessionStatus | undefined;
  closeSession(
    sessionId: string,
  ): Promise<Result<FridaSessionCleanupObservation, AnalysisError>>;
  closeAll(): Promise<void>;
}
