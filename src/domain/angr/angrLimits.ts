/** Provider identity of the local angr symbolic-execution bridge. */
export const ANGR_PROVIDER_ID = "angr";
export const ANGR_PROVIDER_NAME = "angr symbolic engine";

/** Directory holding the REA-owned sidecar script. */
export const ANGR_BRIDGE_DIR_ENV = "REA_ANGR_BRIDGE_DIR";
export const ANGR_BRIDGE_FILE_NAME = "angr_bridge.py";
/** Interpreter of the caller-managed environment that carries angr. */
export const ANGR_PYTHON_ENV = "REA_ANGR_PYTHON";
/** Most bridge jobs REA admits at once for this lane. */
export const ANGR_JOBS_ENV = "REA_ANGR_JOBS";
/** Deadline of one bridge job, applied when a request names none. */
export const ANGR_OPERATION_TIMEOUT_ENV = "REA_ANGR_OPERATION_TIMEOUT_MS";
export const ANGR_OPERATION_TIMEOUT_SETTING = "angr.operation_timeout_ms";

/** angr minor release this bridge is written and pinned against. */
export const ANGR_REQUIRED_MINOR = "9.2";

export const ANGR_BRIDGE_DIR_REMEDIATION = `Set ${ANGR_BRIDGE_DIR_ENV} to the absolute path of the directory holding ${ANGR_BRIDGE_FILE_NAME} and restart REA. The bridge is REA-owned source; REA never downloads it and never installs angr or its dependencies. See docs/angr-symbolic-execution.md.`;
export const ANGR_PYTHON_ENV_REMEDIATION = `Set ${ANGR_PYTHON_ENV} to the absolute path of the Python interpreter in the environment where angr ${ANGR_REQUIRED_MINOR}.x is installed, then restart REA. REA never creates that environment or upgrades it. See docs/angr-symbolic-execution.md.`;

/** Default deadline of one bridge job when neither the request nor a setting names one. */
export const DEFAULT_ANGR_OPERATION_TIMEOUT_MS = 120_000;

/** Wire protocol spoken by the sidecar on stdin and stdout. */
export const ANGR_PROTOCOL_VERSION = 1;

/** Bounds for one symbolic-execution or CFG-recovery job. */
export const ANGR_LIMITS = {
  defaultTimeoutMs: DEFAULT_ANGR_OPERATION_TIMEOUT_MS,
  maxTimeoutMs: 600_000,
  defaultSteps: 200_000,
  maxSteps: 2_000_000,
  defaultMaxStates: 64,
  maxStates: 256,
  defaultMaxPaths: 1,
  maxPaths: 8,
  /** Caller-supplied assertions one request may carry. */
  maxAssertions: 16,
  maxFindAddresses: 4,
  maxAvoidAddresses: 8,
  /** Bytes of caller-declared stdin window an assertion may reference. */
  maxStdinBytes: 4_096,
  /** Structural facts retained per job. */
  maxConditions: 64,
  maxConditionNodes: 512,
  maxModelValues: 32,
  maxVisitedBlocks: 2_048,
  maxFunctions: 4_096,
  maxBlocks: 16_384,
  maxSuccessors: 16,
  /** Concurrent bridge jobs admitted for this lane. */
  defaultJobs: 1,
  maxJobs: 8,
  /** One JSON line in either direction. */
  maxBridgeLineBytes: 1_048_576,
  /** Grace beyond the caller's deadline before the owned child is stopped. */
  stopGraceMs: 2_000,
} as const;

/** Value-free excerpt retained when the bridge emits text REA cannot parse. */
export const ANGR_DIAGNOSTIC_EXCERPT_BYTES = 512;
