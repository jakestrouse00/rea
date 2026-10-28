/** Provider identity of the local protocol learning loop. */
export const PROTOLEARN_PROVIDER_ID = "protolearn";
export const PROTOLEARN_PROVIDER_NAME = "Protocol learning loop";

/** Directory holding the REA-owned probe runner script. */
export const PROTOLEARN_BRIDGE_DIR_ENV = "REA_PROTOLEARN_BRIDGE_DIR";
export const PROTOLEARN_BRIDGE_FILE_NAME = "probe_runner.py";
/** Interpreter of the caller-managed environment that runs the probe runner. */
export const PROTOLEARN_PYTHON_ENV = "REA_PROTOLEARN_PYTHON";
/** Operator allowlist of lab endpoints the probe lane may reach. */
export const PROTOLEARN_LAB_ENDPOINTS_ENV = "REA_PROTOLEARN_LAB_ENDPOINTS";
/** Deadline of one probe connection, applied when a request names none. */
export const PROTOLEARN_PROBE_TIMEOUT_ENV = "REA_PROTOLEARN_PROBE_TIMEOUT_MS";
export const PROTOLEARN_PROBE_TIMEOUT_SETTING = "protolearn.probe_timeout_ms";

/** Wire protocol spoken by the probe runner on stdin and stdout. */
export const PROTOLEARN_PROTOCOL_VERSION = 1;

/** Default deadline of one probe connection when neither the request nor a setting names one. */
export const DEFAULT_PROTOLEARN_PROBE_TIMEOUT_MS = 10_000;

export const PROTOLEARN_BRIDGE_DIR_REMEDIATION = `Set ${PROTOLEARN_BRIDGE_DIR_ENV} to the absolute path of the directory holding ${PROTOLEARN_BRIDGE_FILE_NAME} and restart REA. The runner is REA-owned source; REA never downloads it and never installs a Python environment. See docs/protocol-learning.md.`;
export const PROTOLEARN_PYTHON_ENV_REMEDIATION = `Set ${PROTOLEARN_PYTHON_ENV} to the absolute path of a Python 3 interpreter that only needs its standard library, then restart REA. REA never creates that environment or upgrades it. See docs/protocol-learning.md.`;
export const PROTOLEARN_LAB_ENDPOINTS_REMEDIATION = `Set ${PROTOLEARN_LAB_ENDPOINTS_ENV} to a JSON array of exact lab socket literals (for example ["127.0.0.1:9000"]) in the REA launch environment, restart REA, then declare the same endpoint in probe_learned_model. REA never probes an endpoint the operator has not allowlisted.`;

/** Bounds for one learning, probing, or grammar-export request. */
export const PROTOLEARN_LIMITS = {
  /** Messages retained for one learned model. */
  maxMessages: 20_000,
  /** Conversations retained for one learned model. */
  maxSessions: 512,
  /** Payload bytes examined per message before only a digest survives. */
  maxPayloadBytes: 4_096,
  /** Payload bytes retained as one class template. */
  maxTemplateBytes: 4_096,
  /** Distinct message classes one model may hold. */
  maxClasses: 64,
  /** States one model may hold. */
  maxStates: 96,
  defaultMaxStates: 24,
  /** Message classes remembered as a state's suffix context. */
  maxSuffixLength: 4,
  defaultSuffixLength: 2,
  /** Field positions a class sketch retains; later positions count only. */
  maxFieldPositions: 16,
  /** Segment types one message sketch retains. */
  maxSegmentTypes: 8,
  /** Segment types one class key keeps apart; later positions count only. */
  maxClassSegments: 4,
  /** Distinct sessions tracked per transition. */
  maxTransitionSessionIds: 512,
  /** Probe connections per request (labels). */
  maxProbeLabels: 8,
  /** Steps per probe connection. */
  maxProbeSteps: 32,
  /** Bytes sent per probe step. */
  maxProbeSendBytes: 4_096,
  /** Response bytes retained per probe step. */
  maxProbeResponseBytes: 16_384,
  /** Response bytes retained per probe connection. */
  maxProbeConnectionBytes: 262_144,
  /** Bytes of one probe request frame. */
  maxProbeRequestBytes: 1_048_576,
  defaultProbeRepeats: 2,
  maxProbeRepeats: 3,
  defaultProbeTimeoutMs: DEFAULT_PROTOLEARN_PROBE_TIMEOUT_MS,
  maxProbeTimeoutMs: 120_000,
  /** Seeds one grammar export may write. */
  maxSeeds: 64,
  /** Bytes one exported seed may hold. */
  maxSeedBytes: 65_536,
  /** One JSON line in either direction between REA and the probe runner. */
  maxBridgeLineBytes: 1_048_576,
  /** Grace beyond the caller's deadline before the owned child is stopped. */
  stopGraceMs: 2_000,
} as const;

/** Value-free excerpt retained when the probe runner emits text REA cannot parse. */
export const PROTOLEARN_DIAGNOSTIC_EXCERPT_BYTES = 512;

/** The qlog profile the owned capture decoder accepts, named in model provenance. */
export const PROTOLEARN_QLOG_PROFILE = "aioquic-1.5.0-json-0.3";
