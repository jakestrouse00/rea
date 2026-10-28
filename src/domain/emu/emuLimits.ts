/** Provider identity of the local Unicorn/Keystone bridge. */
export const EMU_PROVIDER_ID = "unicorn";
export const EMU_PROVIDER_NAME = "Unicorn emulator";

/** Directory holding the REA-owned sidecar script. */
export const EMU_BRIDGE_DIR_ENV = "REA_UNICORN_BRIDGE_DIR";
export const EMU_BRIDGE_FILE_NAME = "unicorn_bridge.py";
/** Interpreter of the caller-managed environment that carries Unicorn. */
export const EMU_PYTHON_ENV = "REA_UNICORN_PYTHON";

/** Unicorn minor release this bridge is written and pinned against. */
export const EMU_REQUIRED_UNICORN_VERSION = "2.1";

export const EMU_BRIDGE_DIR_REMEDIATION = `Set ${EMU_BRIDGE_DIR_ENV} to the absolute path of the directory holding ${EMU_BRIDGE_FILE_NAME} and restart REA. The bridge is REA-owned source; REA never downloads it and never installs Unicorn or Keystone. See docs/emulation.md.`;
export const EMU_PYTHON_ENV_REMEDIATION = `Set ${EMU_PYTHON_ENV} to the absolute path of the Python interpreter in the environment where Unicorn ${EMU_REQUIRED_UNICORN_VERSION}.x and Keystone are installed, then restart REA. REA never creates that environment or upgrades it. See docs/emulation.md.`;

/** Wire protocol spoken by the sidecar on stdin and stdout. */
export const EMU_PROTOCOL_VERSION = 1;

/** Closed architecture modes the bridge maps to Unicorn and Keystone modes. */
export const EMU_ARCHITECTURES = [
  "x86_16",
  "x86_32",
  "x86_64",
  "arm",
  "thumb",
  "arm64",
  "mips32",
  "mips64",
  "ppc32",
] as const;

export type EmuArchitecture = (typeof EMU_ARCHITECTURES)[number];

/** Architecture modes that have a big-endian mapping in Unicorn 2.1. */
export const EMU_BIG_ENDIAN_ARCHITECTURES: ReadonlySet<EmuArchitecture> =
  new Set(["arm", "mips32", "mips64", "ppc32"]);

/** Bounds for one one-shot emulation or assembly job. */
export const EMU_LIMITS = {
  defaultSteps: 100_000,
  maxSteps: 5_000_000,
  defaultTimeoutMs: 10_000,
  maxTimeoutMs: 30_000,
  /** Bytes of caller-selected code admitted from a file slice or hex literal. */
  maxCodeBytes: 262_144,
  defaultCodeBase: "0x100000",
  defaultStackSize: 65_536,
  maxStackSize: 1_048_576,
  /** Registers, addresses, and memory windows one request may name. */
  maxArguments: 8,
  maxRegisters: 32,
  maxMemoryObservations: 32,
  maxMemoryObservationBytes: 65_536,
  maxStopAddresses: 8,
  /** Executed path coverage retained per job. */
  maxEdges: 4_096,
  maxCallTargets: 32,
  /** One JSON line in either direction. */
  maxBridgeLineBytes: 1_048_576,
  /** Bytes Keystone may encode for one assembly request. */
  maxAssembledBytes: 65_536,
  maxAssemblyTextBytes: 4_096,
  /** Grace beyond the caller's deadline before the owned child is stopped. */
  stopGraceMs: 2_000,
} as const;

/** Value-free excerpt retained when the bridge emits text REA cannot parse. */
export const EMU_DIAGNOSTIC_EXCERPT_BYTES = 512;
