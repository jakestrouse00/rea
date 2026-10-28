/**
 * Deny-default macOS seatbelt (SBPL) profiles for autonomous subprocess
 * launches.
 *
 * Every profile starts from `(deny default)` and admits only the workspace
 * writes, the caller-declared executables, the declared network destinations,
 * and the explicitly named Mach services. Anything else is refused by the
 * kernel, so a compromised or confused child cannot reach files, sockets, or
 * services outside the declared scope.
 */

/** The host utility that evaluates an inline seatbelt profile. */
export const SANDBOX_PROFILE_EXECUTABLE = "/usr/bin/sandbox-exec";

/** Emergency exit; see `sandboxDisableState`. */
export const SANDBOX_DISABLE_ENV = "REA_DISABLE_SANDBOX";

/**
 * Runtime paths a dynamically linked child needs before its own code runs.
 * They are read-only and deliberately narrow: the dynamic loader, the system
 * library cache, and the shared library directories.
 */
const BASELINE_READ_PATHS = [
  "/usr/lib",
  "/System/Library/dyld",
  "/System/Library/Frameworks",
  "/System/Library/PrivateFrameworks",
] as const;

/** One declared outbound destination. Hostnames are not resolved by SBPL. */
export interface SandboxNetworkAllowance {
  /** IPv4 or IPv6 literal; names are rejected because the kernel matches addresses. */
  readonly host: string;
  readonly port: number;
}

/** Everything a deny-default profile admits for one loop. */
export interface SandboxProfileRequest {
  /** The only directory the child may write to (recursively). */
  readonly workspace_root: string;
  /** Additional read-write directories; the workspace is always writable. */
  readonly writable_paths?: readonly string[];
  /** Additional read-only directories. */
  readonly readable_paths?: readonly string[];
  /** Absolute executables the child may spawn, through `process-exec`. */
  readonly executable_paths: readonly string[];
  /** Declared outbound destinations. Omit for no network at all. */
  readonly network_allowlist?: readonly SandboxNetworkAllowance[];
  /** Mach services the child may look up. Omit for no Mach lookups. */
  readonly mach_lookup?: readonly string[];
}

/** Why a profile request could not be represented in SBPL. */
export type SandboxProfileRejectionCode =
  | "not_absolute"
  | "unrepresentable"
  | "invalid_host"
  | "invalid_port"
  | "invalid_disable_value";

/** A profile request that cannot be expressed as a deny-default policy. */
export class SandboxProfileRejection extends Error {
  readonly _tag = "SandboxProfileRejection";
  constructor(
    readonly code: SandboxProfileRejectionCode,
    message: string,
  ) {
    super(message);
    this.name = "SandboxProfileRejection";
  }
}

/** SBPL has no escape for these bytes; a value that needs one is unrepresentable. */
const quote = (value: string, field: string): string => {
  if (value.length === 0)
    throw new SandboxProfileRejection(
      "unrepresentable",
      `${field} is empty; every sandbox path and service name must be nonempty`,
    );
  if (/[\u0000-\u001f\u007f]/u.test(value))
    throw new SandboxProfileRejection(
      "unrepresentable",
      `${field} contains a control character, which a seatbelt string cannot represent: ${JSON.stringify(value)}`,
    );
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
};

const absolutePath = (value: string, field: string): string => {
  if (!value.startsWith("/"))
    throw new SandboxProfileRejection(
      "not_absolute",
      `${field} must be an absolute path so the profile names one kernel object: ${value}`,
    );
  const segments = value.split("/");
  if (segments.includes(".."))
    throw new SandboxProfileRejection(
      "not_absolute",
      `${field} must not contain ".." segments; canonicalize it first: ${value}`,
    );
  const trimmed = value.length > 1 ? value.replace(/\/+$/u, "") : value;
  return quote(trimmed, field);
};

const ipv4 = /^(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})$/u;
const ipv6 = /^[0-9a-f:]+$/iu;

/**
 * Addresses the kernel's profile grammar can name. `sandbox-exec` accepts only
 * `*` or `localhost` as a host in a network address and refuses a numeric
 * literal outright ("host must be * or localhost"), so only a loopback
 * destination is expressible as an exact one.
 */
const expressibleHosts = new Set(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);

const remote = (allowance: SandboxNetworkAllowance, index: number): string => {
  const { host, port } = allowance;
  if (!ipv4.test(host) && !(host.includes(":") && ipv6.test(host)))
    throw new SandboxProfileRejection(
      "invalid_host",
      `network_allowlist[${String(index)}].host must be an IPv4 or IPv6 literal; resolve the name before generating the profile: ${host}`,
    );
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535)
    throw new SandboxProfileRejection(
      "invalid_port",
      `network_allowlist[${String(index)}].port must be an integer from 1 to 65535: ${String(port)}`,
    );
  if (!expressibleHosts.has(host))
    throw new SandboxProfileRejection(
      "unrepresentable",
      `network_allowlist[${String(index)}].host is not a loopback address: the kernel's profile grammar admits only "*" or "localhost" as a named host, so an exact destination elsewhere cannot be expressed (${host}). Reach the lab through a loopback forwarder.`,
    );
  return quote(
    `localhost:${String(port)}`,
    `network_allowlist[${String(index)}]`,
  );
};

const uniqueSorted = (values: readonly string[]): readonly string[] =>
  [...new Set(values)].sort();

const reader = (paths: readonly string[]): string =>
  `(allow file-read* ${paths.map((path) => `(subpath ${path})`).join(" ")})`;

const writer = (paths: readonly string[]): string =>
  `(allow file-write* ${paths.map((path) => `(subpath ${path})`).join(" ")})`;

/**
 * Render the complete deny-default profile for one loop.
 *
 * `mach_lookup` is empty by default: a child that needs a Mach service must
 * declare it by name, so a service lookup cannot silently widen the scope.
 */
export const sandboxProfileSource = (
  request: SandboxProfileRequest,
): string => {
  const readable = uniqueSorted([
    ...BASELINE_READ_PATHS,
    ...(request.readable_paths ?? []),
  ]).map((path, index) =>
    absolutePath(path, `readable_paths[${String(index)}]`),
  );
  const writable = uniqueSorted([
    request.workspace_root,
    ...(request.writable_paths ?? []),
  ]).map((path, index) =>
    absolutePath(path, `writable_paths[${String(index)}]`),
  );
  const executable = request.executable_paths.map((path, index) =>
    absolutePath(path, `executable_paths[${String(index)}]`),
  );
  if (executable.length === 0)
    throw new SandboxProfileRejection(
      "unrepresentable",
      "executable_paths must name the executables this loop spawns; an empty allowlist cannot start the loop",
    );
  const remotes = (request.network_allowlist ?? []).map(remote);
  const services = (request.mach_lookup ?? []).map((name, index) =>
    quote(name, `mach_lookup[${String(index)}]`),
  );
  const lines = [
    "(version 1)",
    "(deny default)",
    "(allow process-fork)",
    "(allow signal (target self))",
    "(allow sysctl-read)",
    reader(readable),
    writer(writable),
    `(allow process-exec ${executable.map((path) => `(literal ${path})`).join(" ")})`,
    ...(remotes.length === 0
      ? ["(deny network-outbound)"]
      : [
          `(allow network-outbound ${remotes
            .map((value) => `(remote ip ${value})`)
            .join(" ")})`,
        ]),
    ...(services.length === 0
      ? ["(deny mach-lookup)"]
      : [
          `(allow mach-lookup ${services.map((name) => `(global-name ${name})`).join(" ")})`,
        ]),
  ];
  return `${lines.join("\n")}\n`;
};

/** Observed state of the emergency sandbox exit. */
export type SandboxDisableState =
  | { readonly kind: "enabled" }
  | { readonly kind: "disabled"; readonly limitation: string }
  | { readonly kind: "invalid"; readonly reason: string };

const DISABLING_VALUES = new Set(["1", "true", "yes", "on"]);
const ENABLING_VALUES = new Set(["", "0", "false", "no", "off"]);

/**
 * Read `REA_DISABLE_SANDBOX` without guessing.
 *
 * A disabling value produces the limitation the caller must attach to
 * Evidence, so an unconfined launch is never reported as confined. An
 * unrecognized value refuses the launch instead of being read either way.
 */
export const sandboxDisableState = (
  environment: Readonly<Record<string, string | undefined>>,
): SandboxDisableState => {
  const raw = environment[SANDBOX_DISABLE_ENV];
  if (raw === undefined) return { kind: "enabled" };
  const value = raw.trim().toLowerCase();
  if (DISABLING_VALUES.has(value))
    return {
      kind: "disabled",
      limitation: `${SANDBOX_DISABLE_ENV}=${raw} disabled the deny-default sandbox profile for this launch: subprocess filesystem, network, and Mach effects are not confined. Remove ${SANDBOX_DISABLE_ENV} to restore confinement.`,
    };
  if (ENABLING_VALUES.has(value)) return { kind: "enabled" };
  return {
    kind: "invalid",
    reason: `${SANDBOX_DISABLE_ENV}=${raw} is not a recognized value; use 1/true/yes/on to disable confinement or 0/false/no/off to keep it. REA does not guess which one was meant.`,
  };
};

/** One loop launch, as the sandbox would run it. */
export interface SandboxLaunchRequest {
  readonly executable: string;
  readonly args: readonly string[];
  readonly profile: SandboxProfileRequest;
  readonly environment: Readonly<Record<string, string | undefined>>;
}

/** The argv to spawn, plus every limitation the caller must report. */
export interface SandboxLaunchPlan {
  readonly executable: string;
  readonly args: readonly string[];
  readonly limitations: readonly string[];
}

/**
 * Wrap one launch in its profile, or return the bare argv with the limitation
 * that records the emergency exit. Never returns an unconfined argv silently.
 */
export const sandboxLaunchPlan = (
  request: SandboxLaunchRequest,
): SandboxLaunchPlan => {
  const state = sandboxDisableState(request.environment);
  if (state.kind === "invalid")
    throw new SandboxProfileRejection("invalid_disable_value", state.reason);
  const source = sandboxProfileSource(request.profile);
  if (state.kind === "disabled")
    return {
      executable: request.executable,
      args: [...request.args],
      limitations: [state.limitation],
    };
  return {
    executable: SANDBOX_PROFILE_EXECUTABLE,
    args: ["-p", source, request.executable, ...request.args],
    limitations: [],
  };
};
