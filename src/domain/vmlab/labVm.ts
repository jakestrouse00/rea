import { z } from "zod";

/** Provider identity for the caller-supplied Lima lab-VM lane. */
export const LAB_VM_PROVIDER = {
  id: "rea-lab-vm",
  name: "REA Lima lab VM lane",
  version: "1",
} as const;

/** Caller-supplied Lima CLI. REA never installs or upgrades Lima. */
export const LAB_VM_COMMAND_ENV = "REA_LIMACTL_COMMAND";

export const LAB_VM_COMMAND_REMEDIATION = `Set ${LAB_VM_COMMAND_ENV} to the absolute path of a caller-supplied limactl binary created by the vz driver on Apple silicon. REA does not download, install, or upgrade Lima, and a first boot still needs whatever guest image the selected template references.`;

/** Virtualization driver this lane always requests. */
export const LAB_VM_DRIVER = "vz";

/** Rosetta translation is requested together with the vz driver. */
export const LAB_VM_ROSETTA_ENABLED = true;

/** Guest mount point of the caller's workspace. */
export const LAB_VM_GUEST_WORKSPACE = "/workspace";

/** First boot includes guest-image acquisition, so it has its own deadline. */
export const LAB_VM_START_TIMEOUT_MS = 900_000;

/** Wall clock for one guest command when the caller omits `command_timeout_ms`. */
export const LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS = 120_000;

/** Largest delay Node honors as a timer rather than clamping to 1 ms. */
export const LAB_VM_MAX_TIMER_MS = 2_147_483_647;

/** Retained stdout, and separately stderr, from one limactl call. */
export const LAB_VM_MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

/** One live lab VM per REA process; each VM is a complete guest operating system. */
export const LAB_VM_LIVE_CAPACITY = 1;

/** Bounded workspace inventory used to report produced artifact paths. */
export const LAB_VM_MAX_WORKSPACE_ENTRIES = 20_000;

/** Bounded produced-path rows retained per command. */
export const LAB_VM_MAX_WORKSPACE_CHANGES = 512;

/** Retained byte tail for one failure diagnostic from limactl. */
export const LAB_VM_DIAGNOSTIC_EXCERPT_BYTES = 512;

/**
 * UTF-8 bytes of one guest command line.
 *
 * The line travels as a single argv element to a caller-supplied `limactl`,
 * so it is bounded by the host kernel's per-argument limit on Linux and its
 * macOS equivalent rather than by an agent-facing allowance.
 */
export const LAB_VM_MAX_COMMAND_BYTES = 131_072;

export const LAB_VM_UNVERIFIED_NOTE =
  "This lane is exercised with a scripted limactl stand-in only; the offline suite does not run a real Lima VM, the vz driver, or Rosetta translation.";

export const LAB_VM_SANDBOX_NOTE =
  "limactl is launched on this host without a deny-default seatbelt profile because VM management needs its own control socket, network transport, and ~/.lima state. Isolation for work inside the guest comes from the virtual machine, not from a host sandbox.";

/** The `vz` driver needs Apple Virtualization.framework on an Apple silicon host. */
export const labVmHostSupported = (
  platform: NodeJS.Platform = process.platform,
  arch: string = process.arch,
): boolean => platform === "darwin" && arch === "arm64";

export const LAB_VM_UNSUPPORTED_HOST_REASON = `The vz virtual-machine driver needs Apple Virtualization.framework on an Apple silicon macOS host; this host is ${process.platform}-${process.arch}. Use a Linux host with its own container or VM tooling instead.`;

/** Guest architecture the vz driver boots on a supported host. */
export const LAB_VM_GUEST_ARCHITECTURE = "aarch64";

/** How one limactl call ended. */
export const labVmExitTypeSchema = z.enum([
  "exited",
  "signalled",
  "timeout",
  "cancelled",
  "output_truncated",
  "not_started",
]);

export type LabVmExitType = z.infer<typeof labVmExitTypeSchema>;

/** Integer millisecond deadline for one guest command. */
export const labVmCommandTimeoutSchema = z
  .number()
  .int()
  .min(1)
  .max(LAB_VM_MAX_TIMER_MS);

export const labVmCommandTimeoutField = labVmCommandTimeoutSchema
  .optional()
  .describe(
    `Wall-clock budget in milliseconds for this guest command. Omitted means ${String(LAB_VM_DEFAULT_COMMAND_TIMEOUT_MS)}. Integer from 1 to ${String(LAB_VM_MAX_TIMER_MS)}. Applies on the next call and does not raise the ${String(LAB_VM_MAX_OUTPUT_BYTES)}-byte limactl output budget, the ${String(LAB_VM_MAX_COMMAND_BYTES)}-byte command line bound, or the ${String(LAB_VM_START_TIMEOUT_MS)} ms first-boot deadline.`,
  );
