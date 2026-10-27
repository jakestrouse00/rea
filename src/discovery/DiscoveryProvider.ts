import net from "node:net";

import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../application/AnalysisProvider.js";
import { createAnalysisExecution } from "../application/AnalysisProvider.js";
import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisProtocolError,
} from "../domain/analysisErrorCore.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisError as AnalysisErrorClass } from "../domain/analysisErrorBase.js";
import { err, ok, type Result } from "../domain/result.js";
import { providerConfigurationRefusal } from "../domain/providerConfigurationRefusal.js";
import type { DiscoveryRequest } from "../domain/discovery/discoveryAnalysis.js";
import type { DiscoveryReadinessFailure } from "./DiscoveryInstallation.js";
import { inspectDiscoveryInstallation } from "./DiscoveryInstallation.js";
import {
  runDiscoveryCommand,
  runDiscoveryObservation,
  type DiscoveryProcessLauncher,
} from "./DiscoveryCommand.js";
import {
  cidrCandidates,
  parseArpOutput,
  parseBluetoothTree,
  parseBlueutilInquiry,
  parseBrowseOutput,
  parseNdpOutput,
  parsePingLatencyMs,
  parseSystemProfilerJson,
  parseUsbTree,
  type DiscoveryToolset,
  type ParsedServiceType,
  serviceTypeKey,
} from "./DiscoveryDeviceOutput.js";
import {
  DISCOVERY_BLUEUTIL_REMEDIATION,
  DISCOVERY_LANE_NOTE,
  DISCOVERY_PROVIDER_ID,
} from "./DiscoveryRelease.js";

export const DISCOVERY_PROVIDER_IDENTITY = {
  id: DISCOVERY_PROVIDER_ID,
  name: "macOS host discovery tools",
  version: null,
} as const;

export interface DiscoveryProviderOptions {
  readonly environment?: Readonly<NodeJS.ProcessEnv>;
  readonly platform?: NodeJS.Platform;
  /** Test seam for the owned child launcher; production runs the executable. */
  readonly launcher?: DiscoveryProcessLauncher;
}

type RunFn = (
  args: readonly string[],
  timeoutMs?: number,
) => Promise<
  Result<{ stdout: string; stderr: string; stdoutBytes: number }, AnalysisError>
>;

type ObserveFn = (
  args: readonly string[],
  timeoutMs: number,
) => Promise<
  Result<
    {
      stdout: string;
      stderr: string;
      exit_code: number | null;
      timed_out: boolean;
    },
    AnalysisError
  >
>;

interface ResolvedInstallation {
  readonly tools: DiscoveryToolset;
  readonly operationTimeoutMs: number;
  readonly browseProcessTimeoutMs: number;
}

const toolsOf = (tools: DiscoveryToolset) => ({
  arp: tools.arp,
  ndp: tools.ndp,
  dns_sd: tools.dnsSd,
  system_profiler: tools.systemProfiler,
  ping: tools.ping,
  blueutil: tools.blueutil,
});

export class DiscoveryProvider {
  readonly #environment: Readonly<NodeJS.ProcessEnv>;
  readonly #platform: NodeJS.Platform;
  readonly #launcher: DiscoveryProcessLauncher | undefined;
  readonly #activeOperations = new Set<Promise<void>>();
  #closing = false;

  constructor(options: DiscoveryProviderOptions = {}) {
    this.#environment = options.environment ?? process.env;
    this.#platform = options.platform ?? process.platform;
    this.#launcher = options.launcher;
  }

  /** Probe tool resolution without reading host tables or devices. */
  async inspectAvailability(
    signal?: AbortSignal,
  ): Promise<ProviderAvailability> {
    try {
      const installation = await inspectDiscoveryInstallation(
        this.#environment,
        { platform: this.#platform },
      );
      if (!installation.ok)
        return {
          status: "unavailable",
          code: installation.error.code,
          reason: installation.error.reason,
          diagnostics: { ...installation.error.diagnostics },
        };
      return {
        status: "available",
        code: null,
        reason: null,
        diagnostics: {
          arp: installation.value.tools.arp,
          ndp: installation.value.tools.ndp,
          dns_sd: installation.value.tools.dnsSd,
          system_profiler: installation.value.tools.systemProfiler,
          ping: installation.value.tools.ping,
          ...(installation.value.tools.blueutil === null
            ? {}
            : { blueutil: installation.value.tools.blueutil }),
        },
      };
    } catch (cause: unknown) {
      return {
        status: "unavailable",
        code: "executable_missing",
        reason:
          cause instanceof Error
            ? cause.message
            : "The discovery toolset verification failed",
        diagnostics: {},
      };
    }
  }

  /** Stop admission and await active work. */
  async close(): Promise<void> {
    this.#closing = true;
    await Promise.all(this.#activeOperations);
  }

  async execute(
    request: DiscoveryRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const signal = options?.signal;
    if (this.#closing || signal?.aborted === true)
      return err(new AnalysisCancelledError(request.operation));
    let release!: () => void;
    const active = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#activeOperations.add(active);
    try {
      const installation = await this.#requireInstallation(
        request.operation,
        signal,
      );
      if (!installation.ok) return installation;
      const resolvedInstallation = installation.value;
      switch (request.operation) {
        case "list_network_neighbors":
          return await this.#listNeighbors(resolvedInstallation, signal);
        case "browse_lan_services":
          return await this.#browseServices(
            resolvedInstallation,
            request.input,
            signal,
          );
        case "list_usb_devices":
          return await this.#listUsbDevices(resolvedInstallation, signal);
        case "list_bluetooth_devices":
          return await this.#listBluetoothDevices(
            resolvedInstallation,
            request.input,
            signal,
          );
        case "probe_subnet_reachability":
          return await this.#probeSubnet(
            resolvedInstallation,
            request.input,
            signal,
          );
      }
    } finally {
      this.#activeOperations.delete(active);
      release();
    }
  }

  async #requireInstallation(
    operation: string,
    signal: AbortSignal | undefined,
  ): Promise<Result<ResolvedInstallation, AnalysisError>> {
    try {
      const inspected = await inspectDiscoveryInstallation(this.#environment, {
        platform: this.#platform,
      });
      if (!inspected.ok)
        return err(
          providerConfigurationRefusal(
            DISCOVERY_PROVIDER_ID,
            operation,
            readinessRefusal(inspected.error),
          ),
        );
      return ok({
        tools: inspected.value.tools,
        operationTimeoutMs: inspected.value.configuration.operationTimeoutMs,
        browseProcessTimeoutMs:
          inspected.value.configuration.browseProcessTimeoutMs,
      });
    } catch (cause: unknown) {
      if (signal?.aborted)
        return err(
          new AnalysisCancelledError(operation, { cause: signal.reason }),
        );
      return err(
        cause instanceof AnalysisErrorClass
          ? cause
          : new AnalysisProtocolError(
              `discovery toolset verification failed for ${operation}`,
              { cause },
            ),
      );
    }
  }

  async #listNeighbors(
    installation: ResolvedInstallation,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const arpRun = this.#runFor(
      installation.tools.arp,
      "list_network_neighbors",
      installation,
      signal,
    );
    const ndpRun = this.#runFor(
      installation.tools.ndp,
      "list_network_neighbors",
      installation,
      signal,
    );
    const [arp, ndp] = await Promise.all([
      arpRun(["-a", "-n"]),
      ndpRun(["-a", "-n"]),
    ]);
    if (!arp.ok) return arp;
    if (!ndp.ok) return ndp;
    const arpParsed = parseArpOutput(arp.value.stdout);
    const ndpParsed = parseNdpOutput(ndp.value.stdout);
    const hosts = [...arpParsed.items, ...ndpParsed.items];
    const unparsedLines = [
      ...arpParsed.unparsedLines,
      ...ndpParsed.unparsedLines,
    ];
    if (hosts.length === 0 && unparsedLines.length > 0)
      return err(unparseableNeighbors(unparsedLines));
    return ok(
      createAnalysisExecution(
        {
          tools: toolsOf(installation.tools),
          hosts,
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        DISCOVERY_PROVIDER_IDENTITY,
        {
          limitations: [
            DISCOVERY_LANE_NOTE,
            "Neighbor tables are kernel-cached observation state and expire; absence here is not absence on the network",
            ...(unparsedLines.length > 0
              ? ["unparsed_lines preserves table rows REA did not recognize"]
              : []),
          ],
        },
      ),
    );
  }

  async #browseServices(
    installation: ResolvedInstallation,
    input: {
      readonly browse_seconds: number;
      readonly per_type_seconds: number;
      readonly max_types: number;
    },
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const started = Date.now();
    const metaObserve = this.#observeFor(
      installation.tools.dnsSd,
      "browse_lan_services",
      installation,
      signal,
    );
    const meta = await metaObserve(
      ["-B", "_services._dns-sd._udp", "local."],
      input.browse_seconds * 1000 + BROWSE_GRACE_MS,
    );
    if (!meta.ok) return meta;
    const metaParsed = parseBrowseOutput(meta.value.stdout, "meta");
    const found = metaParsed.types;
    const selected = found.slice(0, input.max_types);
    let types: ParsedServiceType[] = selected.map((type) => ({
      ...type,
      instances: [],
    }));
    const unparsedLines = [...metaParsed.unparsedLines];
    for (const selectedType of selected) {
      const instanceObserve = this.#observeFor(
        installation.tools.dnsSd,
        "browse_lan_services",
        installation,
        signal,
      );
      const browse = await instanceObserve(
        [
          "-B",
          selectedType.service_type.replace(/\.$/u, ""),
          selectedType.domain,
        ],
        input.per_type_seconds * 1000 + BROWSE_GRACE_MS,
      );
      if (!browse.ok) return browse;
      const parsed = parseBrowseOutput(browse.value.stdout, "instances");
      unparsedLines.push(...parsed.unparsedLines);
      // One window per browsed type: replace that type's instances with
      // the rows observed in this window instead of accumulating windows.
      const wanted = serviceTypeKey(
        selectedType.service_type,
        selectedType.domain,
      );
      types = types.map((type) =>
        serviceTypeKey(type.service_type, type.domain) === wanted
          ? {
              ...type,
              instances:
                parsed.types.find(
                  (row) =>
                    serviceTypeKey(row.service_type, row.domain) === wanted,
                )?.instances ?? [],
            }
          : type,
      );
    }
    const unbrowsed = found.length - selected.length;
    const exhausted = meta.value.timed_out && unbrowsed > 0;
    return ok(
      createAnalysisExecution(
        {
          tools: toolsOf(installation.tools),
          browse_seconds: input.browse_seconds,
          per_type_seconds: input.per_type_seconds,
          types,
          browsed_type_count: selected.length,
          window_exhausted: exhausted,
          elapsed_ms: Date.now() - started,
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0 || exhausted
              ? ("partial" as const)
              : ("complete" as const),
        },
        DISCOVERY_PROVIDER_IDENTITY,
        {
          limitations: [
            DISCOVERY_LANE_NOTE,
            "dns-sd browses continuously until each window elapses; instance lists reflect only that window",
            "The browse emits multicast queries this host originates; respondents publish their own names",
            ...(unbrowsed > 0
              ? [
                  `${String(unbrowsed)} discovered service types were outside the max_types bound and were not browsed for instances`,
                ]
              : []),
          ],
        },
      ),
    );
  }

  async #listUsbDevices(
    installation: ResolvedInstallation,
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const run = this.#runFor(
      installation.tools.systemProfiler,
      "list_usb_devices",
      installation,
      signal,
    );
    const ran = await run(["SPUSBDataType", "-json", "-detailLevel", "mini"]);
    if (!ran.ok) return ran;
    const parsed = parseSystemProfilerJson(ran.value.stdout);
    if (!parsed.ok)
      return err(
        new AnalysisProtocolError(
          `system_profiler SPUSBDataType was not recognizable: ${parsed.reason ?? "no JSON"}`,
        ),
      );
    const tree = parseUsbTree(parsed.data!);
    return ok(
      createAnalysisExecution(
        {
          tools: toolsOf(installation.tools),
          devices: tree.items,
          unparsed_lines: tree.unparsedLines,
          coverage:
            tree.unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        DISCOVERY_PROVIDER_IDENTITY,
        {
          limitations: [
            DISCOVERY_LANE_NOTE,
            "system_profiler runs with a bounded deadline; a USB device can have been attached after the read or be sleeping",
          ],
        },
      ),
    );
  }

  async #listBluetoothDevices(
    installation: ResolvedInstallation,
    input: {
      readonly source: "paired" | "inquiry";
      readonly inquiry_seconds: number;
    },
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    const run = this.#runFor(
      installation.tools.systemProfiler,
      "list_bluetooth_devices",
      installation,
      signal,
    );
    const ran = await run(["SPBluetoothDataType", "-json"]);
    if (!ran.ok) return ran;
    const parsed = parseSystemProfilerJson(ran.value.stdout);
    if (!parsed.ok)
      return err(
        new AnalysisProtocolError(
          `system_profiler SPBluetoothDataType was not recognizable: ${parsed.reason ?? "no JSON"}`,
        ),
      );
    const tree = parseBluetoothTree(parsed.data!);
    let inquiry: Awaited<ReturnType<typeof parseBlueutilInquiry>> | null = null;
    const unconfigured = installation.tools.blueutil === null;
    const skipped = input.source === "inquiry" && unconfigured;
    const unparsedLines = [...tree.unparsedLines];
    if (input.source === "inquiry" && !unconfigured) {
      const observe = this.#observeFor(
        installation.tools.blueutil!,
        "list_bluetooth_devices",
        installation,
        signal,
      );
      const inquiryRan = await observe(
        ["--inquiry-timeout", String(input.inquiry_seconds), "--inquiry"],
        input.inquiry_seconds * 1000 + INQUIRY_GRACE_MS,
      );
      if (!inquiryRan.ok) return inquiryRan;
      inquiry = parseBlueutilInquiry(inquiryRan.value.stdout);
      unparsedLines.push(...inquiry.unparsedLines);
    }
    return ok(
      createAnalysisExecution(
        {
          tools: toolsOf(installation.tools),
          source: input.source,
          paired: tree.items,
          inquiry: inquiry === null ? null : inquiry.items,
          inquiry_skipped: skipped,
          unparsed_lines: unparsedLines,
          coverage:
            unparsedLines.length > 0
              ? ("partial" as const)
              : ("complete" as const),
        },
        DISCOVERY_PROVIDER_IDENTITY,
        {
          limitations: [
            DISCOVERY_LANE_NOTE,
            ...(skipped
              ? [
                  `The inquiry source was skipped because REA_BLUEUTIL_PATH is not configured. ${DISCOVERY_BLUEUTIL_REMEDIATION}`,
                ]
              : []),
          ],
        },
      ),
    );
  }

  async #probeSubnet(
    installation: ResolvedInstallation,
    input: {
      readonly cidr: string;
      readonly authorize_probe: true;
      readonly concurrency: number;
      readonly per_host_timeout_ms: number;
      readonly tcp_ports: readonly number[];
    },
    signal: AbortSignal | undefined,
  ): Promise<Result<AnalysisExecution, AnalysisError>> {
    // The schema types the authorization as literal true; the provider
    // re-checks it so no execution path skips the gate.
    if (input.authorize_probe !== true)
      return err(
        new AnalysisInputError("probe_subnet_reachability", {
          userMessage:
            "The sweep requires the caller's explicit authorization: pass authorize_probe: true to acknowledge the ICMP and TCP probes this operation sends",
        }),
      );
    const candidates = cidrCandidates(input.cidr);
    if (!candidates.ok)
      return err(
        new AnalysisInputError("probe_subnet_reachability", {
          userMessage: candidates.reason ?? "The CIDR is not probeable",
        }),
      );
    const started = Date.now();
    const timeoutSeconds = Math.ceil(input.per_host_timeout_ms / 1000) + 1;
    const rows = new Map<
      string,
      {
        icmp_reachable: boolean | null;
        icmp_latency_ms: number | null;
        icmp_error: string | null;
        tcp_open_ports: number[];
      }
    >();
    for (const host of candidates.hosts)
      rows.set(host, {
        icmp_reachable: null,
        icmp_latency_ms: null,
        icmp_error: null,
        tcp_open_ports: [],
      });

    let cursor = 0;
    const isAborted = (): boolean => signal?.aborted === true;
    const worker = async (): Promise<void> => {
      for (;;) {
        if (isAborted()) return;
        const index = cursor;
        cursor += 1;
        const host = candidates.hosts[index];
        if (host === undefined) return;
        const row = rows.get(host)!;
        const observe = this.#observeFor(
          installation.tools.ping,
          "probe_subnet_reachability",
          installation,
          signal,
        );
        const ran = await observe(
          [
            "-c",
            "1",
            "-W",
            String(input.per_host_timeout_ms),
            "-t",
            String(timeoutSeconds),
            "-n",
            host,
          ],
          input.per_host_timeout_ms * 3 + PING_GRACE_MS,
        );
        if (!ran.ok) {
          row.icmp_reachable = false;
          row.icmp_error = "ping could not be run";
          rows.set(host, row);
          continue;
        }
        if (ran.value.timed_out) {
          row.icmp_reachable = false;
          row.icmp_error = "no reply within the per-host deadline";
          rows.set(host, row);
          continue;
        }
        const reachable = ran.value.exit_code === 0;
        row.icmp_reachable = reachable;
        row.icmp_latency_ms = reachable
          ? parsePingLatencyMs(ran.value.stdout)
          : null;
        row.icmp_error = reachable ? null : ran.value.stderr.trim() || null;
        rows.set(host, row);
        if (reachable && input.tcp_ports.length > 0 && !isAborted()) {
          const probeDeadline = Math.min(
            input.per_host_timeout_ms,
            TCP_PORT_TIMEOUT_MS,
          );
          for (const port of input.tcp_ports) {
            if (isAborted()) break;
            if (await probeTcpConnect(host, port, probeDeadline))
              row.tcp_open_ports.push(port);
          }
        }
      }
    };
    await Promise.all(
      Array.from(
        {
          length: Math.min(input.concurrency, candidates.hosts.length),
        },
        () => worker(),
      ),
    );
    if (signal?.aborted === true)
      return err(
        new AnalysisCancelledError("probe_subnet_reachability", {
          cause: signal.reason,
        }),
      );
    const hostRows = candidates.hosts.map((host) => ({
      ip: host,
      ...rows.get(host)!,
    }));
    const reachableCount = hostRows.filter(
      (row) => row.icmp_reachable === true,
    ).length;
    return ok(
      createAnalysisExecution(
        {
          tools: toolsOf(installation.tools),
          cidr: input.cidr,
          tcp_ports: [...input.tcp_ports],
          concurrency: input.concurrency,
          per_host_timeout_ms: input.per_host_timeout_ms,
          hosts: hostRows,
          summary: {
            candidates: candidates.hosts.length,
            reachable: reachableCount,
            elapsed_ms: Date.now() - started,
          },
        },
        DISCOVERY_PROVIDER_IDENTITY,
        {
          limitations: [
            DISCOVERY_LANE_NOTE,
            "Exactly one ICMP echo request was sent per candidate address plus optional TCP connects to the requested ports; no other packets originated from REA",
            "A non-response reflects silence on the wire — host firewalling, drop rules, or offline state — never proof of absence",
          ],
        },
      ),
    );
  }

  #runFor(
    executable: string,
    operation: string,
    installation: ResolvedInstallation,
    signal: AbortSignal | undefined,
  ): RunFn {
    return (args, timeoutMs) =>
      runDiscoveryCommand(
        operation,
        executable,
        args,
        { timeoutMs: timeoutMs ?? installation.operationTimeoutMs },
        signal,
        this.#launcher,
      );
  }

  #observeFor(
    executable: string,
    operation: string,
    installation: ResolvedInstallation,
    signal: AbortSignal | undefined,
  ): ObserveFn {
    void installation;
    return (args, timeoutMs) =>
      runDiscoveryObservation(
        operation,
        executable,
        args,
        { timeoutMs },
        signal,
        this.#launcher,
      );
  }
}

const unparseableNeighbors = (unparsedLines: string[]): AnalysisError =>
  new AnalysisProtocolError(
    `arp/ndp output was not recognizable; unmatched rows are preserved: ${unparsedLines
      .slice(0, 4)
      .join(" | ")}`,
  );

const BROWSE_GRACE_MS = 250;
const INQUIRY_GRACE_MS = 5_000;
const PING_GRACE_MS = 1_000;
const TCP_PORT_TIMEOUT_MS = 1_000;

const probeTcpConnect = (
  ip: string,
  port: number,
  timeoutMs: number,
): Promise<boolean> =>
  new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open: boolean): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(open);
    };
    const timer = setTimeout(() => finish(false), timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.connect(port, ip);
  });

/** Project one readiness failure into the shared provider refusal shape. */
const readinessRefusal = (
  failure: DiscoveryReadinessFailure,
): Error & { readonly diagnostics?: Record<string, string> } => {
  const error = new Error(failure.reason);
  return Object.assign(error, {
    diagnostics: { ...failure.diagnostics } as Record<string, string>,
  });
};
