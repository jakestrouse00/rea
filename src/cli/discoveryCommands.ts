import { z } from "incur";

import { DiscoveryAnalysisService } from "../application/discovery/DiscoveryAnalysisService.js";
import type { DiscoveryAnalysisPort } from "../application/discovery/DiscoveryPort.js";
import { createDiscoveryAnalysisProvider } from "../composition/discovery.js";
import type { DiscoveryOperation } from "../domain/discovery/discoveryAnalysis.js";
import { logCliCommand } from "../cliLogging.js";
import type { Logger } from "pino";
import type { CliInstance } from "./types.js";
import { withCommandCancellation } from "./commandCancellation.js";
import { finishAnalysisCommand } from "./finishAnalysisCommand.js";
import { CLI_COMMANDS } from "../cliCommandNames.js";

const DISCOVERY_CLI_COMMANDS = CLI_COMMANDS;

/** Expose the discovery-lane operations through the CLI. */
export const registerDiscoveryCommands = (
  cli: CliInstance,
  logger: Logger,
  environment: Readonly<Record<string, string | undefined>>,
  provider: DiscoveryAnalysisPort = createDiscoveryAnalysisProvider(
    environment,
  ),
): void => {
  const service = new DiscoveryAnalysisService(provider);
  const execute = (
    name: string,
    operation: DiscoveryOperation,
    input: unknown,
  ) =>
    withCommandCancellation((signal) =>
      logCliCommand(logger, name, () =>
        finishAnalysisCommand(
          () => service.execute(operation, input, { signal }),
          { close: () => provider.close() },
          "discovery",
          operation,
          signal,
        ),
      ),
    );

  cli.command(DISCOVERY_CLI_COMMANDS.listNetworkNeighbors, {
    description:
      "Read this host's arp/ndp neighbor tables; an empty table is an observation, not an error",
    args: z.object({}),
    run: () =>
      execute(
        DISCOVERY_CLI_COMMANDS.listNetworkNeighbors,
        "list_network_neighbors",
        {},
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.browseLanServices, {
    description:
      "Browse the local network for mDNS/Bonjour service types and instances in bounded windows",
    options: z.object({
      "browse-seconds": z
        .number()
        .int()
        .min(1)
        .max(30)
        .default(10)
        .describe("Multicast browse window for the service-type meta query"),
      "per-type-seconds": z
        .number()
        .int()
        .min(1)
        .max(10)
        .default(3)
        .describe("Instance browse window per discovered service type"),
      "max-types": z
        .number()
        .int()
        .min(1)
        .max(32)
        .default(16)
        .describe("Maximum service types to browse for instances"),
    }),
    run: ({ options }) =>
      execute(DISCOVERY_CLI_COMMANDS.browseLanServices, "browse_lan_services", {
        browse_seconds: options["browse-seconds"],
        per_type_seconds: options["per-type-seconds"],
        max_types: options["max-types"],
      }),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.listUsbDevices, {
    description:
      "Inventory the USB/Thunderbolt device tree through system_profiler",
    args: z.object({}),
    run: () =>
      execute(DISCOVERY_CLI_COMMANDS.listUsbDevices, "list_usb_devices", {}),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.listBluetoothDevices, {
    description:
      "Read the host's paired Bluetooth inventory, optionally adding a bounded inquiry window via caller-supplied blueutil",
    options: z.object({
      source: z
        .enum(["paired", "inquiry"])
        .default("paired")
        .describe("paired reads the host inventory; inquiry runs blueutil"),
      "inquiry-seconds": z
        .number()
        .int()
        .min(2)
        .max(60)
        .default(10)
        .describe("Discovery window in seconds when source is inquiry"),
    }),
    run: ({ options }) =>
      execute(
        DISCOVERY_CLI_COMMANDS.listBluetoothDevices,
        "list_bluetooth_devices",
        {
          source: options.source,
          inquiry_seconds: options["inquiry-seconds"],
        },
      ),
  });
  cli.command(DISCOVERY_CLI_COMMANDS.probeSubnetReachability, {
    description:
      "Send exactly one ICMP echo per candidate host of a /22../32 CIDR at bounded concurrency, with optional TCP connect probes",
    args: z.object({
      cidr: z
        .string()
        .min(10)
        .describe("IPv4 network to probe, e.g. 192.168.1.0/24"),
    }),
    options: z.object({
      authorize: z
        .boolean()
        .describe(
          "Must be true to acknowledge the packets this host will send",
        ),
      concurrency: z
        .number()
        .int()
        .min(1)
        .max(64)
        .default(16)
        .describe("Maximum hosts probed in parallel"),
      "per-host-timeout": z
        .number()
        .int()
        .min(100)
        .max(5000)
        .default(1000)
        .describe("Deadline for one host's ICMP echo exchange, in ms"),
      "tcp-ports": z
        .string()
        .default("")
        .describe(
          "Comma-separated TCP ports to probe on responsive hosts, e.g. 5555,27042",
        ),
    }),
    run: ({ args, options }) => {
      const parsedPorts = options["tcp-ports"]
        .split(",")
        .map((part) => part.trim())
        .filter((part) => part.length > 0)
        .map(Number);
      return execute(
        DISCOVERY_CLI_COMMANDS.probeSubnetReachability,
        "probe_subnet_reachability",
        {
          cidr: args.cidr,
          authorize_probe: options.authorize === true,
          concurrency: options.concurrency,
          per_host_timeout_ms: options["per-host-timeout"],
          tcp_ports: parsedPorts,
        },
      );
    },
  });
};
