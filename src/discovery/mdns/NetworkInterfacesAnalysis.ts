import { z } from "zod";

/**
 * Draft input schema for `inspect_network_interfaces`. The integrator lifts
 * this into src/domain/discovery/discoveryAnalysis.ts when wiring.
 */
export const networkInterfacesInputSchema = z.strictObject({
  include_neighbors: z
    .boolean()
    .default(true)
    .describe(
      "Whether to read the IPv6 neighbor table and keep the rows on awdl0/llw0 as AWDL peers",
    ),
});

export type NetworkInterfacesInput = z.infer<
  typeof networkInterfacesInputSchema
>;

export interface IfconfigInterfaceRow {
  readonly name: string;
  readonly status: string | null;
  readonly flags: string | null;
  readonly mac: string | null;
  readonly ipv4: string[];
  readonly ipv6: string[];
  readonly awdl_role: string | null;
}

export interface IfconfigPeerRow {
  readonly peer: string;
  readonly mac: string | null;
  readonly interface: string;
}

export interface IfconfigIndexRow {
  readonly index: string;
  readonly name: string;
}

/** Draft result payload for `inspect_network_interfaces`. */
export interface NetworkInterfacesResult {
  readonly interfaces: IfconfigInterfaceRow[];
  readonly interface_indexes: Record<string, string>;
  readonly peers: IfconfigPeerRow[] | null;
  readonly elapsed_ms: number;
  readonly unparsed_lines: string[];
  readonly coverage: "complete" | "partial";
}
