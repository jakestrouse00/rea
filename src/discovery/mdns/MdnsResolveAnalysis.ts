import { z } from "zod";

/**
 * Draft input schema for `resolve_mdns_records`. The integrator lifts this
 * into src/domain/discovery/discoveryAnalysis.ts when wiring the operation.
 */
export const mdnsResolveInputSchema = z.strictObject({
  instance: z
    .string()
    .min(1)
    .max(255)
    .describe(
      "Service instance label as a browse returned it, e.g. 'Office Printer'",
    ),
  service_type: z
    .string()
    .regex(
      /^_[a-z0-9-]+\._(?:tcp|udp)\.$/iu,
      "Use a full mDNS service type such as _http._tcp. or _raop._udp.",
    )
    .describe("One mDNS service type with its trailing dot, e.g. _http._tcp."),
  domain: z
    .string()
    .regex(
      /^(?:[a-z0-9_-]{1,63}\.)+$/iu,
      "Use a trailing-dot mDNS domain such as local.",
    )
    .default("local.")
    .describe("Trailing-dot mDNS domain of the service; local. is the norm"),
  resolve_seconds: z
    .number()
    .int()
    .min(2)
    .max(15)
    .default(5)
    .describe(
      "Per dns-sd window deadline in seconds (-L and any follow-up reads)",
    ),
  include_addresses: z
    .boolean()
    .default(true)
    .describe(
      "Whether to run the -G v4v6 address window against the resolved SRV target",
    ),
});

export type MdnsResolveInput = z.infer<typeof mdnsResolveInputSchema>;

/** One TXT key/value as the host's record spells it; key stays null untagged. */
export interface MdnsTxtEntry {
  readonly key: string | null;
  readonly value: string;
}

/** One -L lookup row exactly as dns-sd emitted it. */
export interface MdnsLookupRecord {
  readonly service_name: string;
  readonly target: string | null;
  readonly port: number | null;
  readonly interface_index: string | null;
  readonly txt: MdnsTxtEntry[];
  readonly txt_raw: string | null;
  readonly raw: string;
}

/** One -Z zone-format record row. */
export interface MdnsZoneRecord {
  readonly kind: "ptr" | "srv" | "txt";
  readonly name: string;
  readonly target: string | null;
  readonly port: number | null;
  readonly ttl: string | null;
  readonly txt: MdnsTxtEntry[];
  readonly raw: string;
}

/** One -G address row; family follows the record's rrtype. */
export interface MdnsAddressRow {
  readonly family: "ipv4" | "ipv6";
  readonly address: string;
  readonly interface_index: string | null;
  readonly hostname: string | null;
  readonly raw: string;
}

/** Draft result payload for `resolve_mdns_records`. */
export interface MdnsResolveResult {
  readonly instance: string;
  readonly service_type: string;
  readonly domain: string;
  readonly interface_index: string | null;
  readonly srv: {
    readonly target: string | null;
    readonly port: number | null;
  };
  readonly txt: MdnsTxtEntry[];
  readonly raw_txt: string | null;
  readonly addresses: MdnsAddressRow[];
  readonly lookup_rows: MdnsLookupRecord[];
  readonly zone_ran: boolean;
  readonly addresses_ran: boolean;
  readonly lookup_timed_out: boolean | null;
  readonly elapsed_ms: number;
  readonly unparsed_lines: string[];
  readonly coverage: "complete" | "partial";
}
