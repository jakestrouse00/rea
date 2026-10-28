export interface GrpcMethod {
  readonly name: string;
  readonly inputType: string;
  readonly outputType: string;
  readonly clientStreaming: boolean;
  readonly serverStreaming: boolean;
}

export interface GrpcService {
  readonly name: string;
  readonly methods: readonly GrpcMethod[];
}

/** Parse `grpcurl <endpoint> list` into unique service names in server order. */
export const parseGrpcServiceList = (stdout: string): readonly string[] => [
  ...new Set(
    stdout
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter((line) => line !== "" && !line.startsWith("grpcurl:")),
  ),
];

const RPC =
  /^\s*rpc\s+([A-Za-z_]\w*)\s*\(\s*(stream\s+)?([A-Za-z_.][\w.]*)\s*\)\s*returns\s*\(\s*(stream\s+)?([A-Za-z_.][\w.]*)\s*\)/u;

const typeNameOf = (value: string): string =>
  value.startsWith(".") ? value.slice(1) : value;

/**
 * Parse `grpcurl <endpoint> describe <service>` into its method signatures.
 * Returns null when the output names no recognizable rpc.
 */
export const parseGrpcServiceDescription = (
  stdout: string,
  service: string,
): GrpcService | null => {
  const methods: GrpcMethod[] = [];
  for (const line of stdout.split(/\r?\n/u)) {
    const match = RPC.exec(line);
    if (match === null) continue;
    methods.push({
      name: match[1]!,
      clientStreaming: match[2] !== undefined,
      inputType: typeNameOf(match[3]!),
      serverStreaming: match[4] !== undefined,
      outputType: typeNameOf(match[5]!),
    });
  }
  return methods.length === 0 ? null : { name: service, methods };
};
