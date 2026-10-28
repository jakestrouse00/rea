# Protobuf recovery and gRPC reflection

Two tools recover protobuf structure from **caller-held** artifacts and
**caller-declared** lab endpoints. REA never installs a recovery tool, never
discovers endpoints, and never invokes an RPC method.

| Tool                        | Producer          | Question it answers                                                   |
| --------------------------- | ----------------- | --------------------------------------------------------------------- |
| `recover_proto_definitions` | pbtk or protodump | Which packages, messages, fields, and enums does this artifact embed? |
| `enumerate_grpc_reflection` | grpcurl           | Which services and method signatures does this endpoint advertise?    |

## Configuration

| Setting                 | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `REA_PBTK_COMMAND`      | Absolute path to a pbtk executable. Preferred by `tool: auto`. |
| `REA_PROTODUMP_COMMAND` | Absolute path to a protodump executable.                       |
| `REA_GRPCURL_COMMAND`   | **Required** for reflection. Absolute path to grpcurl.         |

At least one of the two recovery tools is required for
`recover_proto_definitions`; `tool: auto` prefers pbtk and falls back to
protodump. An explicit `tool` fails closed when that tool is unselected. REA
does not install any of the three tools.

## Recovering definitions

Recovered `.proto` files are written into one new subdirectory of the caller's
`output_directory`, each with its SHA-256. The Evidence reports each file's
package, messages, fields (name, number, type, label, map, and the oneof group
a member belongs to), enums, and service count. A oneof member is reported in
its parent message with the group name and no group value, so a recovered
structure never hides a declared field. Field options and default values are
never read, so they cannot reach Evidence. A tool that writes no recognizable
`.proto` file is a protocol error, not a partial success.

The pbtk and protodump argv shapes are documented assumptions; no verified
release of either is pinned.

## Reflection

`enumerate_grpc_reflection` runs `grpcurl list` and then one `describe` per
service against the endpoint the caller names. It reports each service's name
and each method's input and output types plus client and server streaming flags.
Service descriptions that fail are counted (`unparsed_services`), never guessed,
and the result is marked partial. Plaintext is the default for lab endpoints;
set `plaintext: false` for TLS. `max_services` and `max_methods` bound the
published inventory.

`REA_GRPCURL_COMMAND` has no `PATH` fallback. The endpoint schema accepts only
`host[:port]` or `[IPv6][:port]` with no scheme, path, or whitespace.

The grpcurl argv and output shapes are documented assumptions; no verified
release is pinned.
