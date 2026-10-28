/** Why a Frida-observed value was shortened. Caller payloads cannot set these. */
export const FRIDA_OWNED_CAPTURE_LIMITS = [
  "session_bytes",
  "message_type",
  "message_text",
  "payload_bytes",
  "json_nodes",
  "json_depth",
  "binary_bytes",
  "unrepresentable",
] as const;

export type FridaOwnedCaptureLimit =
  (typeof FRIDA_OWNED_CAPTURE_LIMITS)[number];
