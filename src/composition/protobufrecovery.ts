import type { ProtobufRecoveryPort } from "../application/protobufrecovery/ProtobufRecoveryPort.js";
import { ProtobufRecoveryProvider } from "../protobufrecovery/ProtobufRecoveryProvider.js";

/** Construct one protobuf recovery provider over the caller's selected tools. */
export const createProtobufRecoveryProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): ProtobufRecoveryPort => new ProtobufRecoveryProvider({ environment });
