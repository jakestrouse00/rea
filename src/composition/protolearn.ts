import type { ProtocolLearningPort } from "../application/protolearn/ProtocolLearningPort.js";
import type { AnalysisSettingsReader } from "../domain/analysisSettings.js";
import { PcapMessageReader } from "../pcap/PcapMessageReader.js";
import type { ProtocolMessageSourcePort } from "../domain/protolearn/protocolMessageSource.js";
import {
  protolearnProbeEnabled,
} from "../protolearn/ProtocolLearningConfiguration.js";
import { ProtocolLearningProvider } from "../protolearn/ProtocolLearningProvider.js";

/** Construct the protocol learning lane over the caller's capture tools and lab. */
export const createProtocolLearningProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  settings?: AnalysisSettingsReader,
  pcapMessages?: ProtocolMessageSourcePort,
): ProtocolLearningPort =>
  new ProtocolLearningProvider({
    environment,
    ...(settings === undefined ? {} : { settings }),
    ...(pcapMessages === undefined
      ? { pcapMessages: new PcapMessageReader({ environment }) }
      : { pcapMessages }),
  });

/** Whether the probe lane's interpreter, runner, and allowlist are selected. */
export const protocolLearningProbeEnabled = (
  environment: Readonly<Record<string, string | undefined>>,
  provided: boolean,
): boolean => provided || protolearnProbeEnabled(environment, false);
