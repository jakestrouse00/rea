import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { AdbDeviceAnalysisService } from "../application/adb/AdbDeviceAnalysisService.js";
import { toolContract } from "../contracts/toolContracts.js";
import { ADB_TOOL_CONTRACTS } from "../contracts/adb/adbToolContracts.js";
import type { ToolContract } from "../contracts/toolContractTypes.js";
import type { Logger } from "pino";
import { createContractToolHandler } from "./contractToolHandler.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";

/** Bind ADB handlers to their exact named contracts through shared workflows. */
export const registerAdbTools = (
  server: EvidenceMcpServer,
  service: AdbDeviceAnalysisService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const handler = createContractToolHandler(
    server,
    service,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  // All ADB contracts participate in the central TOOL_CONTRACTS inventory
  // (toolContracts.ts spreads ADB_TOOL_CONTRACTS); the capture contracts are
  // looked up from the owning module by exact name so catalog ordering never
  // selects an operation.
  const perfettoContract = ADB_TOOL_CONTRACTS.find(
    (
      contract,
    ): contract is Extract<
      (typeof ADB_TOOL_CONTRACTS)[number],
      { readonly name: "capture_android_perfetto" }
    > => contract.name === "capture_android_perfetto",
  );
  const simpleperfContract = ADB_TOOL_CONTRACTS.find(
    (
      contract,
    ): contract is Extract<
      (typeof ADB_TOOL_CONTRACTS)[number],
      { readonly name: "capture_android_simpleperf" }
    > => contract.name === "capture_android_simpleperf",
  );
  for (const contract of [
    toolContract("inspect_adb_client"),
    toolContract("list_adb_devices"),
    toolContract("inspect_adb_device"),
    toolContract("list_adb_packages"),
    toolContract("pull_adb_package"),
    toolContract("read_adb_logcat"),
    toolContract("inspect_adb_package"),
    toolContract("pull_adb_file"),
    toolContract("push_adb_file"),
    toolContract("capture_adb_screen"),
    toolContract("list_adb_processes"),
    toolContract("list_adb_directory"),
    toolContract("list_adb_features"),
    toolContract("list_adb_services"),
    toolContract("inspect_adb_display"),
    toolContract("inspect_adb_window"),
    toolContract("read_adb_setting"),
    toolContract("collect_adb_bugreport"),
    toolContract("resolve_adb_packages"),
    toolContract("install_adb_package"),
    toolContract("uninstall_adb_package"),
    toolContract("start_adb_app"),
    toolContract("start_adb_activity"),
    toolContract("stop_adb_app"),
    ...(perfettoContract === undefined || simpleperfContract === undefined
      ? []
      : [perfettoContract, simpleperfContract]),
  ]) {
    server.registerTool(
      contract.name,
      toolRegistrationOptions(contract),
      handler(contract),
    );
  }
};
