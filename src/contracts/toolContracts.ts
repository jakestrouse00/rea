import { ANALYSIS_SETTINGS_TOOL_CONTRACTS } from "./analysisSettingsContracts.js";
import { GPU_TOOL_CONTRACTS } from "./gpu/gpuToolContracts.js";
import { CAPTURE_TOOL_CONTRACTS } from "./captures/captureToolContracts.js";
import { SIGNAL_TOOL_CONTRACTS } from "./signals/signalToolContracts.js";
import { WASM_TOOL_CONTRACTS } from "./wasm/wasmToolContracts.js";
import { APK_SIGNATURE_TOOL_CONTRACTS } from "./apkSignature/apkSignatureToolContracts.js";
import { EVM_TOOL_CONTRACTS } from "./evm/evmToolContracts.js";
import { DESKTOP_APPLICATION_TOOL_CONTRACTS } from "./desktopApplicationToolContracts.js";
import { GO_TOOL_CONTRACTS } from "./go/goToolContracts.js";
import { MODEL_TOOL_CONTRACTS } from "./model/modelToolContracts.js";
import { IL2CPP_TOOL_CONTRACTS } from "./il2cpp/il2cppToolContracts.js";
import { RUST_TOOL_CONTRACTS } from "./rust/rustToolContracts.js";
import { PYTHON_PYC_TOOL_CONTRACTS } from "./python/pythonPycToolContracts.js";
import { ERLANG_BEAM_TOOL_CONTRACTS } from "./erlang/beamToolContracts.js";
import { SQLITE_TOOL_CONTRACTS } from "./sqlite/sqliteToolContracts.js";
import { ANALYSIS_VIEW_TOOL_CONTRACTS } from "./analysisViewToolContracts.js";
import { BINARY_DIAGNOSTICS_TOOL_CONTRACTS } from "./native/binaryDiagnosticsToolContracts.js";
import { NATIVE_TOOL_CONTRACTS } from "./native/nativeToolContracts.js";
import { ARTIFACT_TOOL_CONTRACTS } from "./artifactToolContracts.js";
import { MANAGED_TOOL_CONTRACTS } from "./managed/managedToolContracts.js";
import { FIRMWARE_TOOL_CONTRACTS } from "./firmware/firmwareToolContracts.js";
import { ANDROID_TOOL_CONTRACTS } from "./android/androidToolContracts.js";
import { APKTOOL_TOOL_CONTRACTS } from "./apktool/apktoolToolContracts.js";
import { PCAP_TOOL_CONTRACTS } from "./pcap/pcapToolContracts.js";
import { FLUTTER_TOOL_CONTRACTS } from "./flutter/flutterToolContracts.js";
import { JEB_TOOL_CONTRACTS } from "./jeb/jebToolContracts.js";
import { ADB_TOOL_CONTRACTS } from "./adb/adbToolContracts.js";
import { MANAGED_WORKFLOW_TOOL_CONTRACTS } from "./managed/managedWorkflowToolContracts.js";
import { BROWSER_PROVIDER_TOOL_CONTRACTS } from "./browserProviderToolContracts.js";
import { ELECTRON_TOOL_CONTRACTS } from "./javascript/electronToolContracts.js";
import { JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS } from "./javascript/javascriptRuntimeObservationToolContracts.js";
import { APPLICATION_TOOL_CONTRACTS } from "./applicationToolContracts.js";
import { WEB_SCRIPT_TOOL_CONTRACTS } from "./webScriptToolContracts.js";
import { WEB_RUNTIME_TOOL_CONTRACTS } from "./webRuntimeToolContracts.js";
import { WEB_NETWORK_CAPTURE_TOOL_CONTRACTS } from "./webNetworkCaptureToolContracts.js";
import { JAVASCRIPT_RECOVERY_TOOL_CONTRACTS } from "./javascript/javascriptRecoveryToolContracts.js";
import { OFFICIAL_TOOL_CONTRACTS } from "./officialToolContracts.js";
import { ENHANCED_TOOL_CONTRACTS } from "./enhancedToolContracts.js";
import { SESSION_TOOL_CONTRACTS } from "./sessionToolContracts.js";
import { CUTTER_TOOL_CONTRACTS } from "./cutterToolContracts.js";
import { REVERSE_ENGINEERING_TOOL_CONTRACTS } from "./reverseEngineeringToolContracts.js";
import { GDB_TOOL_CONTRACTS } from "./gdbToolContracts.js";
import { RIZIN_DEBUG_TOOL_CONTRACTS } from "./rizinDebugToolContracts.js";
import { FRIDA_TOOL_CONTRACTS } from "./fridaToolContracts.js";
import { WINDOWS_ARTIFACTS_TOOL_CONTRACTS } from "./windowsArtifacts/windowsArtifactsToolContracts.js";
import { LIEF_TOOL_CONTRACTS } from "./lief/liefToolContracts.js";
import { NATIVE_AOT_TOOL_CONTRACTS } from "./managed/nativeAotToolContracts.js";
import { GAME_DATA_TOOL_CONTRACTS } from "./gamedata/gamedataToolContracts.js";
import { CONTAINER_TOOL_CONTRACTS } from "./containers/containersToolContracts.js";
import { IDEVICE_TOOL_CONTRACTS } from "./idevice/ideviceToolContracts.js";
import { IPSW_TOOL_CONTRACTS } from "./iosipsw/IpswToolContracts.js";
import { CAPA_TOOL_CONTRACTS } from "./capa/capaToolContracts.js";
import { YARA_TOOL_CONTRACTS } from "./yara/yaraToolContracts.js";
import { SYMBOL_TOOL_CONTRACTS } from "./symbols/symbolToolContracts.js";
import { DOTNET_DECOMPILER_TOOL_CONTRACTS } from "./manageddecomp/dotnetDecompilerToolContracts.js";
import { PYTHON_DECOMPILER_TOOL_CONTRACTS } from "./pysrc/pythonDecompilerToolContracts.js";
import { JVM_DECOMPILER_TOOL_CONTRACTS } from "./jvmdecomp/jvmDecompilerToolContracts.js";
import { V8_BYTECODE_TOOL_CONTRACTS } from "./javascript/v8BytecodeToolContracts.js";
import { ASAR_INTEGRITY_TOOL_CONTRACTS } from "./electron/asarIntegrityToolContracts.js";
import { PROTOBUF_RECOVERY_TOOL_CONTRACTS } from "./protobufrecovery/protobufRecoveryToolContracts.js";
import { BINDIFF_TOOL_CONTRACTS } from "./bindiff/bindiffToolContracts.js";
import { CRASH_TRIAGE_TOOL_CONTRACTS } from "./crashTriage/crashTriageToolContracts.js";
import { FUZZING_TOOL_CONTRACTS } from "./fuzzing/fuzzingToolContracts.js";
import { REPLAY_TOOL_CONTRACTS } from "./replay/ReplayToolContracts.js";
import { MITM_TOOL_CONTRACTS } from "./mitm/MitmToolContracts.js";
import { EMU_TOOL_CONTRACTS } from "./emu/emuToolContracts.js";
import { ANGR_TOOL_CONTRACTS } from "./angr/angrToolContracts.js";
import { MOBILE_TOOLCHAIN_TOOL_CONTRACTS } from "./mobile/mobileToolchainToolContracts.js";
import { PROTOLEARN_TOOL_CONTRACTS } from "./protolearn/protolearnToolContracts.js";
import { HUNTING_TOOL_CONTRACTS } from "./hunting/huntingToolContracts.js";
import { DISCOVERY_TOOL_CONTRACTS } from "./discovery/discoveryToolContracts.js";
import { CORRELATION_TOOL_CONTRACTS } from "./correlationToolContracts.js";
import { ENVIRONMENT_TOOL_CONTRACTS } from "./environmentToolContracts.js";

/** Complete ordered public inventory used by registration and verification. */
export const TOOL_CONTRACTS = [
  ...ANALYSIS_SETTINGS_TOOL_CONTRACTS,
  ...OFFICIAL_TOOL_CONTRACTS,
  ...ENHANCED_TOOL_CONTRACTS,
  ...NATIVE_TOOL_CONTRACTS,
  ...BINARY_DIAGNOSTICS_TOOL_CONTRACTS,
  ...ANALYSIS_VIEW_TOOL_CONTRACTS,
  ...ARTIFACT_TOOL_CONTRACTS,
  ...DESKTOP_APPLICATION_TOOL_CONTRACTS,
  ...EVM_TOOL_CONTRACTS,
  ...GO_TOOL_CONTRACTS,
  ...IL2CPP_TOOL_CONTRACTS,
  ...MODEL_TOOL_CONTRACTS,
  ...GPU_TOOL_CONTRACTS,
  ...RUST_TOOL_CONTRACTS,
  ...NATIVE_AOT_TOOL_CONTRACTS,
  ...WINDOWS_ARTIFACTS_TOOL_CONTRACTS,
  ...LIEF_TOOL_CONTRACTS,
  ...GAME_DATA_TOOL_CONTRACTS,
  ...CONTAINER_TOOL_CONTRACTS,
  ...IDEVICE_TOOL_CONTRACTS,
  ...IPSW_TOOL_CONTRACTS,
  ...CAPA_TOOL_CONTRACTS,
  ...YARA_TOOL_CONTRACTS,
  ...SYMBOL_TOOL_CONTRACTS,
  ...DOTNET_DECOMPILER_TOOL_CONTRACTS,
  ...PYTHON_DECOMPILER_TOOL_CONTRACTS,
  ...JVM_DECOMPILER_TOOL_CONTRACTS,
  ...V8_BYTECODE_TOOL_CONTRACTS,
  ...ASAR_INTEGRITY_TOOL_CONTRACTS,
  ...PROTOBUF_RECOVERY_TOOL_CONTRACTS,
  ...BINDIFF_TOOL_CONTRACTS,
  ...CRASH_TRIAGE_TOOL_CONTRACTS,
  ...FUZZING_TOOL_CONTRACTS,
  ...REPLAY_TOOL_CONTRACTS,
  ...MITM_TOOL_CONTRACTS,
  ...EMU_TOOL_CONTRACTS,
  ...ANGR_TOOL_CONTRACTS,
  ...MOBILE_TOOLCHAIN_TOOL_CONTRACTS,
  ...PROTOLEARN_TOOL_CONTRACTS,
  ...HUNTING_TOOL_CONTRACTS,
  ...DISCOVERY_TOOL_CONTRACTS,
  ...CORRELATION_TOOL_CONTRACTS,
  ...PYTHON_PYC_TOOL_CONTRACTS,
  ...ERLANG_BEAM_TOOL_CONTRACTS,
  ...WASM_TOOL_CONTRACTS,
  ...APK_SIGNATURE_TOOL_CONTRACTS,
  ...SQLITE_TOOL_CONTRACTS,
  ...CAPTURE_TOOL_CONTRACTS,
  ...SIGNAL_TOOL_CONTRACTS,
  ...MANAGED_TOOL_CONTRACTS,
  ...ANDROID_TOOL_CONTRACTS,
  ...APKTOOL_TOOL_CONTRACTS,
  ...PCAP_TOOL_CONTRACTS,
  ...FLUTTER_TOOL_CONTRACTS,
  ...JEB_TOOL_CONTRACTS,
  ...ADB_TOOL_CONTRACTS,
  ...FIRMWARE_TOOL_CONTRACTS,
  ...MANAGED_WORKFLOW_TOOL_CONTRACTS,
  ...BROWSER_PROVIDER_TOOL_CONTRACTS,
  ...ELECTRON_TOOL_CONTRACTS,
  ...JAVASCRIPT_RUNTIME_OBSERVATION_TOOL_CONTRACTS,
  ...APPLICATION_TOOL_CONTRACTS,
  ...WEB_SCRIPT_TOOL_CONTRACTS,
  ...WEB_RUNTIME_TOOL_CONTRACTS,
  ...WEB_NETWORK_CAPTURE_TOOL_CONTRACTS,
  ...ENVIRONMENT_TOOL_CONTRACTS,
  ...JAVASCRIPT_RECOVERY_TOOL_CONTRACTS,
  ...SESSION_TOOL_CONTRACTS,
  ...CUTTER_TOOL_CONTRACTS,
  ...REVERSE_ENGINEERING_TOOL_CONTRACTS,
  ...GDB_TOOL_CONTRACTS,
  ...RIZIN_DEBUG_TOOL_CONTRACTS,
  ...FRIDA_TOOL_CONTRACTS,
] as const;

/** Resolve a public contract by name while retaining its exact schema types. */
export const toolContract = <
  Name extends (typeof TOOL_CONTRACTS)[number]["name"],
>(
  name: Name,
): Extract<(typeof TOOL_CONTRACTS)[number], { readonly name: Name }> => {
  const contract = TOOL_CONTRACTS.find(
    (
      candidate,
    ): candidate is Extract<
      (typeof TOOL_CONTRACTS)[number],
      { readonly name: Name }
    > => candidate.name === name,
  );
  if (contract === undefined) throw new Error(`Missing tool contract: ${name}`);
  return contract;
};
