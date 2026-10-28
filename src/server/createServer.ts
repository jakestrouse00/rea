import { AnalysisSettings } from "../application/AnalysisSettings.js";
import { registerAnalysisSettingsTools } from "./registerAnalysisSettingsTools.js";
import type { DevicetreeService } from "../application/binaryDiagnostics/DevicetreeService.js";
import { registerDevicetreeTool } from "./registerDevicetreeTool.js";
import { pcapCaptureHostSupported } from "../domain/pcap/pcapAnalysis.js";
import { createGpuCodeObjectsService } from "../composition/gpu.js";
import { registerGpuCodeObjectsTools } from "./registerGpuCodeObjectsTools.js";
import type { PacketCaptureService } from "../application/captures/PacketCaptureService.js";
import { UNTRUSTED_CONTENT_INSTRUCTIONS } from "./toolResultEncoding.js";
import { RECOVERY_INSTRUCTIONS } from "./recoveryInstructions.js";
import {
  createPacketCaptureService,
  tsharkHostSupported,
} from "../composition/captures.js";
import { registerCaptureTools } from "./registerCaptureTools.js";
import type { SignalRecordingService } from "../application/signals/SignalRecordingService.js";
import {
  createSignalRecordingService,
  sigrokHostSupported,
} from "../composition/signals.js";
import { registerSignalTools } from "./registerSignalTools.js";
import type { WasmArtifactService } from "../application/wasm/WasmArtifactService.js";
import { wasmArtifactModule } from "../composition/wasm.js";
import { registerWasmTools } from "./registerWasmTools.js";
import type { ApkSignatureService } from "../application/apkSignature/ApkSignatureService.js";
import { apkSignatureModule } from "../composition/apkSignature.js";
import { registerApkSignatureTools } from "./registerApkSignatureTools.js";
import { snapshotEnvironment } from "../process/snapshotEnvironment.js";
import { captureProviderEnvironment } from "./providerEnvironment.js";
import {
  createElfNotesService,
  createAppleIpsService,
  createDevicetreeService,
  createKernelModuleService,
  createPeLoadConfigService,
  createPeCertificatesService,
  createPeImportsService,
  createNativeExportsService,
  createPeResourcesService,
  createRecordedCrashService,
  createByteEntropyService,
  createBinaryLayoutService,
  pwntoolsHostSupported,
} from "../composition/binaryDiagnostics.js";
import type { ElfNotesService } from "../application/binaryDiagnostics/ElfNotesService.js";
import type { AppleIpsService } from "../application/binaryDiagnostics/AppleIpsService.js";
import type { KernelModuleService } from "../application/binaryDiagnostics/KernelModuleService.js";
import type { PeLoadConfigService } from "../application/binaryDiagnostics/PeLoadConfigService.js";
import type { PeCertificatesService } from "../application/binaryDiagnostics/PeCertificatesService.js";
import type { PeImportsService } from "../application/binaryDiagnostics/PeImportsService.js";
import type { PeResourcesService } from "../application/binaryDiagnostics/PeResourcesService.js";
import type { NativeExportsService } from "../application/binaryDiagnostics/NativeExportsService.js";
import { registerElfNotesTool } from "./registerElfNotesTool.js";
import { registerAppleIpsTool } from "./registerAppleIpsTool.js";
import { registerKernelModuleTool } from "./registerKernelModuleTool.js";
import { registerPeLoadConfigTool } from "./registerPeLoadConfigTool.js";
import { registerPeCertificatesTool } from "./registerPeCertificatesTool.js";
import { registerPeImportsTool } from "./registerPeImportsTool.js";
import { registerPeResourcesTool } from "./registerPeResourcesTool.js";
import { registerNativeExportsTool } from "./registerNativeExportsTool.js";
import type { EvmInterfaceService } from "../application/evm/EvmInterfaceService.js";
import {
  evmHostSupported,
  evmInterfaceModule,
  evmLimiterAvailability,
} from "../composition/evm.js";
import { registerEvmTools } from "./registerEvmTools.js";
import type { SqliteDatabaseService } from "../application/sqlite/SqliteDatabaseService.js";
import { createSqliteDatabaseService } from "../composition/sqlite.js";
import { registerSqliteTools } from "./registerSqliteTools.js";
import { registerRecordedCrashTools } from "./registerRecordedCrashTools.js";
import { createDesktopApplicationService } from "../composition/desktop.js";
import { registerDesktopApplicationTool } from "./registerDesktopApplicationTool.js";
import { createGoBinaryService } from "../composition/go.js";
import { createModelArtifactService } from "../composition/model.js";
import { registerModelArtifactTools } from "./registerModelArtifactTools.js";
import { createIl2cppMetadataService } from "../composition/il2cpp.js";
import type { Il2cppMetadataService } from "../application/il2cpp/Il2cppMetadataService.js";
import type { GoBinaryService } from "../application/go/GoBinaryService.js";
import { createElectronFuseService } from "../composition/electronFuses.js";
import { AsarIntegrityService } from "../application/electron/AsarIntegrityService.js";
import { createAsarIntegrityProvider } from "../composition/asarIntegrity.js";
import { registerAsarIntegrityTool } from "./registerAsarIntegrityTool.js";
import { V8BytecodeService } from "../application/javascript/V8BytecodeService.js";
import type { V8BytecodePort } from "../application/javascript/V8BytecodePort.js";
import { createV8BytecodeProvider } from "../composition/v8Bytecode.js";
import { registerV8BytecodeTool } from "./registerV8BytecodeTool.js";
import type { ElectronFuseService } from "../application/electron/ElectronFuseService.js";
import { registerGoTools } from "./registerGoTools.js";
import { registerIl2cppTools } from "./registerIl2cppTools.js";
import {
  createRustBinaryService,
  createRustSymbolsService,
} from "../composition/rust.js";
import type { RustBinaryService } from "../application/rust/RustBinaryService.js";
import type { RustSymbolsService } from "../application/rust/RustSymbolsService.js";
import { registerRustTools } from "./registerRustTools.js";
import { createPythonPycService } from "../composition/pythonPyc.js";
import type { PythonPycService } from "../application/python/PythonPycService.js";
import { registerPythonPycTool } from "./registerPythonPycTool.js";
import { createBeamService } from "../composition/erlang.js";
import type { BeamService } from "../application/erlang/BeamService.js";
import { registerErlangTools } from "./registerErlangTools.js";
import type { RecordedCrashService } from "../application/binaryDiagnostics/RecordedCrashService.js";
import { registerAnalysisViewTool } from "./registerAnalysisViewTool.js";
import { registerBinaryDiagnosticsTools } from "./registerBinaryDiagnosticsTools.js";
import { FridaInstrumentationManager } from "../frida/FridaInstrumentationManager.js";
import { registerFridaTools } from "./registerFridaTools.js";
import type { BinaryLayoutService } from "../application/binaryDiagnostics/BinaryLayoutService.js";
import { createCatalogIdentity } from "../catalogIdentity.js";
import { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { createToolResultDelivery } from "./toolResult.js";
import type { ToolResultDelivery } from "./ToolResultDelivery.js";
import { parseMcpResponseBudget } from "../config/mcpResponseBudget.js";
import { parseMcpOutputSchemaProfile } from "../config/mcpOutputSchemaProfile.js";
import {
  compactPresentationForMcpInputSchemaProfile,
  parseMcpInputSchemaProfile,
} from "../config/mcpInputSchemaProfile.js";
import type { CompactInputSchemaPresentation } from "./EvidenceMcpServer.js";
import { isAbsolute } from "node:path";

import type { BinarySessionPort } from "../application/binary/BinarySessionPort.js";
import type { BrowserObservationPort } from "../application/BrowserObservationPort.js";
import type { BrowserScenarioCapturePort } from "../application/BrowserScenarioCapturePort.js";
import type { ElectronActiveObservationPort } from "../application/javascript/ElectronActiveObservationPort.js";
import type { ElectronObservationPort } from "../application/javascript/ElectronObservationPort.js";
import type { JavaScriptRuntimeObservationPort } from "../application/javascript/JavaScriptRuntimeObservationPort.js";
import type { FridaInstrumentationPort } from "../application/frida/FridaInstrumentationPort.js";
import type { OptionalProviderLoadFailures } from "../application/OptionalObservationProviders.js";
import { PRODUCT_IDENTITY } from "../identity.js";
import { silentLogger } from "../logger.js";
import type { Logger } from "pino";
import { registerApplicationTools } from "./registerApplicationTools.js";
import { registerArtifactTools } from "./registerArtifactTools.js";
import { registerNativeTools } from "./registerNativeTools.js";
import { registerBrowserScenarioTool } from "./registerBrowserScenarioTool.js";
import { registerBrowserTools } from "./registerBrowserTools.js";
import { registerWebScriptTool } from "./registerWebScriptTool.js";
import { registerWebModuleTool } from "./registerWebModuleTool.js";
import type { WebModuleTraceService } from "../application/WebModuleTraceService.js";
import { createWebModuleTraceService } from "../composition/webModules.js";
import { createWebSourceLocationService } from "../composition/webSourceLocations.js";
import { registerWebSourceLocationTool } from "./registerWebSourceLocationTool.js";
import type { WebSourceLocationService } from "../application/WebSourceLocationService.js";
import type { WebRuntimeService } from "../application/WebRuntimeService.js";
import { createWebRuntimeService } from "../composition/webRuntime.js";
import { registerWebRuntimeTools } from "./registerWebRuntimeTools.js";
import type { WebNetworkCaptureService } from "../application/WebNetworkCaptureService.js";
import { createWebNetworkCaptureService } from "../composition/webNetworkCaptures.js";
import { registerWebNetworkCaptureTool } from "./registerWebNetworkCaptureTool.js";
import { registerJavaScriptRecoveryTool } from "./registerJavaScriptRecoveryTool.js";
import { JavaScriptRecoveryService } from "../application/javascript/JavaScriptRecoveryService.js";
import type { JavaScriptRecoveryPort } from "../application/javascript/JavaScriptRecoveryPort.js";
import {
  createJavaScriptRecoveryProvider,
  wakaruHostSupported,
} from "../composition/javascriptRecovery.js";
import { registerElectronTools } from "./registerElectronTools.js";
import { ArtifactResourceScope } from "../artifacts/ArtifactResourceScope.js";
import { registerEnhancedTools } from "./registerEnhancedTools.js";
import { registerJavaScriptRuntimeObservationTools } from "./registerJavaScriptRuntimeObservationTools.js";
import { registerManagedTools } from "./registerManagedTools.js";
import { registerFirmwareTools } from "./registerFirmwareTools.js";
import { FirmwareAnalysisService } from "../application/firmware/FirmwareAnalysisService.js";
import type { FirmwareAnalysisPort } from "../application/firmware/FirmwareAnalysisPort.js";
import {
  createFirmwareAnalysisProvider,
  firmwareHostSupported,
} from "../composition/firmware.js";
import { registerAndroidTools } from "./registerAndroidTools.js";
import { registerApktoolTools } from "./registerApktoolTools.js";
import { registerPcapTools } from "./registerPcapTools.js";
import { registerFlutterTools } from "./registerFlutterTools.js";
import { registerJebTools } from "./registerJebTools.js";
import { registerAdbTools } from "./registerAdbTools.js";
import { AndroidAnalysisService } from "../application/android/AndroidAnalysisService.js";
import { JebAnalysisService } from "../application/jeb/JebAnalysisService.js";
import type { AndroidAnalysisPort } from "../application/android/AndroidAnalysisPort.js";
import type { ApktoolResourceAnalysisPort } from "../application/apktool/ApktoolResourceAnalysisPort.js";
import type { PcapAnalysisPort } from "../application/pcap/PcapAnalysisPort.js";
import { PcapAnalysisService } from "../application/pcap/PcapAnalysisService.js";
import {
  locateWiresharkTool,
  selectWiresharkTool,
} from "../pcap/PcapConfiguration.js";
import { ApktoolResourceAnalysisService } from "../application/apktool/ApktoolResourceAnalysisService.js";
import type { FlutterBuildAnalysisPort } from "../application/flutter/FlutterBuildAnalysisPort.js";
import { FlutterBuildAnalysisService } from "../application/flutter/FlutterBuildAnalysisService.js";
import { createAndroidAnalysisProvider } from "../composition/android.js";
import { createApktoolResourceAnalysisProvider } from "../composition/apktool.js";
import { createPcapAnalysisProvider } from "../composition/pcap.js";
import { createFlutterBuildAnalysisProvider } from "../composition/flutter.js";
import type { JebAnalysisPort } from "../application/jeb/JebAnalysisPort.js";
import { createJebAnalysisProvider } from "../composition/jeb.js";
import type { AdbDeviceAnalysisPort } from "../application/adb/AdbDeviceAnalysisPort.js";
import { AdbDeviceAnalysisService } from "../application/adb/AdbDeviceAnalysisService.js";
import { createAdbDeviceAnalysisProvider } from "../composition/adb.js";
import type { IdeviceAnalysisPort } from "../application/idevice/IdevicePort.js";
import { IdeviceAnalysisService } from "../application/idevice/IdeviceAnalysisService.js";
import { createIdeviceAnalysisProvider } from "../composition/idevice.js";
import type { IpswAnalysisPort } from "../application/iosipsw/IpswAnalysisPort.js";
import { IpswAnalysisService } from "../application/iosipsw/IpswAnalysisService.js";
import { createIpswAnalysisProvider } from "../composition/iosipsw.js";
import { registerIpswTools } from "./registerIpswTools.js";
import type { CapaAnalysisPort } from "../application/capa/CapaAnalysisPort.js";
import { CapaAnalysisService } from "../application/capa/CapaAnalysisService.js";
import { createCapaAnalysisProvider } from "../composition/capa.js";
import { registerCapaTools } from "./registerCapaTools.js";
import type { YaraAnalysisPort } from "../application/yara/YaraAnalysisPort.js";
import { YaraAnalysisService } from "../application/yara/YaraAnalysisService.js";
import { createYaraAnalysisProvider } from "../composition/yara.js";
import { registerYaraTools } from "./registerYaraTools.js";
import type { SymbolRecoveryPort } from "../application/symbols/SymbolRecoveryPort.js";
import { SymbolRecoveryService } from "../application/symbols/SymbolRecoveryService.js";
import { createSymbolRecoveryProvider } from "../composition/symbols.js";
import { registerSymbolTools } from "./registerSymbolTools.js";
import type { DotnetDecompilerPort } from "../application/manageddecomp/DotnetDecompilerPort.js";
import { DotnetDecompilerService } from "../application/manageddecomp/DotnetDecompilerService.js";
import { createDotnetDecompilerProvider } from "../composition/manageddecomp.js";
import { registerDotnetDecompilerTool } from "./registerDotnetDecompilerTool.js";
import type { PythonDecompilerPort } from "../application/pysrc/PythonDecompilerPort.js";
import { PythonDecompilerService } from "../application/pysrc/PythonDecompilerService.js";
import { createPythonDecompilerProvider } from "../composition/pysrc.js";
import { registerPythonDecompilerTool } from "./registerPythonDecompilerTool.js";
import type { JvmDecompilerPort } from "../application/jvmdecomp/JvmDecompilerPort.js";
import { JvmDecompilerService } from "../application/jvmdecomp/JvmDecompilerService.js";
import { createJvmDecompilerProvider } from "../composition/jvmdecomp.js";
import { registerJvmDecompilerTools } from "./registerJvmDecompilerTools.js";
import type { ProtobufRecoveryPort } from "../application/protobufrecovery/ProtobufRecoveryPort.js";
import { ProtobufRecoveryService } from "../application/protobufrecovery/ProtobufRecoveryService.js";
import { createProtobufRecoveryProvider } from "../composition/protobufrecovery.js";
import { registerProtobufRecoveryTools } from "./registerProtobufRecoveryTools.js";
import type { BindiffPort } from "../application/bindiff/BindiffPort.js";
import { BindiffExportService } from "../application/bindiff/BindiffExportService.js";
import { createBindiffProvider } from "../composition/bindiff.js";
import { registerBinexportTool } from "./registerBinexportTool.js";
import { registerIdeviceTools } from "./registerIdeviceTools.js";
import type { DiscoveryAnalysisPort } from "../application/discovery/DiscoveryPort.js";
import { DiscoveryAnalysisService } from "../application/discovery/DiscoveryAnalysisService.js";
import { createDiscoveryAnalysisProvider } from "../composition/discovery.js";
import { registerDiscoveryTools } from "./registerDiscoveryTools.js";
import { createWindowsArtifactsService } from "../composition/windowsArtifacts.js";
import type { WindowsArtifactsService } from "../application/windowsArtifacts/WindowsArtifactsService.js";
import { createNativeAotArtifactService } from "../composition/nativeAot.js";
import type { NativeAotArtifactService } from "../application/nativeAot/NativeAotArtifactService.js";
import { createGameDataService } from "../composition/gamedata.js";
import type { GameDataService } from "../gamedata/GameDataService.js";
import { createContainerInspectionService } from "../composition/containers.js";
import type { ContainerInspectionService } from "../application/containers/ContainerInspectionService.js";
import { registerWindowsArtifactsTools } from "./registerWindowsArtifactsTools.js";
import { registerNativeAotTools } from "./registerNativeAotTools.js";
import { registerGamedataTools } from "./registerGamedataTools.js";
import { registerContainersTools } from "./registerContainersTools.js";
import { registerManagedWorkflowTools } from "./registerManagedWorkflowTools.js";
import { registerOfficialTools } from "./registerOfficialTools.js";
import { registerGuidedPrompts } from "./registerPrompts.js";
import { registerSessionTools } from "./registerSessionTools.js";
import type { AvailabilityPolicy } from "../application/CapabilityInventory.js";
import { sessionAvailabilityPolicy } from "./sessionAvailabilityPolicy.js";
import {
  withAdmittedAnalysis,
  type ServerAnalysisSource,
  type WithAdmittedAnalysis,
} from "./analysisAdmission.js";
import { createReverseEngineeringService } from "../composition/reverseEngineering.js";
import { registerReverseEngineeringTools } from "./registerReverseEngineeringTools.js";
import { CutterBridgeClient } from "../cutter/CutterBridgeClient.js";
import { CutterBridgeService } from "../cutter/CutterBridgeService.js";
import { registerCutterTools } from "./registerCutterTools.js";
import { GdbSessionManager } from "../gdb/GdbSessionManager.js";
import { createLabVmService } from "../composition/vmlab.js";
import { createCrashTriageService } from "../composition/crashTriage.js";
import type { CrashTriagePort } from "../application/crashTriage/CrashTriagePort.js";
import { registerCrashTriageTools } from "./registerCrashTriageTools.js";
import {
  createFuzzingCampaignService,
  fuzzingCampaignLaneEnabled,
} from "../composition/fuzzing.js";
import type { FuzzingCampaignPort } from "../application/fuzzing/FuzzingCampaignPort.js";
import { registerFuzzingTools } from "./registerFuzzingTools.js";
import type { ReplayPort } from "../application/replay/ReplayPort.js";
import type { MitmInterceptionPort } from "../application/mitm/MitmInterceptionPort.js";
import {
  createReplayService,
  replayAllowedOriginsConfigured,
} from "../composition/replay.js";
import { registerReplayTools } from "./registerReplayTools.js";
import {
  createMitmInterceptionService,
  mitmInterceptionLaneEnabled,
} from "../composition/mitm.js";
import { registerMitmTools } from "./registerMitmTools.js";
import type { LabVmPort } from "../application/vmlab/LabVmPort.js";
import { registerGdbTools } from "./registerGdbTools.js";
import { RizinDebugSessionManager } from "../rizin/RizinDebugSessionManager.js";
import { registerRizinDebugTools } from "./registerRizinDebugTools.js";

const TARGET_FREE_INSTRUCTIONS =
  "REA provides reverse-engineering tools for local artifacts, native binaries, managed code, browser pages, and runtimes. Use the tool that directly answers the question; discover targets or inspect inventory only when needed. Tool results include inline Evidence and report their coverage and limitations. An opened target persists across turns. When finished, export needed Evidence and call close_binary; its snapshot_path can retain analysis.";

const ACTIVE_TARGET_INSTRUCTIONS =
  "REA analyzes the active reverse-engineering target. Use the analysis tool that answers the question directly. Search or list symbols when discovery is needed; analyze_function provides a function dossier, and focused procedure tools return individual facets.";

export interface CreateServerOptions {
  readonly analysisSettings?: AnalysisSettings;
  /** Preserve the connection's creation time when materializing its runtime. */
  readonly startedAt?: string;
  /** Existing SDK server whose deferred registrations are being materialized. */
  readonly mcpServer?: EvidenceMcpServer;
  readonly environment?: Readonly<NodeJS.ProcessEnv>;
  readonly delivery?: ToolResultDelivery;
  readonly packetCapture?: PacketCaptureService;
  readonly signalRecording?: SignalRecordingService;
  readonly wasmArtifact?: WasmArtifactService;
  readonly apkSignature?: ApkSignatureService;
  readonly providerEnvironment?: Readonly<NodeJS.ProcessEnv>;
  readonly evmInterface?: EvmInterfaceService;
  readonly sqliteDatabase?: SqliteDatabaseService;
  readonly logger?: Logger;
  readonly binaryLayout?: BinaryLayoutService;
  readonly goBinary?: GoBinaryService;
  readonly il2cppMetadata?: Il2cppMetadataService;
  readonly rustBinary?: RustBinaryService;
  readonly rustSymbols?: RustSymbolsService;
  readonly pythonPyc?: PythonPycService;
  readonly erlangBeam?: BeamService;
  readonly electronFuses?: ElectronFuseService;
  readonly asarIntegrity?: AsarIntegrityService;
  readonly v8Bytecode?: V8BytecodePort;
  readonly recordedCrash?: RecordedCrashService;
  readonly firmwareAnalysis?: FirmwareAnalysisPort;
  readonly javascriptRecovery?: JavaScriptRecoveryPort;
  readonly webModuleTrace?: WebModuleTraceService;
  readonly webSourceLocation?: WebSourceLocationService;
  readonly webRuntime?: WebRuntimeService;
  readonly webNetworkCapture?: WebNetworkCaptureService;
  readonly androidAnalysis?: AndroidAnalysisPort;
  readonly apktoolAnalysis?: ApktoolResourceAnalysisPort;
  readonly pcapAnalysis?: PcapAnalysisPort;
  readonly flutterAnalysis?: FlutterBuildAnalysisPort;
  readonly jebAnalysis?: JebAnalysisPort;
  readonly adbDeviceAnalysis?: AdbDeviceAnalysisPort;
  readonly ideviceDeviceAnalysis?: IdeviceAnalysisPort;
  readonly ipswAnalysis?: IpswAnalysisPort;
  readonly capaAnalysis?: CapaAnalysisPort;
  readonly yaraAnalysis?: YaraAnalysisPort;
  readonly symbolRecovery?: SymbolRecoveryPort;
  readonly dotnetDecompiler?: DotnetDecompilerPort;
  readonly pythonDecompiler?: PythonDecompilerPort;
  readonly jvmDecompiler?: JvmDecompilerPort;
  readonly protobufRecovery?: ProtobufRecoveryPort;
  readonly bindiff?: BindiffPort;
  /** Caller-supplied Lima lab-VM lane; omitted means the lane is selected from the environment. */
  readonly labVm?: LabVmPort;
  readonly crashTriage?: CrashTriagePort;
  /** Fuzz loop over registered campaigns; omitted means the lane is selected from the environment. */
  readonly fuzzing?: FuzzingCampaignPort;
  /** Active request plane; omitted means the lane is selected from the environment. */
  readonly replay?: ReplayPort;
  /** mitmproxy interception lane; omitted means the lane is selected from the environment. */
  readonly mitm?: MitmInterceptionPort;
  readonly discoveryAnalysis?: DiscoveryAnalysisPort;
  readonly windowsArtifacts?: WindowsArtifactsService;
  readonly nativeAot?: NativeAotArtifactService;
  readonly gameData?: GameDataService;
  readonly containerInspection?: ContainerInspectionService;
  readonly browserObservation?: BrowserObservationPort;
  readonly browserScenarioCapture?: BrowserScenarioCapturePort;
  readonly electronObservation?: ElectronObservationPort;
  /** Selects who closes the shared optional observation providers. */
  readonly optionalObservationProviderOwner?: "server" | "caller";
  readonly electronActiveObservation?: ElectronActiveObservationPort;
  readonly javascriptRuntimeObservation?: JavaScriptRuntimeObservationPort;
  readonly fridaInstrumentation?: FridaInstrumentationPort;
  readonly availabilityPolicy?: () => AvailabilityPolicy;
  readonly optionalProviderLoadFailures?: OptionalProviderLoadFailures;
}

/** Apply the shared TShark selection rule without starting the tool. */
const tsharkLocatable = (environment: Readonly<NodeJS.ProcessEnv>): boolean => {
  try {
    return (
      locateWiresharkTool(
        selectWiresharkTool(environment, "tshark"),
        environment,
      ) !== undefined
    );
  } catch {
    // A relative REA_TSHARK_COMMAND is configuration the tool reports at execution.
    return false;
  }
};

const installSessionToolAvailability = (
  session: BinarySessionPort | undefined,
  options: CreateServerOptions,
  environment: Readonly<NodeJS.ProcessEnv>,
  fridaInstrumentation: FridaInstrumentationPort,
) => {
  if (session === undefined) return undefined;
  const { platform, arch } = process;
  // Each provider owns its verified host; discovery and execution share it.
  const verifiedHost = {
    packetCapture: tsharkHostSupported(platform),
    pcapCapture: pcapCaptureHostSupported(platform),
    signalRecording: sigrokHostSupported(platform),
    evmInterface: evmHostSupported(platform, arch),
    pwntools: pwntoolsHostSupported(platform, arch),
    firmware: firmwareHostSupported(platform),
    javascriptRecovery: wakaruHostSupported(platform, arch),
  };
  const pwntools =
    verifiedHost.pwntools && isAbsolute(environment.REA_PWNTOOLS_PYTHON ?? "");
  // Injected services own their availability on any host. Otherwise no
  // configuration lets an integration pass its execution host check.
  const outsideVerifiedHost = (injected: unknown, supported: boolean) =>
    injected === undefined && !supported;
  const basePolicy = sessionAvailabilityPolicy(options.availabilityPolicy, {
    optionalProviderLoadFailures: options.optionalProviderLoadFailures,
    hostUnsupported: {
      pcapCapture: outsideVerifiedHost(
        options.pcapAnalysis,
        verifiedHost.pcapCapture,
      ),
      packetCapture: outsideVerifiedHost(
        options.packetCapture,
        verifiedHost.packetCapture,
      ),
      signalRecording: outsideVerifiedHost(
        options.signalRecording,
        verifiedHost.signalRecording,
      ),
      evmInterface: outsideVerifiedHost(
        options.evmInterface,
        verifiedHost.evmInterface,
      ),
      binaryLayout: outsideVerifiedHost(
        options.binaryLayout,
        verifiedHost.pwntools,
      ),
      recordedCrash: outsideVerifiedHost(
        options.recordedCrash,
        verifiedHost.pwntools,
      ),
      firmwareInspection: outsideVerifiedHost(
        options.firmwareAnalysis,
        verifiedHost.firmware,
      ),
      firmwareExtraction: outsideVerifiedHost(
        options.firmwareAnalysis,
        verifiedHost.firmware,
      ),
      javascriptRecovery: outsideVerifiedHost(
        options.javascriptRecovery,
        verifiedHost.javascriptRecovery,
      ),
    },
    optionalFeatures: {
      packetCaptureEnabled:
        options.packetCapture !== undefined ||
        (verifiedHost.packetCapture && tsharkLocatable(environment)),
      signalRecordingEnabled:
        options.signalRecording !== undefined ||
        (verifiedHost.signalRecording &&
          isAbsolute(environment.REA_SIGROK_COMMAND ?? "")),
      wasmArtifactEnabled:
        options.wasmArtifact !== undefined ||
        isAbsolute(environment.REA_WABT_BIN_DIRECTORY ?? ""),
      evmInterfaceEnabled:
        options.evmInterface !== undefined || verifiedHost.evmInterface,
      webModuleResolutionEnabled:
        options.webModuleTrace !== undefined ||
        isAbsolute(environment.REA_BROWSER_EXECUTABLE ?? ""),
      recordedCrashEnabled: options.recordedCrash !== undefined || pwntools,
      binaryLayoutEnabled: options.binaryLayout !== undefined || pwntools,
      firmwareInspectionEnabled:
        options.firmwareAnalysis !== undefined ||
        (verifiedHost.firmware &&
          isAbsolute(environment.REA_BINWALK_COMMAND ?? "")),
      firmwareExtractionEnabled:
        options.firmwareAnalysis !== undefined ||
        (verifiedHost.firmware &&
          isAbsolute(environment.REA_UNBLOB_COMMAND ?? "")),
      browserObservationEnabled: options.browserObservation !== undefined,
      javascriptRecoveryEnabled:
        options.javascriptRecovery !== undefined ||
        (verifiedHost.javascriptRecovery &&
          isAbsolute(environment.REA_WAKARU_COMMAND ?? "")),
      browserScenarioEnabled: options.browserScenarioCapture !== undefined,
      electronObservationEnabled: options.electronObservation !== undefined,
      electronAutomationEnabled:
        options.electronActiveObservation !== undefined,
      v8InspectorObservationEnabled:
        options.javascriptRuntimeObservation !== undefined,
      replayEnabled: replayAllowedOriginsConfigured(environment),
      mitmInterceptionEnabled: mitmInterceptionLaneEnabled(
        environment,
        options.mitm !== undefined,
      ),
      fuzzingCampaignEnabled: fuzzingCampaignLaneEnabled(
        environment,
        options.fuzzing !== undefined,
      ),
    },
  });
  const policy = (): AvailabilityPolicy => {
    const value = basePolicy();
    const fridaFailure =
      options.optionalProviderLoadFailures?.fridaInstrumentation ??
      fridaInstrumentation.availabilityFailure?.();
    return fridaFailure === undefined
      ? value
      : {
          ...value,
          optionalProviderLoadFailures: {
            ...value.optionalProviderLoadFailures,
            fridaInstrumentation: fridaFailure,
          },
        };
  };
  return {
    policy,
    ...(options.evmInterface !== undefined || !verifiedHost.evmInterface
      ? {}
      : {
          evmLimiterAvailability: (signal: AbortSignal) =>
            evmLimiterAvailability(environment, { signal }),
        }),
  };
};

const createMcpServer = (
  session: BinarySessionPort | undefined,
  delivery: ToolResultDelivery,
  compactPresentation: CompactInputSchemaPresentation | undefined,
  omitOutputSchemas: boolean,
): EvidenceMcpServer =>
  new EvidenceMcpServer(
    {
      name: PRODUCT_IDENTITY.mcpServerKey,
      version: PRODUCT_IDENTITY.packageVersion,
    },
    {
      capabilities: {},
      instructions: `${
        session === undefined
          ? ACTIVE_TARGET_INSTRUCTIONS
          : TARGET_FREE_INSTRUCTIONS
      } ${RECOVERY_INSTRUCTIONS} ${UNTRUSTED_CONTENT_INSTRUCTIONS}`,
    },
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    delivery,
    compactPresentation,
    omitOutputSchemas,
    createCatalogIdentity(
      compactPresentation,
      omitOutputSchemas ? "off" : "full",
    ),
  );

/**
 * Construct one MCP server without acquiring subprocess resources.
 * Supplying a session adds target lifecycle tools; omitting it retains the
 * fixed-target seam used by focused tests and embedders.
 */
export const createServer = (
  source: ServerAnalysisSource,
  options: CreateServerOptions = {},
): EvidenceMcpServer => {
  const session = source.kind === "session" ? source.session : undefined;
  const analysis = source.kind === "session" ? source.session : source.analysis;
  const environment = snapshotEnvironment(options.environment ?? process.env);
  const analysisSettings =
    options.analysisSettings ?? new AnalysisSettings(environment);
  const omitOutputSchemas = outputSchemasOmitted(environment);
  const providerEnvironment = captureProviderEnvironment(
    options.providerEnvironment,
    environment,
  );
  const delivery = selectToolResultDelivery(environment, options.delivery);
  const evmInterface =
    options.evmInterface ?? evmInterfaceModule.create(environment);
  const sqliteDatabase =
    options.sqliteDatabase ?? createSqliteDatabaseService(environment);
  const binaryLayout =
    options.binaryLayout ?? createBinaryLayoutService(environment);
  const recordedCrash =
    options.recordedCrash ?? createRecordedCrashService(environment);
  const webSourceLocation =
    options.webSourceLocation ?? createWebSourceLocationService(environment);
  const webModuleTrace =
    options.webModuleTrace ?? createWebModuleTraceService(environment);
  const desktopApplication = createDesktopApplicationService();
  const goBinary = options.goBinary ?? createGoBinaryService();
  const rustBinary = options.rustBinary ?? createRustBinaryService();
  const rustSymbols = options.rustSymbols ?? createRustSymbolsService();
  const erlangBeam = options.erlangBeam ?? createBeamService();
  const modelArtifact = createModelArtifactService();
  const gpuCodeObjects = createGpuCodeObjectsService();
  const il2cppMetadata =
    options.il2cppMetadata ?? createIl2cppMetadataService();
  const peResources = createPeResourcesService();
  const nativeExports = createNativeExportsService();
  const devicetree = createDevicetreeService();
  const elfNotes = createElfNotesService();
  const appleIps = createAppleIpsService();
  const kernelModule = createKernelModuleService();
  const peLoadConfig = createPeLoadConfigService();
  const peCertificates = createPeCertificatesService();
  const peImports = createPeImportsService();
  const electronFuses = options.electronFuses ?? createElectronFuseService();
  const asarIntegrity =
    options.asarIntegrity ??
    new AsarIntegrityService(createAsarIntegrityProvider(environment));
  const v8Bytecode =
    options.v8Bytecode ?? createV8BytecodeProvider(environment);
  const pythonPyc = options.pythonPyc ?? createPythonPycService();
  const webNetworkCapture =
    options.webNetworkCapture ??
    createWebNetworkCaptureService(environment, analysisSettings.read);
  const javascriptRecovery =
    options.javascriptRecovery ?? createJavaScriptRecoveryProvider(environment);
  const artifactResources = new ArtifactResourceScope();
  const reverseEngineering =
    createReverseEngineeringService(providerEnvironment);
  const firmwareAnalysis = new FirmwareAnalysisService(
    options.firmwareAnalysis ?? createFirmwareAnalysisProvider(environment),
  );
  const selectedOptions = {
    ...options,
    environment,
    delivery,
    evmInterface,
    sqliteDatabase,
    binaryLayout,
    recordedCrash,
    webSourceLocation,
    webModuleTrace,
    javascriptRecovery,
  };
  const startedAt = options.startedAt ?? new Date().toISOString();
  const logger = options.logger ?? silentLogger;
  const server =
    options.mcpServer ??
    createMcpServer(
      session,
      delivery,
      selectCompactInputSchemaPresentation(environment),
      omitOutputSchemas,
    );
  server.analysisSettings = analysisSettings;
  registerAnalysisSettingsTools(server, analysisSettings);
  if (options.mcpServer !== undefined) {
    server.attachRuntime(
      session === undefined
        ? undefined
        : (evidence) => session.recordEvidence(evidence),
      delivery,
      createCatalogIdentity(
        selectCompactInputSchemaPresentation(environment),
        omitOutputSchemas ? "off" : "full",
      ),
    );
  }
  const gdbSessions = new GdbSessionManager({
    environment: providerEnvironment,
  });
  const rizinDebugSessions = new RizinDebugSessionManager(providerEnvironment);
  const android =
    options.androidAnalysis ??
    createAndroidAnalysisProvider(
      environment,
      undefined,
      analysisSettings.read,
    );
  const pcap = options.pcapAnalysis ?? createPcapAnalysisProvider(environment);
  const flutter =
    options.flutterAnalysis ?? createFlutterBuildAnalysisProvider();
  const fridaInstrumentation =
    options.fridaInstrumentation ?? new FridaInstrumentationManager();
  const wasmArtifact = wasmArtifactModule.create(
    environment,
    options.wasmArtifact,
    analysisSettings.read,
  );
  const apkSignature = apkSignatureModule.create(
    environment,
    options.apkSignature,
  );
  const packetCapture =
    options.packetCapture ?? createPacketCaptureService(environment);
  const signalRecording =
    options.signalRecording ?? createSignalRecordingService(environment);
  const webRuntime = options.webRuntime ?? createWebRuntimeService();
  const apktool =
    options.apktoolAnalysis ??
    createApktoolResourceAnalysisProvider(environment);
  const jeb = options.jebAnalysis ?? createJebAnalysisProvider(environment);
  const adbDevice =
    options.adbDeviceAnalysis ?? createAdbDeviceAnalysisProvider(environment);
  const idevice =
    options.ideviceDeviceAnalysis ?? createIdeviceAnalysisProvider(environment);
  const ipsw = options.ipswAnalysis ?? createIpswAnalysisProvider(environment);
  const capa = options.capaAnalysis ?? createCapaAnalysisProvider(environment);
  const yara = options.yaraAnalysis ?? createYaraAnalysisProvider(environment);
  const symbolRecovery =
    options.symbolRecovery ?? createSymbolRecoveryProvider(environment);
  const dotnetDecompiler =
    options.dotnetDecompiler ?? createDotnetDecompilerProvider(environment);
  const pythonDecompiler =
    options.pythonDecompiler ?? createPythonDecompilerProvider(environment);
  const jvmDecompiler =
    options.jvmDecompiler ?? createJvmDecompilerProvider(environment);
  const protobufRecovery =
    options.protobufRecovery ?? createProtobufRecoveryProvider(environment);
  const bindiff = options.bindiff ?? createBindiffProvider(environment);
  const labVm = options.labVm ?? createLabVmService(environment);
  const crashTriage =
    options.crashTriage ?? createCrashTriageService(environment);
  const fuzzing =
    options.fuzzing ??
    createFuzzingCampaignService(
      providerEnvironment,
      crashTriage,
      labVm,
      analysisSettings.read,
    );
  const replay = options.replay ?? createReplayService(environment);
  const mitm = options.mitm ?? createMitmInterceptionService(environment);
  const discovery =
    options.discoveryAnalysis ?? createDiscoveryAnalysisProvider(environment);
  const windowsArtifacts =
    options.windowsArtifacts ?? createWindowsArtifactsService(environment);
  const nativeAot = options.nativeAot ?? createNativeAotArtifactService();
  const gameData = options.gameData ?? createGameDataService();
  const containerInspection =
    options.containerInspection ?? createContainerInspectionService();
  const cutter = new CutterBridgeService(
    new CutterBridgeClient(providerEnvironment),
  );
  let providerClose: Promise<void> | undefined;
  const closeProviders = (): Promise<void> => {
    providerClose ??= Promise.allSettled([
      android.close(),
      cutter.close(),
      fridaInstrumentation.closeAll(),
      wasmArtifact.close(),
      apkSignature.close(),
      packetCapture.close(),
      signalRecording.close(),
      apktool.close(),
      jeb.close(),
      adbDevice.close(),
      idevice.close(),
      ipsw.close(),
      capa.close(),
      yara.close(),
      symbolRecovery.close(),
      dotnetDecompiler.close(),
      pythonDecompiler.close(),
      jvmDecompiler.close(),
      protobufRecovery.close(),
      bindiff.close(),
      labVm.closeAll().then((closed) => {
        if (!closed.ok) throw closed.error;
      }),
      crashTriage.closeAll().then((closed) => {
        if (!closed.ok) throw closed.error;
      }),
      fuzzing.closeAll().then((closed) => {
        if (!closed.ok) throw closed.error;
      }),
      replay.closeAll().then((closed) => {
        if (!closed.ok) throw closed.error;
      }),
      mitm.closeAll().then((closed) => {
        if (!closed.ok) throw closed.error;
      }),
      discovery.close(),
      windowsArtifacts.close(),
      nativeAot.close(),
      gameData.close(),
      containerInspection.close(),
      flutter.close(),
      pcap.close(),
      evmInterface.close(),
      sqliteDatabase.close(),
      binaryLayout.close(),
      recordedCrash.close(),
      webSourceLocation.close(),
      webModuleTrace.close(),
      desktopApplication.close(),
      goBinary.close(),
      rustBinary.close(),
      rustSymbols.close(),
      erlangBeam.close(),
      il2cppMetadata.close(),
      modelArtifact.close(),
      gpuCodeObjects.close(),
      peResources.close(),
      nativeExports.close(),
      devicetree.close(),
      elfNotes.close(),
      appleIps.close(),
      kernelModule.close(),
      peLoadConfig.close(),
      peCertificates.close(),
      peImports.close(),
      electronFuses.close(),
      asarIntegrity.close(),
      v8Bytecode.close(),
      pythonPyc.close(),
      webNetworkCapture.close(),
      javascriptRecovery.close?.() ?? Promise.resolve(),
      ...(options.optionalObservationProviderOwner === "caller"
        ? []
        : [
            options.browserObservation?.close?.() ?? Promise.resolve(),
            options.browserScenarioCapture?.close?.() ?? Promise.resolve(),
            options.electronObservation?.close?.() ?? Promise.resolve(),
            options.electronActiveObservation?.close?.() ?? Promise.resolve(),
            options.javascriptRuntimeObservation?.close?.() ??
              Promise.resolve(),
          ]),
      webRuntime.provider.close?.() ?? Promise.resolve(),
      artifactResources.close(),
      reverseEngineering.close(),
      firmwareAnalysis.close(),
      gdbSessions.closeAll(),
      rizinDebugSessions.closeAll(),
    ])
      .then((results) => {
        const failures = results.flatMap((result) =>
          result.status === "rejected" ? [result.reason] : [],
        );
        if (failures.length > 0)
          throw new AggregateError(failures, "REA provider cleanup failed");
      })
      .catch((cause: unknown) => {
        providerClose = undefined;
        throw cause;
      });
    return providerClose;
  };
  const availability = installSessionToolAvailability(
    session,
    options,
    environment,
    fridaInstrumentation,
  );
  const toolLogger = logger.child({ layer: "server" });
  const {
    evidenceById,
    activeTarget,
    recordEvidence,
    recordEvidenceWithUnknown,
  } = createSessionRecorders(server, session);
  const analysisAdmission = withAdmittedAnalysis(source);
  const toolContext: ServerToolContext = {
    server,
    session,
    options: selectedOptions,
    environment,
    logger: toolLogger,
    evidenceById,
    activeTarget,
    recordEvidence,
    recordEvidenceWithUnknown,
    withAdmittedAnalysis: analysisAdmission,
    artifactResources,
    goBinary,
    rustBinary,
    rustSymbols,
    erlangBeam,
    il2cppMetadata,
    peResources,
    nativeExports,
    devicetree,
    elfNotes,
    appleIps,
    kernelModule,
    peLoadConfig,
    peCertificates,
    peImports,
    electronFuses,
    asarIntegrity,
    v8Bytecode,
    pythonPyc,
    webNetworkCapture,
  };
  registerDesktopApplicationTool(
    server,
    desktopApplication,
    toolLogger,
    recordEvidence,
    analysisAdmission,
    evidenceById,
  );
  registerModelArtifactTools(
    server,
    modelArtifact,
    toolLogger,
    recordEvidence,
    analysisAdmission,
    evidenceById,
  );
  registerGpuCodeObjectsTools(
    server,
    gpuCodeObjects,
    toolLogger,
    recordEvidence,
    analysisAdmission,
    evidenceById,
  );
  registerBinaryAnalysisTools(toolContext);
  registerReverseEngineeringTools(
    server,
    reverseEngineering,
    toolLogger,
    delivery,
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    analysisAdmission,
    session === undefined
      ? undefined
      : () => session.invalidateSnapshotForExternalMutation(),
    session === undefined
      ? undefined
      : (path, signal, operation, rebindFailure) =>
          session.withAdmittedExternalMutation(
            path,
            signal,
            operation,
            rebindFailure,
          ),
    evidenceById,
  );
  registerFridaTools(
    server,
    fridaInstrumentation,
    toolLogger,
    delivery,
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    evidenceById,
  );
  registerCutterTools(
    server,
    cutter,
    toolLogger,
    delivery,
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    session,
  );
  registerGdbTools(
    server,
    gdbSessions,
    toolLogger,
    delivery,
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    session,
    evidenceById,
  );
  registerRizinDebugTools(
    server,
    rizinDebugSessions,
    toolLogger,
    delivery,
    session === undefined
      ? undefined
      : (evidence) => session.recordEvidence(evidence),
    session,
  );
  const previousOnclose = server.server.onclose;
  server.server.onclose = () => {
    previousOnclose?.();
    void closeProviders().catch((cause: unknown) => {
      logger.error(
        { error: cause instanceof Error ? cause.message : String(cause) },
        "Provider cleanup failed during server shutdown",
      );
    });
  };
  const closeServer = server.close.bind(server);
  server.close = async () => {
    const results = await Promise.allSettled([closeServer(), closeProviders()]);
    for (const result of results)
      if (result.status === "rejected") throw result.reason;
  };
  registerCaptureTools(
    server,
    packetCapture,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerSignalTools(
    server,
    signalRecording,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerConfiguredAnalysisTools(
    toolContext,
    android,
    wasmArtifact,
    apkSignature,
    evmInterface,
    jeb,
    firmwareAnalysis,
    webRuntime,
  );
  registerAdbTools(
    server,
    new AdbDeviceAnalysisService(adbDevice),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerIdeviceTools(
    server,
    new IdeviceAnalysisService(idevice),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerIpswTools(
    server,
    new IpswAnalysisService(ipsw),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerCapaTools(
    server,
    new CapaAnalysisService(capa),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerYaraTools(
    server,
    new YaraAnalysisService(yara),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerSymbolTools(
    server,
    new SymbolRecoveryService(symbolRecovery),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerDotnetDecompilerTool(
    server,
    new DotnetDecompilerService(dotnetDecompiler),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerPythonDecompilerTool(
    server,
    new PythonDecompilerService(pythonDecompiler),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerJvmDecompilerTools(
    server,
    new JvmDecompilerService(jvmDecompiler),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerProtobufRecoveryTools(
    server,
    new ProtobufRecoveryService(protobufRecovery),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerBinexportTool(
    server,
    new BindiffExportService(bindiff),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerDiscoveryTools(
    server,
    new DiscoveryAnalysisService(discovery),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerWindowsArtifactsTools(
    server,
    windowsArtifacts,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerNativeAotTools(
    server,
    nativeAot,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerGamedataTools(
    server,
    gameData,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerContainersTools(
    server,
    containerInspection,
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerPcapTools(
    server,
    new PcapAnalysisService(pcap),
    toolLogger,
    recordEvidence,
    analysisAdmission,
    evidenceById,
  );
  registerFlutterTools(
    server,
    new FlutterBuildAnalysisService(flutter),
    toolLogger,
    recordEvidence,
    analysisAdmission,
    evidenceById,
  );
  registerApktoolTools(
    server,
    new ApktoolResourceAnalysisService(apktool),
    toolLogger,
    recordEvidence,
    analysisAdmission,
  );
  registerObservationTools(toolContext);
  registerCrashTriageTools({
    server,
    crashTriage,
    logger: toolLogger,
    recordEvidence,
  });
  registerFuzzingTools({
    server,
    fuzzing,
    logger: toolLogger,
    recordEvidence,
  });
  registerReplayTools({
    server,
    replay,
    logger: toolLogger,
    recordEvidence,
  });
  registerMitmTools({
    server,
    mitm,
    logger: toolLogger,
    recordEvidence,
  });
  registerGuidedPrompts(server, analysis, session);
  if (session !== undefined) {
    registerSessionTools(server, session, toolLogger, {
      ...selectedOptions,
      artifactResources,
      bindiff,
      labVm,
      ...(availability === undefined
        ? {}
        : { availabilityPolicy: availability.policy }),
      ...(availability?.evmLimiterAvailability === undefined
        ? {}
        : { evmLimiterAvailability: availability.evmLimiterAvailability }),
      androidAnalysisAvailability: (signal) =>
        android.inspectAvailability(signal),
      adbAnalysisAvailability: (signal) =>
        adbDevice.inspectAvailability(signal),
      ipswAnalysisAvailability: (signal) => ipsw.inspectAvailability(signal),
      capaAnalysisAvailability: (signal) => capa.inspectAvailability(signal),
      yaraAnalysisAvailability: (signal) => yara.inspectAvailability(signal),
      goresymAnalysisAvailability: (signal) =>
        symbolRecovery.inspectToolAvailability?.(
          "recover_go_symbols",
          signal,
        ) ?? symbolRecovery.inspectAvailability(signal),
      rustfiltAnalysisAvailability: (signal) =>
        symbolRecovery.inspectToolAvailability?.(
          "demangle_rust_name",
          signal,
        ) ?? symbolRecovery.inspectAvailability(signal),
      dumpSymsAnalysisAvailability: (signal) =>
        symbolRecovery.inspectToolAvailability?.(
          "generate_symbol_table",
          signal,
        ) ?? symbolRecovery.inspectAvailability(signal),
      dotnetDecompilerAvailability: (signal) =>
        dotnetDecompiler.inspectAvailability(signal),
      pythonDecompilerAvailability: (signal) =>
        pythonDecompiler.inspectAvailability(signal),
      jvmDecompilerAvailability: (signal) =>
        jvmDecompiler.inspectAvailability(signal),
      v8BytecodeAvailability: (signal) =>
        v8Bytecode.inspectAvailability(signal),
      protobufRecoveryAvailability: (signal) =>
        protobufRecovery.inspectRecoveryAvailability?.(signal) ??
        protobufRecovery.inspectAvailability(signal),
      grpcReflectionAvailability: (signal) =>
        protobufRecovery.inspectReflectionAvailability?.(signal) ??
        protobufRecovery.inspectAvailability(signal),
      bindiffDiffAvailability: (signal) =>
        bindiff.inspectDiffAvailability?.(signal) ??
        bindiff.inspectAvailability(signal),
      bindiffExportAvailability: (signal) =>
        bindiff.inspectExportAvailability?.(signal) ??
        bindiff.inspectAvailability(signal),
      apktoolAnalysisAvailability: (signal) =>
        apktool.inspectAvailability(signal),
      jebAnalysisAvailability: (signal) => jeb.inspectAvailability(signal),
      labVmAvailability: (signal) => labVm.inspectAvailability(signal),
      startedAt,
    });
  }
  return server;
};

const selectToolResultDelivery = (
  environment: Readonly<NodeJS.ProcessEnv>,
  selected: ToolResultDelivery | undefined,
): ToolResultDelivery => {
  if (selected !== undefined) return selected;
  const configured = parseMcpResponseBudget(
    environment.REA_MCP_MAX_RESPONSE_BYTES,
  );
  if (!configured.ok) throw configured.error;
  return createToolResultDelivery(configured.value);
};

const outputSchemasOmitted = (
  environment: Readonly<NodeJS.ProcessEnv>,
): boolean => {
  const configured = parseMcpOutputSchemaProfile(
    environment.REA_MCP_OUTPUT_SCHEMA_PROFILE,
  );
  if (!configured.ok) throw configured.error;
  return configured.value === "off";
};

const selectCompactInputSchemaPresentation = (
  environment: Readonly<NodeJS.ProcessEnv>,
): CompactInputSchemaPresentation | undefined => {
  const configured = parseMcpInputSchemaProfile(
    environment.REA_MCP_INPUT_SCHEMA_PROFILE,
  );
  if (!configured.ok) throw configured.error;
  return compactPresentationForMcpInputSchemaProfile(configured.value);
};

const registerConfiguredAnalysisTools = (
  {
    server,
    options,
    environment,
    logger: toolLogger,
    evidenceById,
    recordEvidence,
    withAdmittedAnalysis,
    goBinary,
    rustBinary,
    rustSymbols,
    erlangBeam,
    il2cppMetadata,
    peResources,
    nativeExports,
    devicetree,
    elfNotes,
    appleIps,
    kernelModule,
    peLoadConfig,
    peCertificates,
    peImports,
    pythonPyc,
    webNetworkCapture,
    artifactResources,
  }: ServerToolContext,
  android: AndroidAnalysisPort,
  wasmArtifact: Pick<WasmArtifactService, "inspect" | "close">,
  apkSignature: Pick<ApkSignatureService, "inspect" | "close">,
  evmInterface: EvmInterfaceService,
  jeb: JebAnalysisPort,
  firmwareAnalysis: FirmwareAnalysisService,
  webRuntime: WebRuntimeService,
): void => {
  registerAndroidTools(
    server,
    new AndroidAnalysisService(android, recordEvidence),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerJebTools(
    server,
    new JebAnalysisService(jeb),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerBinaryDiagnosticsTools(
    server,
    options.binaryLayout ?? createBinaryLayoutService(environment),
    createByteEntropyService(artifactResources),
    toolLogger,
    recordEvidence,
    evidenceById,
    withAdmittedAnalysis,
  );
  registerAnalysisViewTool(
    server,
    toolLogger,
    evidenceById,
    recordEvidence,
    withAdmittedAnalysis,
    artifactResources,
  );
  registerPeResourcesTool(
    server,
    peResources,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerNativeExportsTool(
    server,
    nativeExports,
    toolLogger,
    recordEvidence,
    evidenceById,
    withAdmittedAnalysis,
  );
  registerDevicetreeTool(
    server,
    devicetree,
    toolLogger,
    recordEvidence,
    evidenceById,
    withAdmittedAnalysis,
  );
  registerElfNotesTool(
    server,
    elfNotes,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerAppleIpsTool(
    server,
    appleIps,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerKernelModuleTool(
    server,
    kernelModule,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerPeLoadConfigTool(
    server,
    peLoadConfig,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerPeCertificatesTool(
    server,
    peCertificates,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerPeImportsTool(
    server,
    peImports,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerGoTools(
    server,
    goBinary,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerIl2cppTools(
    server,
    il2cppMetadata,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerRustTools(
    server,
    rustBinary,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    rustSymbols,
    evidenceById,
  );
  registerPythonPycTool(
    server,
    pythonPyc,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerErlangTools(
    server,
    erlangBeam,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerWasmTools(
    server,
    wasmArtifact,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerApkSignatureTools(
    server,
    apkSignature,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerEvmTools(
    server,
    evmInterface,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerSqliteTools(
    server,
    options.sqliteDatabase ?? createSqliteDatabaseService(environment),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerRecordedCrashTools(
    server,
    options.recordedCrash ?? createRecordedCrashService(environment),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerFirmwareTools(
    server,
    firmwareAnalysis,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerWebModuleTool(
    server,
    options.webModuleTrace ?? createWebModuleTraceService(environment),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerWebSourceLocationTool(
    server,
    options.webSourceLocation ?? createWebSourceLocationService(environment),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerWebRuntimeTools(
    server,
    webRuntime,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerWebNetworkCaptureTool(
    server,
    webNetworkCapture,
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
    evidenceById,
  );
  registerJavaScriptRecoveryTool(
    server,
    new JavaScriptRecoveryService(
      options.javascriptRecovery ??
        createJavaScriptRecoveryProvider(environment),
    ),
    toolLogger,
    recordEvidence,
    withAdmittedAnalysis,
  );
};

const createSessionRecorders = (
  server: EvidenceMcpServer,
  session: BinarySessionPort | undefined,
) => ({
  evidenceById:
    session === undefined
      ? undefined
      : session.evidenceForAnalysis.bind(session),
  activeTarget:
    session === undefined ? undefined : () => session.activeTarget(),
  recordEvidence:
    session === undefined
      ? undefined
      : (evidence: Parameters<typeof session.recordEvidence>[0]) =>
          session.recordEvidence(evidence),
  recordEvidenceWithUnknown:
    session === undefined
      ? undefined
      : (
          evidence: Parameters<typeof session.recordEvidenceWithUnknown>[0],
          input: Parameters<typeof session.recordEvidenceWithUnknown>[1],
        ) => session.recordEvidenceWithUnknown(evidence, input),
});

interface ServerToolContext extends ReturnType<typeof createSessionRecorders> {
  readonly goBinary: GoBinaryService;
  readonly rustBinary: RustBinaryService;
  readonly rustSymbols: RustSymbolsService;
  readonly erlangBeam: BeamService;
  readonly il2cppMetadata: Il2cppMetadataService;
  readonly peResources: PeResourcesService;
  readonly nativeExports: NativeExportsService;
  readonly devicetree: DevicetreeService;
  readonly elfNotes: ElfNotesService;
  readonly appleIps: AppleIpsService;
  readonly kernelModule: KernelModuleService;
  readonly peLoadConfig: PeLoadConfigService;
  readonly peCertificates: PeCertificatesService;
  readonly peImports: PeImportsService;
  readonly electronFuses: ElectronFuseService;
  readonly asarIntegrity: AsarIntegrityService;
  readonly v8Bytecode: V8BytecodePort;
  readonly pythonPyc: PythonPycService;
  readonly webNetworkCapture: WebNetworkCaptureService;
  readonly artifactResources: ArtifactResourceScope;
  readonly server: EvidenceMcpServer;
  readonly session: BinarySessionPort | undefined;
  readonly options: CreateServerOptions;
  readonly environment: Readonly<NodeJS.ProcessEnv>;
  readonly logger: Logger;
  readonly withAdmittedAnalysis: WithAdmittedAnalysis;
}

const registerBinaryAnalysisTools = ({
  server,
  session,
  logger,
  activeTarget,
  recordEvidence,
  recordEvidenceWithUnknown,
  evidenceById,
  withAdmittedAnalysis,
}: ServerToolContext): void => {
  const recordUnknown =
    session === undefined
      ? undefined
      : (input: Parameters<typeof session.recordUnknown>[0]) =>
          session.recordUnknown(input);
  const analysisOptions = {
    logger,
    activeTarget,
    recordEvidence,
    recordUnknown,
    evidenceById,
    withAdmittedAnalysis,
  };
  registerOfficialTools(server, analysisOptions);
  registerEnhancedTools(server, {
    ...analysisOptions,
    analysisProfile:
      session === undefined
        ? undefined
        : (operation) =>
            session.analysisProfile() ?? session.analysisProfile(operation),
    allowsSnapshotReplay:
      session === undefined
        ? undefined
        : (operation) => session.allowsSnapshotReplay(operation),
    recordWorkflowSnapshot:
      session === undefined
        ? undefined
        : (input) => session.recordWorkflowSnapshot(input),
  });
  const evidenceOptions = {
    logger,
    activeTarget,
    recordEvidence,
    withAdmittedAnalysis,
  };
  registerNativeTools(server, { ...evidenceOptions, evidenceById });
  registerArtifactTools(server, { ...evidenceOptions, evidenceById });
  registerManagedTools(server, { ...evidenceOptions, evidenceById });
  if (session !== undefined)
    registerManagedWorkflowTools(server, {
      logger,
      recordEvidence,
      recordEvidenceWithUnknown,
      session,
      withAdmittedAnalysis,
    });
};

const registerObservationTools = ({
  electronFuses,
  asarIntegrity,
  v8Bytecode,
  evidenceById,
  server,
  options,
  logger,
  recordEvidence,
  recordEvidenceWithUnknown,
  withAdmittedAnalysis,
  artifactResources,
  environment,
}: ServerToolContext): void => {
  const common = { logger, recordEvidence, withAdmittedAnalysis };
  registerWebScriptTool(server, { ...common, artifactResources });
  registerBrowserTools(server, {
    ...common,
    evidenceById,
    browser: options.browserObservation,
    loadFailure: options.optionalProviderLoadFailures?.browserObservation,
  });
  registerBrowserScenarioTool(server, {
    ...common,
    provider: options.browserScenarioCapture,
    loadFailure: options.optionalProviderLoadFailures?.browserScenarioCapture,
  });
  registerElectronTools(server, {
    ...common,
    artifactResources,
    environment,
    evidenceById,
    electron: options.electronObservation,
    electronActive: options.electronActiveObservation,
    electronFuses,
    observationLoadFailure:
      options.optionalProviderLoadFailures?.electronObservation,
    activeLoadFailure:
      options.optionalProviderLoadFailures?.electronActiveObservation,
  });
  registerAsarIntegrityTool(
    server,
    asarIntegrity,
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerV8BytecodeTool(
    server,
    new V8BytecodeService(v8Bytecode),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  registerJavaScriptRuntimeObservationTools(server, {
    ...common,
    runtime: options.javascriptRuntimeObservation,
    loadFailure:
      options.optionalProviderLoadFailures?.javascriptRuntimeObservation,
  });
  registerApplicationTools(server, {
    artifactResources,
    evidenceById,
    logger,
    recordEvidence,
    recordEvidenceWithUnknown,
    withAdmittedAnalysis,
  });
};
