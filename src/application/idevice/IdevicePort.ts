import type {
  AnalysisExecution,
  ExecutionOptions,
  ProviderAvailability,
} from "../AnalysisProvider.js";
import type { IdeviceRequest } from "../../domain/idevice/ideviceDeviceAnalysis.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type { Result } from "../../domain/result.js";

/**
 * iOS device-read boundary over a caller-supplied pymobiledevice3 launcher.
 * Read-only operations only; the implementation details belong to the provider
 * adapter. Unpaired devices are an empty inventory, not an error.
 */
export interface IdeviceAnalysisPort {
  /** Probe the selected launcher without contacting usbmuxd or devices. */
  inspectAvailability(signal?: AbortSignal): Promise<ProviderAvailability>;
  /** Terminally stop admission and release owned staging resources. */
  close(): Promise<void>;
  execute(
    request: IdeviceRequest,
    options?: ExecutionOptions,
  ): Promise<Result<AnalysisExecution, AnalysisError>>;
}
