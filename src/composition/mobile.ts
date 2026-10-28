import type { MobileToolchainPort } from "../application/mobile/MobileToolchainPort.js";
import {
  MobileToolchainProvider,
  type MobileToolchainProviderOptions,
} from "../mobile/MobileToolchainProvider.js";

/** Construct the mobile toolchain family over caller-selected launchers. */
export const createMobileToolchainProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
  options: Omit<MobileToolchainProviderOptions, "environment"> = {},
): MobileToolchainPort =>
  new MobileToolchainProvider({ environment, ...options });
