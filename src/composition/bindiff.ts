import type { BindiffPort } from "../application/bindiff/BindiffPort.js";
import { BindiffProvider } from "../bindiff/BindiffProvider.js";

/** Construct one BinDiff provider over the caller's adapter and exporter. */
export const createBindiffProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): BindiffPort => new BindiffProvider({ environment });
