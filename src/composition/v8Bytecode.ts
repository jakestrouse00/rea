import type { V8BytecodePort } from "../application/javascript/V8BytecodePort.js";
import { View8Provider } from "../javascript/v8/View8Provider.js";

/** Construct one V8 disassembly provider over the caller's selected View8 build. */
export const createV8BytecodeProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): V8BytecodePort => new View8Provider({ environment });
