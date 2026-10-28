import type { PythonDecompilerPort } from "../application/pysrc/PythonDecompilerPort.js";
import { PythonDecompilerProvider } from "../pysrc/PythonDecompilerProvider.js";

/** Construct one Python decompiler over the caller's selected binary. */
export const createPythonDecompilerProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): PythonDecompilerPort => new PythonDecompilerProvider({ environment });
