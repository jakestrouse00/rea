import type { DotnetDecompilerPort } from "../application/manageddecomp/DotnetDecompilerPort.js";
import { DotnetDecompilerProvider } from "../manageddecomp/DotnetDecompilerProvider.js";

/** Construct one .NET decompiler over the caller's ilspycmd binary. */
export const createDotnetDecompilerProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): DotnetDecompilerPort => new DotnetDecompilerProvider({ environment });
