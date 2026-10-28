import type { JvmDecompilerPort } from "../application/jvmdecomp/JvmDecompilerPort.js";
import { JvmDecompilerProvider } from "../jvmdecomp/JvmDecompilerProvider.js";

/** Construct one JVM decompiler over the caller's Vineflower JAR and JDK. */
export const createJvmDecompilerProvider = (
  environment: Readonly<Record<string, string | undefined>> = process.env,
): JvmDecompilerPort => new JvmDecompilerProvider({ environment });
