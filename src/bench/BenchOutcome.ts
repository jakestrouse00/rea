import { createHash } from "node:crypto";
import { open } from "node:fs/promises";
import { join } from "node:path";

import {
  benchGuestOutcomeSchema,
  type BenchOutcomeFacts,
  type BenchOutcomeState,
} from "../domain/bench/benchTask.js";
import {
  BENCH_LIMITS,
  BENCH_OUTCOME_RELATIVE_PATH,
} from "../domain/bench/benchLimits.js";

/** One bounded read of the guest harness outcome. */
export type BenchOutcomeRead =
  | { readonly state: "read"; readonly facts: BenchOutcomeFacts }
  | {
      readonly state: Exclude<BenchOutcomeState, "read">;
      readonly reason: string;
    };

const sha256Of = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const readBoundedOutcome = async (
  path: string,
): Promise<
  | { readonly kind: "text"; readonly text: string }
  | {
      readonly kind: "missing" | "oversized" | "unreadable";
      readonly reason: string;
    }
> => {
  let handle;
  try {
    handle = await open(path, "r");
  } catch (cause: unknown) {
    const code = (cause as NodeJS.ErrnoException).code;
    return code === "ENOENT"
      ? { kind: "missing", reason: `No outcome file was written: ${path}` }
      : {
          kind: "unreadable",
          reason: `The outcome file could not be opened: ${path}`,
        };
  }
  try {
    const buffer = Buffer.alloc(BENCH_LIMITS.maxOutcomeBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > BENCH_LIMITS.maxOutcomeBytes)
      return {
        kind: "oversized",
        reason: `The outcome file exceeds the ${String(BENCH_LIMITS.maxOutcomeBytes)}-byte budget`,
      };
    return {
      kind: "text",
      text: buffer.subarray(0, bytesRead).toString("utf8"),
    };
  } catch {
    return {
      kind: "unreadable",
      reason: `The outcome file could not be read: ${path}`,
    };
  } finally {
    await handle.close().catch(() => undefined);
  }
};

/**
 * Read one guest outcome from the mounted workspace.
 *
 * The flag value is hashed here and never leaves this function: only its
 * digest and the harness's structural facts reach the observation. Any
 * unreadable, oversized, or schema-invalid file is an unknown outcome state
 * rather than a failure of the metric.
 */
export const readBenchOutcome = async (
  workspacePath: string,
): Promise<BenchOutcomeRead> => {
  const path = join(workspacePath, BENCH_OUTCOME_RELATIVE_PATH);
  const read = await readBoundedOutcome(path);
  if (read.kind !== "text") return { state: read.kind, reason: read.reason };
  let parsed: unknown;
  try {
    parsed = JSON.parse(read.text);
  } catch {
    return {
      state: "unreadable",
      reason: `The outcome file is not valid JSON: ${path}`,
    };
  }
  const outcome = benchGuestOutcomeSchema.safeParse(parsed);
  if (!outcome.success)
    return {
      state: "unreadable",
      reason: `The outcome file does not match this release's outcome schema: ${path}`,
    };
  return {
    state: "read",
    facts: {
      status: outcome.data.status,
      recoveredFlagSha256:
        outcome.data.flag === undefined ? null : sha256Of(outcome.data.flag),
      pov:
        outcome.data.pov === undefined
          ? null
          : {
              recorded: outcome.data.pov.recorded,
              sanitizerClass: outcome.data.pov.sanitizer_class ?? null,
            },
    },
  };
};

/** Report an unreadable outcome beside the metric it leaves unknown. */
export const benchOutcomeLimitations = (
  read: BenchOutcomeRead,
): readonly string[] => (read.state === "read" ? [] : [read.reason]);
