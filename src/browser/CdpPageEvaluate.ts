import { createHash } from "node:crypto";

import type { ProgressReporter } from "../application/ProgressReporter.js";
import {
  BROWSER_EVALUATE_OUTCOMES,
  BROWSER_EVALUATE_SIDE_EFFECT_LIMITATION,
  BROWSER_EVALUATE_TEXT_LIMITATION,
  browserEvaluateResultSchema,
  type BrowserEvaluateInput,
  type BrowserEvaluateResult,
} from "../domain/browserMutation.js";
import { BROWSER_MUTATION_LIMITS } from "../domain/browserMutationLimits.js";
import { sanitizeBrowserUrl } from "../domain/browserObservation.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import type { BrowserObservationOperation } from "../domain/browserObservationErrors.js";
import { authorizedMainFrame } from "./CdpAuthorizedMainFrame.js";
import {
  classifyCdpFrameUrl,
  observeMainFrameUrl,
} from "./CdpCaptureDocuments.js";
import { recordValue, cdpStringValue } from "./CdpCaptureValues.js";
import type { CdpConnection } from "./CdpConnection.js";
import type { CdpEndpointTarget } from "./CdpEndpoint.js";

interface PageEvaluateContext {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
  readonly target: CdpEndpointTarget;
  readonly input: BrowserEvaluateInput;
  readonly signal?: AbortSignal;
  readonly progress?: ProgressReporter;
}

const operation: BrowserObservationOperation = "browser_evaluate";

interface CapturedReply {
  readonly outcome: (typeof BROWSER_EVALUATE_OUTCOMES)[number];
  readonly valueType: string | null;
  readonly valueText: string | null;
  readonly exceptionText: string | null;
}

/** Evaluate one expression in the authorized main frame and project its answer. */
export const evaluateCdpMainFrame = async (
  context: PageEvaluateContext,
): Promise<BrowserEvaluateResult> => {
  const origins = new Set(context.input.allowed_origins);
  await context.progress?.report({
    phase: "browser_observation",
    completed: 1,
    total: 2,
    message: "Authorizing evaluation frame",
  });
  const frameTree = await authorizedMainFrame({
    connection: context.connection,
    sessionId: context.sessionId,
    signal: context.signal,
    allowedOrigins: origins,
    operation,
  });
  const facts = classifyCdpFrameUrl(observeMainFrameUrl(frameTree), origins);
  if (
    facts.scope !== "approved" ||
    facts.url === undefined ||
    facts.origin === null
  )
    throw new BrowserObservationError(operation, "target_not_allowed", {
      detail:
        "The selected target's main frame is not inside the evaluation origin scope.",
    });
  const evaluated = await context.connection.send(
    "Runtime.evaluate",
    {
      expression: context.input.expression,
      awaitPromise: context.input.await_promise,
      returnByValue: true,
      userGesture: false,
      silent: true,
    },
    context.sessionId,
    context.signal,
  );
  await context.progress?.report({
    phase: "browser_observation",
    completed: 2,
    total: 2,
    message: "Projecting evaluation result",
  });
  const reply = capturedReply(evaluated);
  const kept = keepText(reply.valueText);
  const exception = keepText(reply.exceptionText);
  const target = sanitizeBrowserUrl(facts.url);
  return browserEvaluateResultSchema.parse({
    target: {
      target_id: context.target.id,
      url: target,
      origin: facts.origin,
    },
    expression_sha256: createHash("sha256")
      .update(context.input.expression, "utf8")
      .digest("hex"),
    expression_bytes: Buffer.byteLength(context.input.expression, "utf8"),
    outcome: reply.outcome,
    value_type: reply.valueType,
    value_text: kept.text,
    value_bytes: kept.bytes,
    value_truncated: kept.truncated,
    exception_text: exception.text,
    trust: "evaluated-untrusted",
    limitations: [
      BROWSER_EVALUATE_TEXT_LIMITATION,
      BROWSER_EVALUATE_SIDE_EFFECT_LIMITATION,
      `Result text is retained up to ${String(BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes)} UTF-8 bytes and truncated beyond that.`,
    ],
  });
};

const capturedReply = (value: unknown): CapturedReply => {
  const envelope = recordValue(value);
  if (envelope === undefined)
    throw new BrowserObservationError(operation, "protocol_error");
  const exception = recordValue(envelope.exceptionDetails);
  if (exception !== undefined)
    return {
      outcome: "exception",
      valueType: null,
      valueText: null,
      exceptionText:
        cdpStringValue(recordValue(exception.exception)?.description) ??
        cdpStringValue(exception.text) ??
        "the page raised an exception without a description",
    };
  const result = recordValue(envelope.result);
  if (result === undefined)
    throw new BrowserObservationError(operation, "protocol_error");
  const type = cdpStringValue(result.type) ?? null;
  if ("value" in result)
    return {
      outcome: "value",
      valueType: type,
      valueText: literalText(result.value),
      exceptionText: null,
    };
  const unserializable = cdpStringValue(result.unserializableValue);
  if (unserializable !== undefined)
    return {
      outcome: "value",
      valueType: type,
      valueText: unserializable,
      exceptionText: null,
    };
  if (type === "undefined")
    return {
      outcome: "value",
      valueType: type,
      valueText: "undefined",
      exceptionText: null,
    };
  return {
    outcome: "not_serializable",
    valueType: type,
    valueText: null,
    exceptionText: null,
  };
};

/** JSON text for a by-value result; a string result is reported verbatim. */
const literalText = (value: unknown): string =>
  typeof value === "string" ? value : (JSON.stringify(value) ?? "null");

const keepText = (
  value: string | null,
): {
  readonly text: string | null;
  readonly bytes: number;
  readonly truncated: boolean;
} => {
  if (value === null) return { text: null, bytes: 0, truncated: false };
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes <= BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes)
    return { text: value, bytes, truncated: false };
  const buffer = Buffer.from(value, "utf8").subarray(
    0,
    BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes,
  );
  return {
    text: buffer.toString("utf8").replace(/\uFFFD+$/u, ""),
    bytes: BROWSER_MUTATION_LIMITS.maxEvaluateResultBytes,
    truncated: true,
  };
};
