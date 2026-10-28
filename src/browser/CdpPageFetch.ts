import type { ProgressReporter } from "../application/ProgressReporter.js";
import {
  BROWSER_FETCH_BODY_LIMITATION,
  BROWSER_FETCH_SESSION_LIMITATION,
  BROWSER_FETCH_TRANSPORT_LIMITATION,
  browserFetchResultSchema,
  type BrowserFetchInput,
  type BrowserFetchResult,
} from "../domain/browserMutation.js";
import { sanitizeBrowserUrl } from "../domain/browserObservation.js";
import { BrowserObservationError } from "../domain/browserObservationError.js";
import { REPLAY_RETRY_LIMITATION } from "../domain/replay/replayObservation.js";
import type { ReplayRequest } from "../domain/replay/replayRequest.js";
import { ReplaySendCore } from "../replay/ReplaySendCore.js";
import { authorizedMainFrame } from "./CdpAuthorizedMainFrame.js";
import {
  classifyCdpFrameUrl,
  observeMainFrameUrl,
} from "./CdpCaptureDocuments.js";
import {
  CdpPageFetchTransport,
  pageManagedHeaderNames,
} from "./CdpPageFetchTransport.js";
import type { CdpConnection } from "./CdpConnection.js";
import type { CdpEndpointTarget } from "./CdpEndpoint.js";

interface PageFetchContext {
  readonly connection: CdpConnection;
  readonly sessionId: string | undefined;
  readonly target: CdpEndpointTarget;
  readonly input: BrowserFetchInput;
  /** Operator-approved origins; empty disables the plane. */
  readonly operatorOrigins: readonly string[];
  readonly signal?: AbortSignal;
  readonly progress?: ProgressReporter;
}

/**
 * Dispatch one page-context request through the shared replay send core.
 *
 * The target's main frame is authorized first, the caller's origin scope is
 * narrowed by the operator allowlist, and the core then owns the one-shot
 * policy, the per-hop gate, the body budget, and the redacted echo. Only the
 * transport differs: the request leaves from the page, not from REA.
 */
export const fetchFromPage = async (
  context: PageFetchContext,
): Promise<BrowserFetchResult> => {
  await context.progress?.report({
    phase: "browser_observation",
    completed: 1,
    total: 2,
    message: "Authorizing page-context fetch",
  });
  const origins = new Set(context.input.allowed_origins);
  const frameTree = await authorizedMainFrame({
    connection: context.connection,
    sessionId: context.sessionId,
    signal: context.signal,
    allowedOrigins: origins,
    operation: "browser_fetch",
  });
  const facts = classifyCdpFrameUrl(observeMainFrameUrl(frameTree), origins);
  if (
    facts.scope !== "approved" ||
    facts.url === undefined ||
    facts.origin === null
  )
    throw new BrowserObservationError("browser_fetch", "target_not_allowed", {
      detail:
        "The selected target's main frame is not inside the page-fetch origin scope.",
    });
  const exchange = await new ReplaySendCore(
    new CdpPageFetchTransport({
      connection: context.connection,
      sessionId: context.sessionId,
    }),
  ).send({
    operation: "browser_fetch",
    request: pageRequest(context.input),
    allowedOrigins: approvedPageOrigins(context),
    timeoutMs: context.input.timeout_ms,
    followRedirects: false,
    signal: context.signal,
    dump:
      context.input.dump_path === undefined
        ? undefined
        : { path: context.input.dump_path, overwrite: context.input.overwrite },
  });
  if (!exchange.ok) throw exchange.error;
  await context.progress?.report({
    phase: "browser_observation",
    completed: 2,
    total: 2,
    message: "Projecting page-context exchange",
  });
  const request = exchange.value.request;
  return browserFetchResultSchema.parse({
    target: {
      target_id: context.target.id,
      url: sanitizeBrowserUrl(facts.url),
      origin: facts.origin,
    },
    request,
    browser_managed_header_names: pageManagedHeaderNames(
      request.header_names.map((name) => ({ name, value: "" })),
    ),
    redirect_chain: exchange.value.redirectChain,
    response: exchange.value.response,
    outcome: exchange.value.outcome,
    failure: exchange.value.failure,
    retry: "none",
    elapsed_ms: exchange.value.elapsedMs,
    limitations: [
      BROWSER_FETCH_SESSION_LIMITATION,
      BROWSER_FETCH_TRANSPORT_LIMITATION,
      REPLAY_RETRY_LIMITATION,
      BROWSER_FETCH_BODY_LIMITATION,
    ],
  });
};

const pageRequest = (input: BrowserFetchInput): ReplayRequest => ({
  method: input.method.trim().toUpperCase(),
  url: input.url,
  headers: input.headers,
  body: input.body,
});

/**
 * The caller's scope narrowed by the operator allowlist.
 *
 * A declared origin the operator never approved is dropped, never added: REA
 * cannot widen the plane from a request, so an empty intersection is a refusal
 * inside the send core rather than a page-context dispatch.
 */
const approvedPageOrigins = (context: PageFetchContext): readonly string[] => {
  const operator = new Set(context.operatorOrigins);
  return context.input.allowed_origins.filter((origin) => operator.has(origin));
};
