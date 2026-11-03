import { randomBytes } from "node:crypto";

import type { MailProviderBackend } from "./MailTmClient.js";
import { MailboxRegistry, requireMailbox } from "./MailboxRegistry.js";
import {
  extractMagicLinks,
  extractVerificationCodes,
} from "./OtpExtraction.js";
import type {
  MailboxAttachment,
  MailboxMessageDetail as DetailType,
  MailboxMessageSummary,
  MailboxMessageSummary as MailboxMessageSummaryShape,
  MailProviderStatus,
} from "../domain/testmail/mailboxSchemas.js";
import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";

export interface TestmailCreateInput {
  readonly provider?: string | undefined;
  readonly user?: string | undefined;
  readonly password?: string | undefined;
}

/** Type aliases (not interfaces) so values satisfy JsonValue at the MCP boundary. */
export type TestmailCreateResult = {
  readonly mailbox_id: string;
  readonly provider: string;
  readonly address: string;
  readonly password: string;
};

export interface TestmailWaitInput {
  readonly mailbox_id: string;
  readonly from_contains?: string | undefined;
  readonly subject_contains?: string | undefined;
  readonly timeout_seconds?: number | undefined;
}

/** Type aliases (not interfaces) so values satisfy JsonValue at the MCP boundary. */
export type TestmailWaitResult = {
  readonly mailbox_id: string;
  readonly provider: string;
  readonly timed_out: boolean;
  readonly messages: MailboxMessageSummaryShape[];
  readonly codes: string[];
  readonly links: string[];
};

/** Type alias (not an interface) so the value satisfies JsonValue at the MCP boundary. */
export type TestmailReadResult = {
  readonly id: string;
  readonly from: string;
  readonly to: string;
  readonly subject: string;
  readonly received_at: string;
  readonly text: string;
  readonly html?: string;
  readonly attachments: MailboxAttachment[];
  readonly codes: string[];
  readonly links: string[];
};

export type TestmailReadInput = {
  readonly mailbox_id: string;
  readonly message_id: string;
};

export type TestmailDeleteInput = {
  readonly mailbox_id: string;
};

export type TestmailDeleteResult = {
  readonly deleted: boolean;
  readonly provider: string;
};

const DEFAULT_WAIT_SECONDS = 60;
const MIN_WAIT_SECONDS = 5;
const MAX_WAIT_SECONDS = 300;
const POLL_INTERVAL_MS = 2_000;
const PROVIDER_DOMAIN_CACHE_TTL_MS = 60_000;

const generatedUser = (): string => `rea${randomBytes(4).toString("hex")}`;

const generatedPassword = (): string => randomBytes(15).toString("base64url");

const matchesFilter = (
  message: MailboxMessageSummary,
  input: TestmailWaitInput,
): boolean =>
  (input.from_contains === undefined ||
    message.from.toLowerCase().includes(input.from_contains.toLowerCase())) &&
  (input.subject_contains === undefined ||
    message.subject
      .toLowerCase()
      .includes(input.subject_contains.toLowerCase()));

const enriched = (
  message: MailboxMessageSummary,
  detail: DetailType,
): MailboxMessageSummaryShape => ({
  ...message,
  subject: detail.subject,
  received_at: detail.received_at,
  text: detail.text.slice(0, 8_192),
  codes: [...extractVerificationCodes(detail.text)],
  links: [...extractMagicLinks(detail.text)],
});

const withExtraction = (
  message: MailboxMessageSummary,
): MailboxMessageSummaryShape => ({
  ...message,
  codes: [...extractVerificationCodes(message.text)],
  links: [...extractMagicLinks(message.text)],
});

const summarize = (
  mailboxId: string,
  timedOut: boolean,
  provider: string,
  messages: readonly MailboxMessageSummaryShape[],
): TestmailWaitResult => ({
  mailbox_id: mailboxId,
  provider,
  timed_out: timedOut,
  messages: [...messages],
  codes: [...new Set(messages.flatMap(({ codes }) => codes))],
  links: [...new Set(messages.flatMap(({ links }) => links))],
});

/** Provider-neutral disposable-mailbox service behind the testmail_* tools. */
export class TestmailService {
  readonly #backends: readonly MailProviderBackend[];
  readonly #registry: MailboxRegistry;
  readonly #pollIntervalMs: number;
  readonly #domainCache = new Map<
    MailProviderBackend["id"],
    { readonly atMs: number; readonly domains: readonly string[] }
  >();

  constructor(
    backends: readonly MailProviderBackend[],
    registry: MailboxRegistry = new MailboxRegistry(),
    options: { readonly pollIntervalMs?: number } = {},
  ) {
    this.#backends = backends;
    this.#registry = registry;
    this.#pollIntervalMs = options.pollIntervalMs ?? POLL_INTERVAL_MS;
  }

  get registrySize(): number {
    return this.#registry.size;
  }

  async listProviders(
    signal?: AbortSignal,
  ): Promise<
    Result<{ readonly providers: MailProviderStatus[] }, AnalysisError>
  > {
    const now = Date.now();
    const providers: MailProviderStatus[] = [];
    let firstFailure: AnalysisError | undefined;
    for (const backend of this.#backends) {
      const cached = this.#domainCache.get(backend.id);
      const domains =
        cached !== undefined && now - cached.atMs < PROVIDER_DOMAIN_CACHE_TTL_MS
          ? ok(cached.domains)
          : await backend.domains(signal);
      if (!domains.ok) {
        firstFailure ??= domains.error;
        continue;
      }
      this.#domainCache.set(backend.id, {
        atMs: now,
        domains: domains.value,
      });
      providers.push({
        id: backend.id,
        base_url: backend.baseUrl,
        domains: [...domains.value],
      });
    }
    return providers.length > 0
      ? ok({ providers })
      : err(
          firstFailure ??
            new ProviderAdapterError("testmail", "list-providers", {
              diagnostics: { reason: "no provider adapters configured" },
            }),
        );
  }

  async createMailbox(
    input: TestmailCreateInput,
    signal?: AbortSignal,
  ): Promise<Result<TestmailCreateResult, AnalysisError>> {
    const selected =
      input.provider === undefined
        ? this.#backends[0]
        : this.#backends.find((backend) => backend.id === input.provider);
    if (selected === undefined)
      return err(
        new ProviderAdapterError(
          input.provider ?? "testmail",
          "create-mailbox",
          {
            diagnostics: { reason: "unknown provider id" },
            remediationAction:
              "Use testmail_list_providers to see live provider ids.",
          },
        ),
      );
    const lease = await selected.createMailbox(
      input.user ?? generatedUser(),
      input.password ?? generatedPassword(),
      signal,
    );
    if (!lease.ok) return lease;
    const entry = this.#registry.add(selected, lease.value, Date.now());
    return ok({
      mailbox_id: entry.mailboxId,
      provider: selected.id,
      address: lease.value.address,
      password: lease.value.password,
    });
  }

  async waitForMail(
    input: TestmailWaitInput,
    signal?: AbortSignal,
  ): Promise<Result<TestmailWaitResult, AnalysisError>> {
    const entry = requireMailbox(
      this.#registry,
      input.mailbox_id,
      "testmail_wait_for_mail",
    );
    if (!entry.ok) return err(entry.error);
    const backend = entry.value.backend;
    const token = entry.value.lease.token;
    const seen = entry.value.seenMessageIds;
    const requestedSeconds = input.timeout_seconds ?? DEFAULT_WAIT_SECONDS;
    const timeoutSeconds = Math.min(
      Math.max(requestedSeconds, MIN_WAIT_SECONDS),
      MAX_WAIT_SECONDS,
    );
    const deadline = Date.now() + timeoutSeconds * 1_000;
    const messages: MailboxMessageSummaryShape[] = [];

    while (Date.now() < deadline && signal?.aborted !== true) {
      const listed = await backend.listMessages(token, signal);
      if (!listed.ok) return listed;
      const fresh = listed.value.filter(
        (message) => !seen.has(message.id) && matchesFilter(message, input),
      );
      for (const message of fresh) {
        seen.add(message.id);
        const detail = await backend.getMessage(token, message.id, signal);
        messages.push(
          detail.ok ? enriched(message, detail.value) : withExtraction(message),
        );
      }
      if (messages.length > 0)
        return ok(summarize(input.mailbox_id, false, backend.id, messages));
      if (Date.now() >= deadline) break;
      await new Promise<void>((resolve) =>
        setTimeout(
          resolve,
          Math.min(this.#pollIntervalMs, deadline - Date.now()),
        ),
      );
    }
    return ok(summarize(input.mailbox_id, true, backend.id, messages));
  }

  async readMessage(
    input: TestmailReadInput,
    signal?: AbortSignal,
  ): Promise<Result<TestmailReadResult, AnalysisError>> {
    const entry = requireMailbox(
      this.#registry,
      input.mailbox_id,
      "testmail_read_message",
    );
    if (!entry.ok) return err(entry.error);
    const detail = await entry.value.backend.getMessage(
      entry.value.lease.token,
      input.message_id,
      signal,
    );
    if (!detail.ok) return detail;
    const { html, ...rest } = detail.value;
    const read: TestmailReadResult = {
      ...rest,
      attachments: rest.attachments.map((attachment) => ({ ...attachment })),
      ...(html === undefined ? {} : { html }),
      codes: [...extractVerificationCodes(detail.value.text)],
      links: [...extractMagicLinks(detail.value.text)],
    };
    return ok(read);
  }

  async deleteMailbox(
    input: TestmailDeleteInput,
    signal?: AbortSignal,
  ): Promise<Result<TestmailDeleteResult, AnalysisError>> {
    const entry = requireMailbox(
      this.#registry,
      input.mailbox_id,
      "testmail_delete_mailbox",
    );
    if (!entry.ok) return err(entry.error);
    const backendId = entry.value.backend.id;
    const deleted = await entry.value.backend.deleteMailbox(
      entry.value.lease.token,
      entry.value.lease.accountId,
      signal,
    );
    await this.#registry.remove(input.mailbox_id);
    return ok({ deleted: deleted.ok, provider: backendId });
  }
}
