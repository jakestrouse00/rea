import {
  type MailProviderId,
  mailboxAttachmentSchema,
  mailboxMessageDetailSchema,
  mailboxMessageSummarySchema,
  type MailboxAttachment,
  type MailboxMessageDetail,
  type MailboxMessageSummary,
} from "../domain/testmail/mailboxSchemas.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok, type Result } from "../domain/result.js";

/** One live disposable-mail account created through a provider adapter. */
export interface MailboxLease {
  readonly provider: MailProviderId;
  readonly accountId: string;
  readonly token: string;
  readonly address: string;
  readonly password: string;
}

/** A mailbox-scoped backend for one disposable-mail provider. */
export interface MailProviderBackend {
  readonly id: MailProviderId;
  readonly baseUrl: string;
  domains(
    signal?: AbortSignal,
  ): Promise<Result<readonly string[], ProviderAdapterError>>;
  createMailbox(
    user: string,
    password: string,
    signal?: AbortSignal,
  ): Promise<Result<MailboxLease, ProviderAdapterError>>;
  listMessages(
    token: string,
    signal?: AbortSignal,
  ): Promise<Result<readonly MailboxMessageSummary[], ProviderAdapterError>>;
  getMessage(
    token: string,
    messageId: string,
    signal?: AbortSignal,
  ): Promise<Result<MailboxMessageDetail, ProviderAdapterError>>;
  deleteMailbox(
    token: string,
    accountId: string,
    signal?: AbortSignal,
  ): Promise<Result<undefined, ProviderAdapterError>>;
}

/** Hydra collections wrap items in `hydra:member`; the JSON dialect returns a plain array. */
const hydraItems = (payload: unknown): readonly unknown[] => {
  if (Array.isArray(payload)) return payload;
  if (typeof payload === "object" && payload !== null) {
    const items = (payload as { readonly "hydra:member"?: unknown })[
      "hydra:member"
    ];
    return Array.isArray(items) ? items : [];
  }
  return [];
};

const asString = (value: unknown): string =>
  typeof value === "string" ? value : "";

const fromAddress = (from: unknown): string => {
  if (typeof from === "string") return from;
  if (typeof from === "object" && from !== null) {
    const record = from as { readonly address?: unknown };
    return asString(record.address);
  }
  return "";
};

const toAddress = (to: unknown): string => {
  if (Array.isArray(to)) return to.map(fromAddress).join(", ");
  if (typeof to === "object" && to !== null) return fromAddress(to);
  return "";
};

const parseAttachments = (
  attachments: readonly unknown[],
): readonly MailboxAttachment[] =>
  attachments.flatMap((attachment) => {
    const parsed = mailboxAttachmentSchema.safeParse({
      filename: asString((attachment as { filename?: unknown })?.filename),
      content_type: asString(
        (attachment as { contentType?: unknown })?.contentType,
      ),
      size:
        typeof (attachment as { size?: unknown })?.size === "number"
          ? (attachment as { size: number }).size
          : 0,
      download_url: asString(
        (attachment as { downloadUrl?: unknown })?.downloadUrl,
      ),
    });
    return parsed.success ? [parsed.data] : [];
  });

const apiFailure = (
  id: MailProviderId,
  operation: string,
  status: number,
  cause?: unknown,
): ProviderAdapterError =>
  new ProviderAdapterError(id, operation, {
    diagnostics: { http_status: status, cause: String(cause) },
    remediationAction:
      status === 429
        ? "Wait at least one second before retrying the provider request."
        : "Retry the operation, or switch providers while listing statuses.",
  });

/**
 * Client for the mail.tm-family REST API (mail.tm and mail.gw share the same
 * protocol; only the base URL differs). Free, keyless, 8 QPS per IP.
 */
export class MailTmClient implements MailProviderBackend {
  readonly id: MailProviderId;
  readonly baseUrl: string;
  #lastRequestAt: number = 0;

  constructor(id: MailProviderId, baseUrl: string) {
    this.id = id;
    this.baseUrl = baseUrl;
  }

  /** Stay under the published 8 QPS limit with a conservative pacing floor. */
  async #pacedFetch(
    path: string,
    init: RequestInit & { readonly token?: string } = {},
    signal?: AbortSignal,
  ): Promise<Response> {
    const minimumSpacingMs = 150;
    const now = Date.now();
    const waitMs = this.#lastRequestAt + minimumSpacingMs - now;
    if (waitMs > 0)
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    const { token, headers, ...rest } = init;
    for (let attempt = 0; attempt < 2; attempt++) {
      const startedAt = Date.now();
      this.#lastRequestAt = startedAt;
      const response = await fetch(`${this.baseUrl}${path}`, {
        ...rest,
        ...(signal === undefined ? {} : { signal }),
        headers: {
          accept: "application/json",
          ...(rest.body === undefined
            ? {}
            : { "content-type": "application/json" }),
          ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
          ...headers,
        },
      });
      if (response.status === 429 && attempt === 0) {
        const retryAfterRaw = response.headers.get("retry-after");
        const retryAfterMs =
          retryAfterRaw === null
            ? 1_000
            : Number.parseInt(retryAfterRaw, 10) * 1_000;
        await new Promise<void>((resolve) =>
          setTimeout(
            resolve,
            Number.isFinite(retryAfterMs) ? retryAfterMs : 1_000,
          ),
        );
        continue;
      }
      return response;
    }
    throw new Error("unreachable");
  }

  async #json(
    operation: string,
    path: string,
    init: RequestInit & { readonly token?: string } = {},
    signal?: AbortSignal,
  ): Promise<Result<unknown, ProviderAdapterError>> {
    try {
      const response = await this.#pacedFetch(path, init, signal);
      if (!response.ok)
        return err(apiFailure(this.id, operation, response.status));
      if (response.status === 204) return ok(undefined);
      const payload = (await response.json()) as unknown;
      return ok(payload);
    } catch (cause: unknown) {
      if (cause instanceof Error && cause.name === "AbortError") throw cause;
      return err(
        new ProviderAdapterError(this.id, operation, {
          diagnostics: { cause: String(cause) },
          remediationAction:
            "Check network connectivity, then retry the operation.",
        }),
      );
    }
  }

  async domains(
    signal?: AbortSignal,
  ): Promise<Result<readonly string[], ProviderAdapterError>> {
    const payload = await this.#json("list-domains", "/domains", {}, signal);
    if (!payload.ok) return payload;
    const domains = hydraItems(payload.value)
      .map((domain) => ({
        domain: asString((domain as { domain?: unknown })?.domain),
        isActive: (domain as { isActive?: unknown })?.isActive,
      }))
      .filter(
        (entry) =>
          entry.domain.length > 0 &&
          (entry.isActive === undefined || entry.isActive),
      )
      .map(({ domain }) => domain);
    return domains.length === 0
      ? err(
          new ProviderAdapterError(this.id, "list-domains", {
            diagnostics: { reason: "provider reported no active domains" },
            remediationAction: "Switch to another provider.",
          }),
        )
      : ok(domains);
  }

  async createMailbox(
    user: string,
    password: string,
    signal?: AbortSignal,
  ): Promise<Result<MailboxLease, ProviderAdapterError>> {
    const available = await this.domains(signal);
    if (!available.ok) return available;
    const domain = available.value[0];
    if (domain === undefined)
      return err(
        new ProviderAdapterError(this.id, "create-mailbox", {
          diagnostics: { reason: "no active domain available" },
        }),
      );
    const account = await this.#json(
      "create-account",
      "/accounts",
      {
        method: "POST",
        body: JSON.stringify({ address: `${user}@${domain}`, password }),
      },
      signal,
    );
    if (!account.ok) return account;
    const accountId = asString((account.value as { id?: unknown }).id);
    const login = await this.#json(
      "login",
      "/token",
      {
        method: "POST",
        body: JSON.stringify({ address: `${user}@${domain}`, password }),
      },
      signal,
    );
    if (!login.ok) return login;
    const loginPayload = login.value as { token?: unknown };
    if (
      typeof loginPayload.token !== "string" ||
      loginPayload.token.length === 0
    )
      return err(
        new ProviderAdapterError(this.id, "login", {
          diagnostics: { reason: "provider returned no bearer token" },
        }),
      );
    return ok({
      provider: this.id,
      accountId,
      token: loginPayload.token,
      address: `${user}@${domain}`,
      password,
    });
  }

  async listMessages(
    token: string,
    signal?: AbortSignal,
  ): Promise<Result<readonly MailboxMessageSummary[], ProviderAdapterError>> {
    const payload = await this.#json(
      "list-messages",
      "/messages",
      { token },
      signal,
    );
    if (!payload.ok) return payload;
    const messages = hydraItems(payload.value).flatMap((message) => {
      const record = message as Record<string, unknown>;
      const text = asString(record.intro);
      const parsed = mailboxMessageSummarySchema.safeParse({
        id: asString(record.id),
        from: fromAddress(record.from),
        to: toAddress(record.to),
        subject: asString(record.subject),
        received_at: asString(record.createdAt),
        text,
        codes: [],
        links: [],
      });
      return parsed.success ? [parsed.data] : [];
    });
    return ok(messages);
  }

  async getMessage(
    token: string,
    messageId: string,
    signal?: AbortSignal,
  ): Promise<Result<MailboxMessageDetail, ProviderAdapterError>> {
    const payload = await this.#json(
      "read-message",
      `/messages/${encodeURIComponent(messageId)}`,
      { token },
      signal,
    );
    if (!payload.ok) return payload;
    const record = payload.value as Record<string, unknown>;
    const htmlRaw = record.html;
    const html = Array.isArray(htmlRaw)
      ? htmlRaw.map(asString).join("\n")
      : typeof htmlRaw === "string"
        ? htmlRaw
        : undefined;
    const text = asString(record.text);
    const parsed = mailboxMessageDetailSchema.safeParse({
      id:
        asString(record.id) || asString((record as { "@id"?: unknown })["@id"]),
      from: fromAddress(record.from),
      to: toAddress(record.to),
      subject: asString(record.subject),
      received_at: asString(record.createdAt),
      text,
      html: html === undefined ? undefined : html.slice(0, 65_536),
      attachments: parseAttachments(
        Array.isArray(record.attachments) ? record.attachments : [],
      ).map((attachment) => ({
        ...attachment,
        download_url: attachment.download_url.startsWith("http")
          ? attachment.download_url
          : `${this.baseUrl}${attachment.download_url}`,
      })),
      codes: [],
      links: [],
    });
    if (!parsed.success)
      return err(
        new ProviderAdapterError(this.id, "read-message", {
          diagnostics: { reason: "unexpected message payload shape" },
        }),
      );
    return ok(parsed.data);
  }

  async deleteMailbox(
    token: string,
    accountId: string,
    signal?: AbortSignal,
  ): Promise<Result<undefined, ProviderAdapterError>> {
    const deleted = await this.#json(
      "delete-account",
      `/accounts/${encodeURIComponent(accountId)}`,
      { method: "DELETE", token },
      signal,
    );
    if (!deleted.ok) return deleted;
    return ok(undefined);
  }
}
