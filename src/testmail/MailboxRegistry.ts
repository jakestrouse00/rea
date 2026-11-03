import { randomUUID } from "node:crypto";

import type { MailProviderBackend, MailboxLease } from "./MailTmClient.js";
import { err, ok, type Result } from "../domain/result.js";
import { AnalysisInputError } from "../domain/analysisErrorCore.js";

/** One leased mailbox held in the server's process-lifetime registry. */
export interface MailboxEntry {
  readonly mailboxId: string;
  readonly backend: MailProviderBackend;
  readonly lease: MailboxLease;
  readonly createdAtMs: number;
  /** Message ids already returned from testmail_wait_for_mail on this mailbox. */
  readonly seenMessageIds: Set<string>;
}

const MAILBOX_REGISTRY_CAPACITY = 128;

/**
 * Process-lifetime store for disposable mailboxes so tool calls reference a
 * stable mailbox_id instead of re-logging in per call. Entries live until
 * deleted or until the registry exceeds its capacity and drops the oldest.
 */
export class MailboxRegistry {
  readonly #entries = new Map<string, MailboxEntry>();

  add(
    backend: MailProviderBackend,
    lease: MailboxLease,
    nowMs: number,
  ): MailboxEntry {
    while (this.#entries.size >= MAILBOX_REGISTRY_CAPACITY) {
      const oldest = [...this.#entries.values()].sort(
        (left, right) => left.createdAtMs - right.createdAtMs,
      )[0];
      if (oldest === undefined) break;
      this.#entries.delete(oldest.mailboxId);
    }
    const entry: MailboxEntry = {
      mailboxId: randomUUID(),
      backend,
      lease,
      createdAtMs: nowMs,
      seenMessageIds: new Set<string>(),
    };
    this.#entries.set(entry.mailboxId, entry);
    return entry;
  }

  get(mailboxId: string): MailboxEntry | undefined {
    return this.#entries.get(mailboxId);
  }

  remove(mailboxId: string): MailboxEntry | undefined {
    const entry = this.#entries.get(mailboxId);
    if (entry === undefined) return undefined;
    this.#entries.delete(mailboxId);
    return entry;
  }

  get size(): number {
    return this.#entries.size;
  }
}

/** Resolve one registered mailbox, or a typed caller-facing input failure. */
export const requireMailbox = (
  registry: MailboxRegistry,
  mailboxId: string,
  operation: string,
): Result<MailboxEntry, AnalysisInputError> => {
  const entry = registry.get(mailboxId);
  if (entry === undefined)
    return err(
      new AnalysisInputError(operation, {
        diagnostics: { mailbox_id: mailboxId },
        userMessage:
          "Unknown mailbox_id: create a mailbox first, or list a fresh one. Registry entries are process-lifetime and drop the oldest beyond capacity.",
      }),
    );
  return ok(entry);
};
