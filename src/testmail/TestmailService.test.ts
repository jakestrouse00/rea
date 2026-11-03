import { describe, expect, it } from "vitest";

import type { MailProviderBackend, MailboxLease } from "./MailTmClient.js";
import { TestmailService } from "./TestmailService.js";
import type {
  MailboxMessageDetail,
  MailboxMessageSummary,
} from "../domain/testmail/mailboxSchemas.js";
import { ProviderAdapterError } from "../domain/providerAdapterError.js";
import { err, ok } from "../domain/result.js";

const lease: MailboxLease = {
  provider: "mail_tm",
  accountId: "acc-1",
  token: "jwt-token",
  address: "burner@fake.test",
  password: "throwaway-pw",
};

const summary = (id: string, text: string): MailboxMessageSummary => ({
  id,
  from: "noreply@exampleapp.com",
  to: lease.address,
  subject: "Verify your account",
  received_at: "2026-11-02T10:00:00Z",
  text,
  codes: [],
  links: [],
});

const detail = (id: string, text: string): MailboxMessageDetail => ({
  id,
  from: "noreply@exampleapp.com",
  to: lease.address,
  subject: "Verify your account",
  received_at: "2026-11-02T10:00:00Z",
  text,
  attachments: [],
  codes: [],
  links: [],
});

class FakeBackend implements MailProviderBackend {
  readonly id = "mail_tm";
  readonly baseUrl = "https://fake.mail.test";
  readonly domainsList: string[] = ["fake.test"];
  lease: MailboxLease | undefined = lease;
  inbox: readonly MailboxMessageSummary[] = [];
  readonly details = new Map<string, MailboxMessageDetail>();
  deleteOutcome: "ok" | "failure" = "ok";

  async domains() {
    return ok([...this.domainsList]);
  }

  async createMailbox() {
    return this.lease === undefined
      ? err(
          new ProviderAdapterError(this.id, "create-mailbox", {
            diagnostics: { reason: "fixture refused" },
          }),
        )
      : ok(this.lease);
  }

  async listMessages() {
    return ok(this.inbox);
  }

  async getMessage(_token: string, messageId: string) {
    const message = this.details.get(messageId);
    return message === undefined
      ? err(
          new ProviderAdapterError(this.id, "read-message", {
            diagnostics: { reason: "missing in fixture" },
          }),
        )
      : ok(message);
  }

  async deleteMailbox() {
    return this.deleteOutcome === "ok"
      ? ok(undefined)
      : err(
          new ProviderAdapterError(this.id, "delete-account", {
            diagnostics: { reason: "fixture network failure" },
          }),
        );
  }
}

describe("TestmailService", () => {
  it("creates a mailbox and registers it under a fresh uuid handle", async () => {
    const backend = new FakeBackend();
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    expect(created.ok).toBe(true);
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    expect(created.ok && created.value.address).toBe(lease.address);
    expect(created.ok && created.value.password).toBe(lease.password);
    expect(created.ok && created.value.provider).toBe("mail_tm");
    expect(mailboxId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(service.registrySize).toBe(1);
  });

  it("refuses unknown provider ids", async () => {
    const service = new TestmailService([new FakeBackend()]);
    const created = await service.createMailbox({ provider: "mail_404" });
    expect(created.ok).toBe(false);
  });

  it("lists live provider pools and omits a failing adapter", async () => {
    const backendA = new FakeBackend();
    const failing: MailProviderBackend = {
      id: "mail_gw",
      baseUrl: "https://api.mail.gw.test",
      domains: () =>
        Promise.resolve(
          err(
            new ProviderAdapterError("mail_gw", "list-domains", {
              diagnostics: { http_status: 503 },
            }),
          ),
        ),
      createMailbox: () => Promise.reject(new Error("unused in this test")),
      listMessages: () => Promise.reject(new Error("unused in this test")),
      getMessage: () => Promise.reject(new Error("unused in this test")),
      deleteMailbox: () => Promise.reject(new Error("unused in this test")),
    };
    const partial = new TestmailService([backendA, failing]);
    const listed = await partial.listProviders();
    expect(listed.ok && listed.value.providers).toEqual([
      { id: "mail_tm", base_url: backendA.baseUrl, domains: ["fake.test"] },
    ]);
    const dead = new TestmailService([failing]);
    const none = await dead.listProviders();
    expect(none.ok).toBe(false);
  });

  it("waits for a fresh message, extracts its code, and does not re-return it", async () => {
    const backend = new FakeBackend();
    backend.inbox = [summary("m1", "Your verification code is 842109.")];
    backend.details.set(
      "m1",
      detail("m1", "Your verification code is 842109."),
    );
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    const waited = await service.waitForMail({
      mailbox_id: mailboxId,
      timeout_seconds: 5,
    });
    expect(waited.ok && waited.value.timed_out).toBe(false);
    expect(waited.ok && waited.value.codes).toEqual(["842109"]);
    expect(waited.ok && waited.value.messages[0]?.subject).toBe(
      "Verify your account",
    );

    backend.inbox = [];
    const again = await service.waitForMail({
      mailbox_id: mailboxId,
      timeout_seconds: 5,
    });
    expect(again.ok && again.value.timed_out).toBe(true);
    expect(again.ok && again.value.messages).toEqual([]);
  });

  it("filters by sender substring", async () => {
    const backend = new FakeBackend();
    backend.inbox = [summary("m1", "no code here")];
    backend.details.set("m1", detail("m1", "no code here"));
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    const waited = await service.waitForMail({
      mailbox_id: mailboxId,
      from_contains: "other@example.com",
      timeout_seconds: 5,
    });
    expect(waited.ok && waited.value.timed_out).toBe(true);
    expect(waited.ok && waited.value.messages).toEqual([]);
  });

  it("aborts a wait immediately and reports the partial snapshot", async () => {
    const backend = new FakeBackend();
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    const controller = new AbortController();
    controller.abort();
    const waited = await service.waitForMail(
      { mailbox_id: mailboxId },
      controller.signal,
    );
    expect(waited.ok && waited.value.timed_out).toBe(true);
    expect(waited.ok && waited.value.messages).toEqual([]);
  });

  it("reads a message and extracts codes and links from the full text", async () => {
    const backend = new FakeBackend();
    backend.details.set(
      "m1",
      detail(
        "m1",
        "Verify: https://app.example.test/v?t=abc . Or enter code 771230",
      ),
    );
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    const read = await service.readMessage({
      mailbox_id: mailboxId,
      message_id: "m1",
    });
    expect(read.ok && read.value.codes).toEqual(["771230"]);
    expect(read.ok && read.value.links).toEqual([
      "https://app.example.test/v?t=abc",
    ]);
  });

  it("fails reads and waits for unknown mailbox ids", async () => {
    const service = new TestmailService([new FakeBackend()]);
    const waited = await service.waitForMail({
      mailbox_id: "c7c9d1a2-5b34-4c56-9e78-d3a0b1c2e4f5",
      timeout_seconds: 5,
    });
    expect(waited.ok).toBe(false);
    const read = await service.readMessage({
      mailbox_id: "c7c9d1a2-5b34-4c56-9e78-d3a0b1c2e4f5",
      message_id: "m1",
    });
    expect(read.ok).toBe(false);
  });

  it("delete drops the handle and reports provider confirmation", async () => {
    const backend = new FakeBackend();
    const service = new TestmailService([backend]);
    const created = await service.createMailbox({});
    const mailboxId = created.ok ? created.value.mailbox_id : "";
    const released = await service.deleteMailbox({ mailbox_id: mailboxId });
    expect(released).toEqual({
      ok: true,
      value: { deleted: true, provider: "mail_tm" },
    });
    expect(service.registrySize).toBe(0);

    backend.deleteOutcome = "failure";
    const second = await service.createMailbox({});
    const secondId = second.ok ? second.value.mailbox_id : "";
    const failed = await service.deleteMailbox({ mailbox_id: secondId });
    expect(failed.ok && failed.value.deleted).toBe(false);
    expect(service.registrySize).toBe(0);
  });
});
