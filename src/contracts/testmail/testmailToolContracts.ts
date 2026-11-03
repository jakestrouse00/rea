import { TESTMAIL_PROVIDER_BASE_URLS } from "../../testmail/TestmailConfiguration.js";
import {
  mailProviderStatusSchema,
  mailboxMessageDetailSchema,
  mailboxMessageSummarySchema,
} from "../../domain/testmail/mailboxSchemas.js";
import { z } from "zod";
import type { ToolContract } from "../toolContractTypes.js";
import { toolContractMetadata } from "../toolEffects.js";
import {
  testmailCreateMailboxInputSchema,
  testmailDeleteMailboxInputSchema,
  testmailListProvidersInputSchema,
  testmailReadMessageInputSchema,
  testmailWaitForMailInputSchema,
} from "./testmailInputSchemas.js";

const TOOL_DISCLOSURE =
  "Addresses come from free shared disposable-mail pools whose domains appear on common disposable-domain blocklists; use these tools only for signup flows you are authorized to test.";

const uuidExample = "c7c9d1a2-5b34-4c56-9e78-d3a0b1c2e4f5";

export const TESTMAIL_TOOL_CONTRACTS = [
  {
    name: "testmail_list_providers",
    ...toolContractMetadata("testmail_list_providers"),
    description: `List the disposable-mail provider adapters REA fronts, each with its currently active domains. The mail.tm-family providers share one protocol and differ only by base URL (${Object.values(TESTMAIL_PROVIDER_BASE_URLS).join(", ")}); each deployment rotates its own domain pool, so one pool can be temporarily rejected by a target site while the other still passes. Recheck the list before retrying a declined signup: the active domain can change between attempts. Providers with no reachable active domains are omitted from the result; when every adapter fails, the call fails with the first provider error. ${TOOL_DISCLOSURE}`,
    kind: "testmail-provider",
    inputSchema: testmailListProvidersInputSchema,
    outputSchema: z.strictObject({
      providers: z
        .array(mailProviderStatusSchema)
        .max(8)
        .describe(
          "Live provider adapters and their currently active domains, in default allocation order.",
        ),
    }),
    examples: [{ title: "List live providers and domains", input: {} }],
  },
  {
    name: "testmail_create_mailbox",
    ...toolContractMetadata("testmail_create_mailbox"),
    description: `Allocate one disposable mailbox on a mail.tm-family provider and register it under a fresh mailbox_id for the later testmail_* tools. The account is created against the provider's currently active domain with a random user and password unless the caller supplies them; the returned credential triple is the only path back into the mailbox, so retain it if the flow must re-login later. Registration is not idempotent: a 409 or 422 from the provider means the chosen user is taken on that domain and another user (or another attempt) is needed, with no mailbox state changed. Mail is received only while the provider domain is live; check testmail_list_providers first when a target site has recently rejected one of these domains. ${TOOL_DISCLOSURE}`,
    kind: "testmail-provider",
    inputSchema: testmailCreateMailboxInputSchema,
    outputSchema: z.strictObject({
      mailbox_id: z
        .string()
        .uuid()
        .describe("Stable handle for the later testmail_* tools."),
      provider: z
        .enum(["mail_tm", "mail_gw"])
        .describe("Provider adapter that owns the mailbox."),
      address: z
        .string()
        .max(320)
        .describe(
          "Full mailbox address including the provider's current domain.",
        ),
      password: z
        .string()
        .max(64)
        .describe(
          "Mailbox password; retained here because the provider shows no recovery path.",
        ),
    }),
    examples: [
      {
        title: "Allocate a random mailbox on the default provider",
        input: {},
      },
      {
        title: "Allocate a named mailbox on mail_gw",
        input: { provider: "mail_gw", user: "signup-burner-01" },
      },
    ],
  },
  {
    name: "testmail_wait_for_mail",
    ...toolContractMetadata("testmail_wait_for_mail"),
    description: `Poll one registered mailbox until a message matching the optional From/Subject filters arrives, then return every matched message with verification codes and links already extracted from its full text. Codes are found by i18n keyword-scoped shape matching (4-8 digit or 5-8 alphanumeric tokens near code/verification labels across English, French, Spanish, Portuguese, Italian, German, Russian, Turkish, Arabic, Chinese, Japanese, and Korean), and links are the plain HTTPS URLs in the body; always skim the returned text when extraction looks wrong instead of retrying the same flow blind. Polls at a fixed interval inside the timeout budget and returns timed_out true with any partial messages instead of failing when nothing arrives; the call is safe to repeat and previously returned messages are not re-fetched. A cancelled request ends the poll and reports what arrived so far. Expiry is provider-side: mail can stop arriving once the provider domain rotates, and REA surfaces that through repeated timed_out results. ${TOOL_DISCLOSURE}`,
    kind: "testmail-provider",
    inputSchema: testmailWaitForMailInputSchema,
    outputSchema: z.strictObject({
      mailbox_id: z.string().uuid(),
      provider: z.enum(["mail_tm", "mail_gw"]),
      timed_out: z
        .boolean()
        .describe(
          "True when the polling budget expired before a matching message arrived.",
        ),
      messages: z
        .array(mailboxMessageSummarySchema)
        .max(128)
        .describe("Matched messages with extracted verification artifacts."),
      codes: z
        .array(z.string().max(64))
        .max(64)
        .describe(
          "Union of candidate verification codes across the returned messages, in first-seen order.",
        ),
      links: z
        .array(z.string().max(2_048))
        .max(64)
        .describe(
          "Union of verification or sign-in links across the returned messages.",
        ),
    }),
    examples: [
      {
        title: "Wait up to two minutes for the signup verification mail",
        input: {
          mailbox_id: uuidExample,
          from_contains: "noreply@exampleapp.com",
          timeout_seconds: 120,
        },
      },
    ],
  },
  {
    name: "testmail_read_message",
    ...toolContractMetadata("testmail_read_message"),
    description: `Fetch one message from a registered mailbox in full: the plain-text body, the provider-sanitized HTML part, attachment metadata with download URLs, and verification codes and links extracted from the full text. Use this when testmail_wait_for_mail's excerpt or extraction is ambiguous, for example a code split across the intro line, or an HTML-only CTA button. The message id comes from a prior testmail_wait_for_mail result; reading is idempotent and does not mark anything read server-side beyond the provider's own bookkeeping. ${TOOL_DISCLOSURE}`,
    kind: "testmail-provider",
    inputSchema: testmailReadMessageInputSchema,
    outputSchema: mailboxMessageDetailSchema,
    examples: [
      {
        title: "Read the full body of a verification mail",
        input: { mailbox_id: uuidExample, message_id: "msg_01JD8X" },
      },
    ],
  },
  {
    name: "testmail_delete_mailbox",
    ...toolContractMetadata("testmail_delete_mailbox"),
    description: `Delete one registered mailbox at its provider and drop REA's local registration. The local handle is removed as soon as the release is attempted; deleted reports whether the provider accepted the deletion, and a network failure still means the handle is gone for good while the provider-side account may survive until its own expiry, so do not expect the mailbox to remain usable after a failed delete. Deleting is the normal end of a finished signup flow and keeps the mailbox registry below its fixed capacity, where the oldest leases are dropped silently. ${TOOL_DISCLOSURE}`,
    kind: "testmail-provider",
    inputSchema: testmailDeleteMailboxInputSchema,
    outputSchema: z.strictObject({
      deleted: z
        .boolean()
        .describe("True when the provider confirmed deletion."),
      provider: z
        .enum(["mail_tm", "mail_gw"])
        .describe("Provider adapter that owned the mailbox."),
    }),
    examples: [
      {
        title: "Release a finished signup mailbox",
        input: { mailbox_id: uuidExample },
      },
    ],
  },
] as const satisfies readonly ToolContract[];
