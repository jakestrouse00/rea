import { z } from "zod";

import { mailProviderIdSchema } from "./../../domain/testmail/mailboxSchemas.js";

export const testmailListProvidersInputSchema = z.strictObject({});

export const testmailCreateMailboxInputSchema = z.strictObject({
  provider: mailProviderIdSchema
    .optional()
    .describe(
      "Provider adapter to allocate on. Omit for the default order (mail_tm first, then mail_gw). Pass a different id when a target site rejects one provider's current domain.",
    ),
  user: z
    .string()
    .min(3)
    .max(32)
    .regex(/^[a-z0-9][a-z0-9._\-]*$/)
    .optional()
    .describe(
      "Requested mailbox user part before the @. Omit to have REA generate a random one. Not unique across the shared provider domains; a 409/422 means pick another.",
    ),
  password: z
    .string()
    .min(8)
    .max(64)
    .optional()
    .describe(
      "Mailbox password, needed only to re-login outside this REA process. Omit and REA generates one; the returned address and password are the only way back into the mailbox.",
    ),
});

export const testmailWaitForMailInputSchema = z.strictObject({
  mailbox_id: z
    .string()
    .uuid()
    .describe("Mailbox identifier returned by testmail_create_mailbox."),
  from_contains: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe(
      "Only count messages whose From address contains this text (case-insensitive).",
    ),
  subject_contains: z
    .string()
    .min(1)
    .max(200)
    .optional()
    .describe(
      "Only count messages whose Subject contains this text (case-insensitive).",
    ),
  timeout_seconds: z
    .number()
    .int()
    .min(5)
    .max(300)
    .optional()
    .describe(
      "Polling budget between 5 and 300 seconds; 60 by default. Returns timed_out true with whatever arrived when the budget expires instead of failing.",
    ),
});

export const testmailReadMessageInputSchema = z.strictObject({
  mailbox_id: z
    .string()
    .uuid()
    .describe("Mailbox identifier returned by testmail_create_mailbox."),
  message_id: z
    .string()
    .min(1)
    .max(512)
    .describe("Message id from testmail_wait_for_mail output."),
});

export const testmailDeleteMailboxInputSchema = z.strictObject({
  mailbox_id: z
    .string()
    .uuid()
    .describe("Mailbox identifier returned by testmail_create_mailbox."),
});
