import { z } from "zod";

/** Disposable-mail provider adapters currently supported by REA. */
export const mailProviderIdSchema = z.enum(["mail_tm", "mail_gw"]);

export type MailProviderId = z.infer<typeof mailProviderIdSchema>;

/** One extracted verification artifact: a short code or a magic link. */
export const verificationCodeSchema = z
  .string()
  .min(1)
  .max(64)
  .describe("Extracted short verification code, trimmed of surrounding text.");

export const magicLinkSchema = z
  .string()
  .min(1)
  .max(2_048)
  .describe("Extracted verification or sign-in URL from the message body.");

export const mailboxAttachmentSchema = z.strictObject({
  filename: z.string().max(512),
  content_type: z.string().max(256),
  size: z.number().int().nonnegative(),
  download_url: z.string().max(4_096),
});

export type MailboxAttachment = z.infer<typeof mailboxAttachmentSchema>;

/** One received mail message with verification artifacts already extracted. */
export const mailboxMessageSummarySchema = z.strictObject({
  id: z.string().max(512),
  from: z.string().max(512),
  to: z.string().max(512),
  subject: z.string().max(1_024),
  received_at: z.string().max(64),
  text: z.string().max(8_192),
  codes: z.array(verificationCodeSchema).max(32),
  links: z.array(magicLinkSchema).max(32),
});

export type MailboxMessageSummary = z.infer<typeof mailboxMessageSummarySchema>;

/** Full message body including the sanitized HTML part and attachments. */
export const mailboxMessageDetailSchema = z.strictObject({
  id: z.string().max(512),
  from: z.string().max(512),
  to: z.string().max(512),
  subject: z.string().max(1_024),
  received_at: z.string().max(64),
  text: z.string().max(65_536),
  html: z.string().max(65_536).optional(),
  attachments: z.array(mailboxAttachmentSchema).max(128),
  codes: z.array(verificationCodeSchema).max(32),
  links: z.array(magicLinkSchema).max(32),
});

export type MailboxMessageDetail = z.infer<typeof mailboxMessageDetailSchema>;

/** One rentable disposable-mail provider and its currently active domains. */
export const mailProviderStatusSchema = z.strictObject({
  id: mailProviderIdSchema,
  base_url: z.string().max(256),
  domains: z.array(z.string().max(256)).max(64),
});

export type MailProviderStatus = z.infer<typeof mailProviderStatusSchema>;
