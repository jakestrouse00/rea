import { MailTmClient } from "./MailTmClient.js";
import { TestmailService } from "./TestmailService.js";

/**
 * The two free mail.tm-family providers share one protocol and differ only in
 * their base URL, so one client covers both. They are independent deployments
 * with separately rotating domain pools, giving a fallback when one pool is
 * blocked by a signup form. Ordering here is the default allocation order.
 */
export const createTestmailService = (): TestmailService =>
  new TestmailService([
    new MailTmClient("mail_tm", "https://api.mail.tm"),
    new MailTmClient("mail_gw", "https://api.mail.gw"),
  ]);

export const TESTMAIL_PROVIDER_BASE_URLS: Readonly<
  Record<"mail_tm" | "mail_gw", string>
> = Object.freeze({
  mail_tm: "https://api.mail.tm",
  mail_gw: "https://api.mail.gw",
});
