import { afterEach, expect, it, vi } from "vitest";

import { MailTmClient } from "./MailTmClient.js";

const jsonResponse = (payload: unknown, status = 200): Response =>
  new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });

const client = new MailTmClient("mail_tm", "https://api.mail.tm.test");
const gwClient = new MailTmClient("mail_gw", "https://api.mail.gw.test");

afterEach(() => vi.unstubAllGlobals());

it("lists live domains from the hydra envelope", async () => {
  const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
    jsonResponse({
      "hydra:member": [
        { domain: "live.test", isActive: true },
        { domain: "retired.test", isActive: false },
      ],
    }),
  );
  vi.stubGlobal("fetch", fetch);
  const domains = await client.domains();
  expect(domains).toEqual({ ok: true, value: ["live.test"] });
  expect(fetch.mock.calls[0]?.[0]).toBe("https://api.mail.tm.test/domains");
  expect(
    (fetch.mock.calls[0]?.[1] as RequestInit | undefined)?.headers,
  ).toMatchObject({ accept: "application/json" });
});

it("accepts the plain-JSON dialect that returns collections as bare arrays", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(
      jsonResponse([{ domain: "bare.test", isActive: true }]),
    )
    .mockResolvedValueOnce(
      jsonResponse([
        {
          id: "m1",
          from: { address: "noreply@exampleapp.com" },
          to: [{ address: "me@bare.test" }],
          subject: "Hi",
          intro: "Your code is inside",
          createdAt: "2026-11-02T10:00:00Z",
        },
      ]),
    );
  vi.stubGlobal("fetch", fetch);
  expect(await client.domains()).toEqual({ ok: true, value: ["bare.test"] });
  const listed = await client.listMessages("tok");
  expect(listed.ok && listed.value[0]?.id).toBe("m1");
  expect(listed.ok && listed.value[0]?.to).toBe("me@bare.test");
});

it("creates an account and logs in for a bearer token", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(
      jsonResponse({
        "hydra:member": [{ domain: "live.test", isActive: true }],
      }),
    )
    .mockResolvedValueOnce(
      jsonResponse({ id: "acc123", address: "user@live.test" }),
    )
    .mockResolvedValueOnce(jsonResponse({ id: "acc123", token: "jwt-token" }));
  vi.stubGlobal("fetch", fetch);
  const lease = await client.createMailbox("user", "s3cret-password");
  expect(lease).toEqual({
    ok: true,
    value: {
      provider: "mail_tm",
      accountId: "acc123",
      token: "jwt-token",
      address: "user@live.test",
      password: "s3cret-password",
    },
  });
  const calls = fetch.mock.calls;
  expect(calls[1]?.[0]).toBe("https://api.mail.tm.test/accounts");
  expect(
    JSON.parse((calls[1]?.[1] as RequestInit | undefined)?.body as string),
  ).toEqual({
    address: "user@live.test",
    password: "s3cret-password",
  });
  expect(
    (calls[2]?.[1] as RequestInit | undefined)?.headers,
  ).not.toHaveProperty("authorization");
});

it("maps provider errors to a typed ProviderAdapterError with diagnostics", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValue(jsonResponse({ message: "boom" }, 500));
  vi.stubGlobal("fetch", fetch);
  const domains = await client.domains();
  expect(domains.ok).toBe(false);
  if (!domains.ok) {
    expect(domains.error._tag).toBe("ProviderAdapterError");
    expect(domains.error.providerId).toBe("mail_tm");
    expect(domains.error.diagnostics).toMatchObject({
      http_status: 500,
    });
    expect(domains.error.remediationAction).toMatch(/Switch providers|Retry/);
  }
});

it("shares the client across providers by base URL only", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValue(
      jsonResponse({ "hydra:member": [{ domain: "gw.test", isActive: true }] }),
    );
  vi.stubGlobal("fetch", fetch);
  const domains = await gwClient.domains();
  expect(domains).toEqual({ ok: true, value: ["gw.test"] });
  expect(fetch.mock.calls[0]?.[0]).toBe("https://api.mail.gw.test/domains");
});

it("lists and reads messages as summarized mail", async () => {
  const fetch = vi
    .fn<typeof globalThis.fetch>()
    .mockResolvedValueOnce(
      jsonResponse({
        "hydra:member": [
          {
            id: "m1",
            from: { address: "noreply@exampleapp.com", name: "Example" },
            to: [{ address: "user@live.test" }],
            subject: "Verify",
            intro: "Your code is inside",
            createdAt: "2026-11-02T10:00:00Z",
          },
        ],
      }),
    )
    .mockResolvedValueOnce(
      jsonResponse({
        id: "m1",
        subject: "Verify",
        from: { address: "noreply@exampleapp.com" },
        to: [{ address: "user@live.test" }],
        createdAt: "2026-11-02T10:00:00Z",
        text: "Your verification code is 582914",
        html: ["<p>Your verification code is 582914</p>"],
        attachments: [
          {
            id: "a1",
            filename: "receipt.pdf",
            contentType: "application/pdf",
            size: 100,
            downloadUrl: "/messages/m1/attachment/a1",
          },
        ],
      }),
    );
  vi.stubGlobal("fetch", fetch);
  const listed = await client.listMessages("jwt-token");
  expect(listed.ok && listed.value[0]?.id).toBe("m1");
  expect(listed.ok && listed.value[0]?.from).toBe("noreply@exampleapp.com");
  const detail = await client.getMessage("jwt-token", "m1");
  expect(detail.ok && detail.value.html).toBe(
    "<p>Your verification code is 582914</p>",
  );
  expect(detail.ok && detail.value.attachments[0]?.filename).toBe(
    "receipt.pdf",
  );
  expect(detail.ok && detail.value.attachments[0]?.download_url).toBe(
    "https://api.mail.tm.test/messages/m1/attachment/a1",
  );
});
