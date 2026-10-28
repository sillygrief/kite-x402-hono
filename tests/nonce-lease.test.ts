import { expect, test } from "bun:test";
import { PaymentNonceReplayGuard } from "../src/nonce-guard.js";
import { harness, signature } from "./helpers.js";

test("an active lease stays reserved beyond the legacy timeout", () => {
  const guard = new PaymentNonceReplayGuard({
    inFlightTtlMs: 1,
    maxEntries: 1,
  });
  const lease = guard.reserve("payer", "nonce", 100)!;
  expect(guard.check("payer", "nonce", 1_000_000)).toBe("IN_FLIGHT");
  expect(guard.reserve("payer", "nonce", 1_000_000)).toBeNull();
  expect(guard.reserve("other", "nonce", 1_000_000)).toBeNull();
  lease.release();
  expect(guard.reserve("other", "nonce", 1_000_000)).not.toBeNull();
});

test("a stale owner cannot release or commit a replacement lease", () => {
  const guard = new PaymentNonceReplayGuard();
  const old = guard.reserve("payer", "nonce", 100)!;
  guard.clear();
  const current = guard.reserve("payer", "nonce", 200)!;
  old.release();
  old.commit(201);
  expect(guard.check("payer", "nonce", 202)).toBe("IN_FLIGHT");
  current.commit(203);
  current.release();
  expect(guard.check("payer", "nonce", 204)).toBe("CONSUMED");
});

test("slow upstream requests retain nonce protection through completion", async () => {
  let finish!: () => void;
  let entered!: () => void;
  const gate = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const { app, events } = harness({
    nonceGuard: new PaymentNonceReplayGuard({ inFlightTtlMs: 1 }),
    upstream: async () => {
      entered();
      await gate;
      return Response.json({ ok: true });
    },
  });
  const sig = await signature(app);
  const headers = { "payment-signature": sig };
  const first = app.request("/v1/echo", { headers });
  try {
    await started;
    await Bun.sleep(5);
    expect((await app.request("/v1/echo", { headers })).status).toBe(402);
    expect(events.filter((event) => event === "upstream")).toHaveLength(1);
  } finally {
    finish();
  }
  expect((await first).status).toBe(200);
  expect(events.filter((event) => event === "settle")).toHaveLength(1);
  expect((await app.request("/v1/echo", { headers })).status).toBe(402);
});
