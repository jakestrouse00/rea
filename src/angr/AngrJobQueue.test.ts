import { expect, test } from "vitest";

import type { AnalysisError } from "../domain/analysisErrorBase.js";
import { AnalysisCancelledError } from "../domain/analysisErrorCore.js";
import { err, ok, type Result } from "../domain/result.js";
import { AngrJobQueue } from "./AngrJobQueue.js";

type Job = Result<string, AnalysisError>;

const settleLater = (value: string, signal?: AbortSignal): Promise<Job> =>
  new Promise((resolve) => {
    const timer = setTimeout(() => resolve(ok(value)), 20);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve(err(new AnalysisCancelledError("test")));
      },
      { once: true },
    );
  });

test("holds one job at a time when the cap is one", async () => {
  const queue = new AngrJobQueue(1);
  const order: string[] = [];
  const run = (name: string) =>
    queue.run(name, undefined, async () => {
      order.push(`${name}:start`);
      const result = await settleLater(name);
      order.push(`${name}:end`);
      return result;
    });
  const results = await Promise.all([run("first"), run("second")]);
  expect(results.every((result) => result.ok)).toBe(true);
  expect(order).toEqual([
    "first:start",
    "first:end",
    "second:start",
    "second:end",
  ]);
});

test("admits several jobs when the cap allows them", async () => {
  const queue = new AngrJobQueue(2);
  const started: string[] = [];
  const run = (name: string) =>
    queue.run(name, undefined, async () => {
      started.push(name);
      return await settleLater(name);
    });
  const pending = Promise.all([run("a"), run("b")]);
  await new Promise((resolve) => setTimeout(resolve, 10));
  expect(queue.snapshot()).toMatchObject({ active: 2, queued: 0 });
  await pending;
  expect(started).toEqual(["a", "b"]);
});

test("cancels a queued caller without spending a slot", async () => {
  const queue = new AngrJobQueue(1);
  const controller = new AbortController();
  const started: string[] = [];
  const first = queue.run("first", undefined, async () => {
    started.push("first");
    return await settleLater("first");
  });
  const queued = queue.run("queued", controller.signal, async () => {
    started.push("queued");
    return ok("queued");
  });
  await new Promise((resolve) => setTimeout(resolve, 5));
  controller.abort(new Error("caller cancelled"));
  const cancelled = await queued;
  expect(cancelled.ok).toBe(false);
  if (cancelled.ok) return;
  expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  expect(started).toEqual(["first"]);
  const remaining = await queue.run("after", undefined, async () =>
    ok("after"),
  );
  expect(remaining.ok).toBe(true);
  await first;
});

test("close cancels every waiter and waits for the admitted job", async () => {
  const queue = new AngrJobQueue(1);
  const events: string[] = [];
  const first = queue.run("first", undefined, async () => {
    events.push("first:start");
    await new Promise((resolve) => setTimeout(resolve, 40));
    events.push("first:end");
    return ok("first");
  });
  const waiting = queue.run("waiting", undefined, async () => {
    events.push("waiting:start");
    return ok("waiting");
  });
  const closing = queue.close();
  const cancelled = await waiting;
  expect(cancelled.ok).toBe(false);
  if (!cancelled.ok)
    expect(cancelled.error._tag).toBe("AnalysisCancelledError");
  expect(queue.snapshot()).toMatchObject({ closed: true, queued: 0 });
  await closing;
  expect(events).toEqual(["first:start", "first:end"]);
  expect(queue.snapshot()).toMatchObject({ active: 0, closed: true });
  await first;
  const after = await queue.run("after", undefined, async () => ok("after"));
  expect(after.ok).toBe(false);
});
