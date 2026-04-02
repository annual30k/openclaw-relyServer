import assert from "node:assert/strict";
import test from "node:test";
import {
  buildCronTaskMutationParams,
  buildTaskRecordFromCronResponse,
  computeNextTaskRun,
  extractTaskResultText,
  normalizeTaskBody,
  sortTaskRecords,
} from "./task-utils.js";

test("task utils normalize task bodies and generate cron mutations", () => {
  const normalized = normalizeTaskBody({
    title: "  ",
    prompt: "Run every day",
    scheduleKind: "repeat",
    scheduleAt: "2030-01-01T00:00:00.000Z",
    repeatAmount: "1",
    repeatUnit: "days",
    enabled: true,
  });

  assert.equal(normalized.title, "Run every day");
  assert.equal(normalized.scheduleKind, "repeat");
  assert.equal(normalized.repeatAmount, 1);
  assert.equal(normalized.repeatUnit, "days");

  const mutation = buildCronTaskMutationParams(normalized);
  assert.ok(mutation);
  assert.equal((mutation as Record<string, unknown>).deleteAfterRun, false);
});

test("task utils map cron jobs and compute next runs", () => {
  const task = buildTaskRecordFromCronResponse("gw_1", "user_1", {
    id: "task_1",
    name: "Morning brief",
    enabled: true,
    createdAtMs: 1000,
    schedule: { kind: "at", atMs: 2000 },
    payload: { message: "hello" },
    state: { lastRunStatus: "ok" },
  });

  assert.ok(task);
  assert.equal(task?.id, "task_1");
  assert.equal(task?.scheduleKind, "once");

  const nextRun = computeNextTaskRun({
    ...(task as NonNullable<typeof task>),
    scheduleKind: "repeat",
    scheduleAt: "2030-01-01T00:00:00.000Z",
    repeatAmount: 1,
    repeatUnit: "days",
  });
  assert.ok(typeof nextRun === "string");

  const sorted = sortTaskRecords([
    {
      ...(task as NonNullable<typeof task>),
      enabled: false,
      nextRunAt: "2030-01-02T00:00:00.000Z",
    },
    {
      ...(task as NonNullable<typeof task>),
      id: "task_2",
      enabled: true,
      nextRunAt: "2030-01-01T00:00:00.000Z",
    },
  ]);
  assert.equal(sorted[0]?.id, "task_2");
});

test("extractTaskResultText prefers message text before fallback fields", () => {
  assert.equal(
    extractTaskResultText({
      message: {
        content: [
          { type: "text", text: "  primary result  " },
          { type: "tool_use", text: "ignored" },
        ],
      },
      result: "fallback",
    }),
    "primary result",
  );

  assert.equal(extractTaskResultText({ output: "secondary result" }), "secondary result");
});
