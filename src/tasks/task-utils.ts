import { nowIso } from "../security.js";
import type { TaskRecord, TaskRepeatUnit, TaskScheduleKind } from "../types.js";
export type { TaskRecord } from "../types.js";

export function readTaskString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

export function readTaskBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export function readTaskNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) {
      return parsed;
    }
  }
  return undefined;
}

export function msToIsoTimestamp(value: unknown): string | undefined {
  const ms = readTaskNumber(value);
  if (ms === undefined) {
    return undefined;
  }
  return new Date(ms).toISOString();
}

export function deriveRepeatConfigFromEveryMs(
  everyMs: number,
): Pick<TaskRecord, "repeatAmount" | "repeatUnit"> {
  const units: Array<[TaskRepeatUnit, number]> = [
    ["weeks", 7 * 24 * 60 * 60 * 1000],
    ["days", 24 * 60 * 60 * 1000],
    ["hours", 60 * 60 * 1000],
    ["minutes", 60 * 1000],
  ];

  for (const [unit, factor] of units) {
    if (everyMs > 0 && everyMs % factor === 0) {
      return {
        repeatAmount: everyMs / factor,
        repeatUnit: unit,
      };
    }
  }

  return {} as Pick<TaskRecord, "repeatAmount" | "repeatUnit">;
}

export function buildTaskLastResultFromCronState(state: Record<string, unknown> | undefined): string {
  if (!state) {
    return "";
  }

  const lastRunStatus = readTaskString(state.lastRunStatus) ?? readTaskString(state.lastStatus) ?? "";
  const lastDeliveryStatus = readTaskString(state.lastDeliveryStatus) ?? "";
  const lastError = readTaskString(state.lastError) ?? "";
  const lastDeliveryError = readTaskString(state.lastDeliveryError) ?? "";
  const lastDelivered = readTaskBoolean(state.lastDelivered);

  if (lastRunStatus === "ok") {
    if (lastDeliveryStatus === "delivered" || lastDelivered === true) {
      return "执行成功，已投递";
    }
    if (lastDeliveryStatus === "not-delivered" || lastDelivered === false) {
      return "执行成功，未投递";
    }
    return "执行成功";
  }
  if (lastRunStatus === "skipped") {
    return "已跳过";
  }
  if (lastRunStatus === "error" || lastRunStatus === "fail" || lastRunStatus === "failed") {
    return lastError ? `执行失败：${formatTaskResultPreview(lastError, "执行失败")}` : "执行失败";
  }
  if (lastDeliveryStatus === "delivered") {
    return "执行成功，已投递";
  }
  if (lastDeliveryStatus === "not-delivered") {
    return "执行成功，未投递";
  }
  if (lastDeliveryError) {
    return `投递失败：${formatTaskResultPreview(lastDeliveryError, "投递失败")}`;
  }
  if (lastError) {
    return `执行失败：${formatTaskResultPreview(lastError, "执行失败")}`;
  }
  return "";
}

export function mapCronJobToTaskRecord(
  gatewayIdValue: string,
  userId: string,
  job: Record<string, unknown>,
): TaskRecord | null {
  const id = readTaskString(job.id);
  if (!id) {
    return null;
  }

  const schedule = job.schedule && typeof job.schedule === "object" && !Array.isArray(job.schedule)
    ? (job.schedule as Record<string, unknown>)
    : undefined;
  const payload = job.payload && typeof job.payload === "object" && !Array.isArray(job.payload)
    ? (job.payload as Record<string, unknown>)
    : undefined;
  const state = job.state && typeof job.state === "object" && !Array.isArray(job.state)
    ? (job.state as Record<string, unknown>)
    : undefined;

  const prompt =
    readTaskString(payload?.message) ??
    readTaskString(payload?.text) ??
    readTaskString(job.description) ??
    "";
  const titleSource = prompt || readTaskString(job.description) || "";
  const title = readTaskString(job.name) ?? buildTaskTitle(titleSource, "定时任务");
  const enabled = readTaskBoolean(job.enabled) ?? true;
  const createdAtMs = readTaskNumber(job.createdAtMs);
  const updatedAtMs = readTaskNumber(job.updatedAtMs) ?? createdAtMs;
  const createdAt = createdAtMs !== undefined ? new Date(createdAtMs).toISOString() : nowIso();
  const updatedAt = updatedAtMs !== undefined ? new Date(updatedAtMs).toISOString() : createdAt;
  const nextRunAt = msToIsoTimestamp(state?.nextRunAtMs);
  const scheduleKindRaw = readTaskString(schedule?.kind)?.toLowerCase() ?? "";

  let scheduleKind: TaskScheduleKind = nextRunAt ? "repeat" : "once";
  let scheduleAt: string | undefined = nextRunAt ?? createdAt;
  let repeatAmount: number | undefined;
  let repeatUnit: TaskRepeatUnit | undefined;

  if (scheduleKindRaw === "at") {
    scheduleKind = "once";
    scheduleAt =
      msToIsoTimestamp(schedule?.atMs) ??
      readTaskString(schedule?.at) ??
      nextRunAt ??
      createdAt;
  } else if (scheduleKindRaw === "every") {
    scheduleKind = "repeat";
    const everyMs = readTaskNumber(schedule?.everyMs);
    if (everyMs !== undefined) {
      const repeat = deriveRepeatConfigFromEveryMs(everyMs);
      repeatAmount = repeat.repeatAmount;
      repeatUnit = repeat.repeatUnit;
    }
    scheduleAt =
      msToIsoTimestamp(schedule?.anchorMs) ??
      nextRunAt ??
      createdAt;
  } else if (scheduleKindRaw === "cron") {
    scheduleKind = "repeat";
    scheduleAt = nextRunAt ?? createdAt;
  }

  return {
    id,
    gatewayId: gatewayIdValue,
    userId,
    title,
    prompt,
    scheduleKind,
    scheduleAt,
    repeatAmount,
    repeatUnit,
    enabled,
    lastResult: buildTaskLastResultFromCronState(state),
    nextRunAt,
    createdAt,
    updatedAt,
  };
}

export function sortTaskRecords(tasks: TaskRecord[]): TaskRecord[] {
  return [...tasks].sort((left: TaskRecord, right: TaskRecord) => {
    if (left.enabled !== right.enabled) {
      return left.enabled ? -1 : 1;
    }
    const leftNext = left.nextRunAt ? Date.parse(left.nextRunAt) : Number.POSITIVE_INFINITY;
    const rightNext = right.nextRunAt ? Date.parse(right.nextRunAt) : Number.POSITIVE_INFINITY;
    if (leftNext !== rightNext) {
      return leftNext - rightNext;
    }
    return left.createdAt.localeCompare(right.createdAt);
  });
}

export function buildTaskRecordFromCronResponse(
  gatewayIdValue: string,
  userId: string,
  payload: unknown,
): TaskRecord | null {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    return null;
  }
  return mapCronJobToTaskRecord(gatewayIdValue, userId, payload as Record<string, unknown>);
}

export function normalizeTaskScheduleKind(value: unknown): TaskScheduleKind | undefined {
  if (value === "once" || value === "repeat") {
    return value;
  }
  return undefined;
}

export function normalizeTaskRepeatUnit(value: unknown): TaskRepeatUnit | undefined {
  if (value === "minutes" || value === "hours" || value === "days" || value === "weeks") {
    return value;
  }
  return undefined;
}

export function normalizeTaskRepeatAmount(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.max(1, Math.round(value));
  }
  if (typeof value === "string" && value.trim()) {
    const parsed = Number.parseInt(value.trim(), 10);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.max(1, Math.round(parsed));
    }
  }
  return undefined;
}

export function parseTaskDate(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = Date.parse(trimmed);
  if (!Number.isFinite(parsed)) return undefined;
  return new Date(parsed).toISOString();
}

export function taskRepeatIntervalMs(amount: number, unit: TaskRepeatUnit): number {
  const factors: Record<TaskRepeatUnit, number> = {
    minutes: 60 * 1000,
    hours: 60 * 60 * 1000,
    days: 24 * 60 * 60 * 1000,
    weeks: 7 * 24 * 60 * 60 * 1000,
  };
  return amount * factors[unit];
}

export function computeNextTaskRun(task: TaskRecord, reference = new Date()): string | undefined {
  const referenceMs = reference.getTime();
  if (task.scheduleKind === "once") {
    return task.scheduleAt;
  }

  const amount = task.repeatAmount ?? 1;
  const unit = task.repeatUnit ?? "days";
  const intervalMs = taskRepeatIntervalMs(amount, unit);
  const baseValue = task.nextRunAt ?? task.scheduleAt;
  const baseMs = baseValue ? Date.parse(baseValue) : referenceMs;
  if (!Number.isFinite(baseMs) || intervalMs <= 0) {
    return undefined;
  }

  let nextMs = baseMs;
  while (nextMs <= referenceMs) {
    nextMs += intervalMs;
  }
  return new Date(nextMs).toISOString();
}

export function buildTaskTitle(prompt: string, fallback = "定时任务"): string {
  const normalized = prompt.trim().replace(/\s+/g, " ");
  if (!normalized) return fallback;
  const sentence = normalized.split(/[。！？!?;；,，、\n]/).find((segment) => segment.trim().length > 0)?.trim() ?? normalized;
  return sentence.slice(0, 40);
}

export function formatTaskResultPreview(text: string, fallback: string): string {
  const normalized = text.trim().replace(/\s+/g, " ");
  if (!normalized) {
    return fallback;
  }
  return normalized.length > 160 ? `${normalized.slice(0, 160)}...` : normalized;
}

export function extractTaskResultText(payload: unknown): string {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return "";
  const record = payload as Record<string, unknown>;
  const message = record.message;
  if (message && typeof message === "object" && !Array.isArray(message)) {
    const messageRecord = message as Record<string, unknown>;
    if (Array.isArray(messageRecord.content)) {
      const text = messageRecord.content
        .filter((block): block is Record<string, unknown> => Boolean(block) && typeof block === "object" && !Array.isArray(block))
        .filter((block) => block.type === "text" && typeof block.text === "string")
        .map((block) => String(block.text))
        .join("\n\n")
        .trim();
      if (text) return text;
    }
  }
  for (const candidate of [record.text, record.result, record.output, record.content]) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim();
    }
  }
  return "";
}

export function normalizeTaskBody(
  body: Record<string, unknown>,
  existing?: TaskRecord,
): {
  title: string;
  prompt: string;
  scheduleKind: TaskScheduleKind;
  scheduleAt?: string;
  repeatAmount?: number;
  repeatUnit?: TaskRepeatUnit;
  enabled: boolean;
  error?: string;
} {
  const scheduleKind = normalizeTaskScheduleKind(body.scheduleKind) ?? existing?.scheduleKind ?? "once";
  const prompt = typeof body.prompt === "string" ? body.prompt.trim() : existing?.prompt ?? "";
  const rawTitle = typeof body.title === "string" ? body.title.trim() : existing?.title ?? "";
  const title = rawTitle || buildTaskTitle(prompt, existing?.title ?? "");
  const scheduleAt = parseTaskDate(body.scheduleAt) ?? existing?.scheduleAt;
  const repeatAmount =
    scheduleKind === "repeat" ? normalizeTaskRepeatAmount(body.repeatAmount) ?? existing?.repeatAmount : undefined;
  const repeatUnit =
    scheduleKind === "repeat" ? normalizeTaskRepeatUnit(body.repeatUnit) ?? existing?.repeatUnit : undefined;
  const enabled = typeof body.enabled === "boolean" ? body.enabled : existing?.enabled ?? true;

  if (!prompt) {
    return { title, prompt, scheduleKind, scheduleAt, repeatAmount, repeatUnit, enabled, error: "prompt_required" };
  }
  if (scheduleKind === "once" && !scheduleAt) {
    return { title, prompt, scheduleKind, scheduleAt, repeatAmount, repeatUnit, enabled, error: "schedule_at_required" };
  }
  if (scheduleKind === "repeat") {
    if (!scheduleAt) {
      return { title, prompt, scheduleKind, scheduleAt, repeatAmount, repeatUnit, enabled, error: "schedule_at_required" };
    }
    if (!repeatAmount || repeatAmount <= 0) {
      return { title, prompt, scheduleKind, scheduleAt, repeatAmount, repeatUnit, enabled, error: "repeat_amount_required" };
    }
    if (!repeatUnit) {
      return { title, prompt, scheduleKind, scheduleAt, repeatAmount, repeatUnit, enabled, error: "repeat_unit_required" };
    }
  }

  return {
    title,
    prompt,
    scheduleKind,
    scheduleAt,
    repeatAmount,
    repeatUnit,
    enabled,
  };
}

export function buildCronTaskMutationParams(normalized: {
  title: string;
  prompt: string;
  scheduleKind: TaskScheduleKind;
  scheduleAt?: string;
  repeatAmount?: number;
  repeatUnit?: TaskRepeatUnit;
  enabled: boolean;
}): Record<string, unknown> | null {
  const scheduleAt = normalized.scheduleAt?.trim();
  const payload = {
    kind: "agentTurn",
    message: normalized.prompt,
  };

  if (normalized.scheduleKind === "once") {
    if (!scheduleAt) {
      return null;
    }
    return {
      name: normalized.title,
      enabled: normalized.enabled,
      deleteAfterRun: true,
      schedule: { kind: "at", at: scheduleAt },
      payload,
    };
  }

  if (!scheduleAt || !normalized.repeatAmount || !normalized.repeatUnit) {
    return null;
  }

  const schedule: Record<string, unknown> = {
    kind: "every",
    everyMs: taskRepeatIntervalMs(normalized.repeatAmount, normalized.repeatUnit),
  };
  const anchorMs = Date.parse(scheduleAt);
  if (Number.isFinite(anchorMs) && anchorMs >= 0) {
    schedule.anchorMs = Math.round(anchorMs);
  }

  return {
    name: normalized.title,
    enabled: normalized.enabled,
    deleteAfterRun: false,
    schedule,
    payload,
  };
}
