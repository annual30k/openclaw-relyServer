import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { randomUUID } from "crypto";
import { WebSocket, WebSocketServer } from "ws";
import { loadConfig } from "./config.js";
import { addSeconds, gatewayCode, gatewayId, hashPassword, maskSensitive, nowIso, randomCode, randomSecret, safeJsonParse, sha256, signToken, verifyPassword, verifyToken } from "./security.js";
import { classifyRisk, isReadOnly, requiresApproval } from "./risk.js";
import { RelayStore } from "./store.js";
import type {
  GatewayMembershipRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  MobileDeviceRecord,
  RelayEnvelope,
  Role,
  TaskRecord,
  TaskRepeatUnit,
  TaskScheduleKind,
  UserRecord,
} from "./types.js";

const config = loadConfig();
const store = await RelayStore.create(config.databaseUrl);

type Metrics = {
  hostConnections: number;
  mobileConnections: number;
  commandRequests: number;
  commandFailures: number;
  wsReconnectKicks: number;
  highRiskCommands: number;
};

const metrics: Metrics = {
  hostConnections: 0,
  mobileConnections: 0,
  commandRequests: 0,
  commandFailures: 0,
  wsReconnectKicks: 0,
  highRiskCommands: 0,
};

type HostSession = {
  gatewayId: string;
  socket: WebSocket;
  lastSeenAt: string;
};

type MobileSession = {
  userId: string;
  deviceId: string;
  socket: WebSocket;
  lastSeenAt: string;
};

type PendingResponse = {
  socket: WebSocket;
  gatewayId: string;
  userId: string;
  method: string;
  startedAt: number;
  paramsMasked: string;
  riskLevel: "L1" | "L2" | "L3";
};

type PendingHostCommand = {
  gatewayId: string;
  userId: string;
  method: string;
  startedAt: number;
  paramsMasked: string;
  riskLevel: "L1" | "L2" | "L3";
  resolve: (payload: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
};

type PendingTaskRun = {
  taskId: string;
  gatewayId: string;
  userId: string;
  sessionKey: string;
  startedAt: number;
  timeout: NodeJS.Timeout;
};

type TokenClaims = {
  userId: string;
  deviceId: string;
  platform: string;
  appVersion?: string;
  exp: string;
  email?: string;
};

const hostSessions = new Map<string, HostSession>();
const mobileSessions = new Map<string, MobileSession>();
const pendingResponses = new Map<string, PendingResponse>();
const pendingHostCommands = new Map<string, PendingHostCommand>();
const rateLimitBuckets = new Map<string, number[]>();
const pendingTaskRunsBySessionKey = new Map<string, PendingTaskRun>();
const pendingTaskRunsByTaskID = new Map<string, PendingTaskRun>();
const taskRunTimeoutMs = 30 * 60 * 1000;

const hostWsServer = new WebSocketServer({ noServer: true });
const mobileWsServer = new WebSocketServer({ noServer: true });

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function text(res: ServerResponse, status: number, body: string, contentType = "text/plain; charset=utf-8"): void {
  res.writeHead(status, { "Content-Type": contentType });
  res.end(body);
}

async function readJson<T>(req: IncomingMessage): Promise<T | null> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) return null;
  return safeJsonParse<T>(Buffer.concat(chunks).toString("utf8"));
}

function normalizeGatewayRuntime(gatewayIdValue: string): GatewayRuntimeStateRecord {
  const current = store.snapshot().gatewayRuntimeState[gatewayIdValue];
  if (current) return current;
  return {
    gatewayId: gatewayIdValue,
    relayStatus: "offline",
    hostStatus: "offline",
    openclawStatus: "offline",
    aggregateStatus: "offline",
    mobileControlStatus: "idle",
  };
}

function computeAggregateStatus(runtime: GatewayRuntimeStateRecord): GatewayRuntimeStateRecord["aggregateStatus"] {
  if (runtime.hostStatus === "healthy" || runtime.openclawStatus === "healthy") return "healthy";
  if (runtime.hostStatus === "degraded" || runtime.openclawStatus === "degraded") return "degraded";
  if (runtime.hostStatus === "connecting_openclaw") return "connecting";
  if (runtime.relayStatus === "relay_connected") return "degraded";
  return "offline";
}

function touchGateway(gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>): void {
  const runtime = { ...normalizeGatewayRuntime(gatewayIdValue), ...patch };
  runtime.aggregateStatus = computeAggregateStatus(runtime);
  store.putRuntimeState(runtime);

  const gateway = store.snapshot().gateways[gatewayIdValue];
  if (gateway) {
    gateway.status = runtime.aggregateStatus;
    gateway.lastSeenAt = runtime.lastSeenAt ?? gateway.lastSeenAt;
    gateway.updatedAt = nowIso();
    store.putGateway(gateway);
  }
}

function getMembership(gatewayIdValue: string, userId: string): GatewayMembershipRecord | undefined {
  return store.snapshot().gatewayMemberships.find(
    (membership) => membership.gatewayId === gatewayIdValue && membership.userId === userId,
  );
}

function getUserIdFromRequest(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const claims = verifyToken<TokenClaims>(auth.slice("Bearer ".length), config.jwtSecret);
    if (claims && claims.exp > nowIso() && typeof claims.userId === "string" && claims.userId) {
      return claims.userId;
    }
  }
  return null;
}

function ensureUser(userId: string): UserRecord {
  const existing = store.snapshot().users[userId];
  if (existing) return existing;
  const user: UserRecord = { id: userId, email: `${userId}@local.invalid`, passwordHash: "", name: userId, createdAt: nowIso() };
  store.putUser(user);
  return user;
}

function makeAccessToken(user: UserRecord, deviceId: string, platform: string, appVersion: string): string {
  return signToken(
    {
      userId: user.id,
      email: user.email,
      deviceId,
      platform,
      appVersion,
      exp: addSeconds(new Date(), config.authTokenTtlSeconds),
    },
    config.jwtSecret,
  );
}

function findUserByEmail(email: string): UserRecord | undefined {
  const normalized = normalizeEmail(email);
  return Object.values(store.snapshot().users).find((user) => user.email.toLowerCase() === normalized);
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function requireAuthenticatedUser(req: IncomingMessage, res: ServerResponse): string | null {
  const userId = getUserIdFromRequest(req);
  if (!userId) {
    json(res, 401, { error: "unauthorized" });
    return null;
  }
  return userId;
}

function ensureRateLimit(scope: string, key: string): boolean {
  const bucketKey = `${scope}:${key}`;
  const now = Date.now();
  const from = now - config.rateLimitWindowMs;
  const bucket = (rateLimitBuckets.get(bucketKey) ?? []).filter((value) => value >= from);
  if (bucket.length >= config.rateLimitMax) {
    rateLimitBuckets.set(bucketKey, bucket);
    return false;
  }
  bucket.push(now);
  rateLimitBuckets.set(bucketKey, bucket);
  return true;
}

function toPositiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.round(value) : undefined;
}

function normalizeEventTimestamp(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.round(value > 10_000_000_000 ? value : value * 1000);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const trimmed = value.trim();
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric) && numeric > 0) {
      return Math.round(numeric > 10_000_000_000 ? numeric : numeric * 1000);
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.round(parsed);
    }
  }
  return undefined;
}

function normalizeRealtimeChatPayload(rawPayload: unknown, fallbackTimestamp = Date.now()): unknown {
  if (!rawPayload || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
    return rawPayload;
  }

  const payload = { ...(rawPayload as Record<string, unknown>) };
  const messageRecord =
    payload.message && typeof payload.message === "object" && !Array.isArray(payload.message)
      ? { ...(payload.message as Record<string, unknown>) }
      : undefined;
  const resolvedTimestamp =
    normalizeEventTimestamp(payload.ts)
    ?? normalizeEventTimestamp(payload.timestamp)
    ?? normalizeEventTimestamp(payload.createdAt)
    ?? normalizeEventTimestamp(payload.created_at)
    ?? normalizeEventTimestamp(payload.time)
    ?? normalizeEventTimestamp(messageRecord?.timestamp)
    ?? fallbackTimestamp;

  payload.ts = resolvedTimestamp;

  if (messageRecord) {
    messageRecord.timestamp = normalizeEventTimestamp(messageRecord.timestamp) ?? resolvedTimestamp;
    if (
      (!messageRecord.role || typeof messageRecord.role !== "string" || !messageRecord.role.trim())
      && typeof payload.role === "string"
      && payload.role.trim()
    ) {
      messageRecord.role = payload.role.trim();
    }
    payload.message = messageRecord;
  }

  return payload;
}

function extractContextMetrics(
  payloadRecord: Record<string, unknown> | undefined,
): Pick<GatewayRuntimeStateRecord, "contextUsage" | "contextLimit"> {
  const usageRecord =
    payloadRecord?.usage && typeof payloadRecord.usage === "object" && !Array.isArray(payloadRecord.usage)
      ? (payloadRecord.usage as Record<string, unknown>)
      : undefined;

  const contextUsage =
    toPositiveInteger(payloadRecord?.contextUsage) ??
    toPositiveInteger(payloadRecord?.promptTokens) ??
    toPositiveInteger(payloadRecord?.prompt_tokens) ??
    toPositiveInteger(payloadRecord?.inputTokens) ??
    toPositiveInteger(payloadRecord?.input_tokens) ??
    toPositiveInteger(usageRecord?.promptTokens) ??
    toPositiveInteger(usageRecord?.prompt_tokens) ??
    toPositiveInteger(usageRecord?.inputTokens) ??
    toPositiveInteger(usageRecord?.input_tokens);
  const contextLimit =
    toPositiveInteger(payloadRecord?.contextLimit) ??
    toPositiveInteger(payloadRecord?.maxInputTokens) ??
    toPositiveInteger(payloadRecord?.max_input_tokens) ??
    toPositiveInteger(usageRecord?.contextLimit) ??
    toPositiveInteger(usageRecord?.maxInputTokens) ??
    toPositiveInteger(usageRecord?.max_input_tokens);

  return {
    contextUsage,
    contextLimit,
  };
}

function buildGatewaySummary(gateway: GatewayRecord) {
  const runtime = normalizeGatewayRuntime(gateway.id);
  const lastSeenAt =
    normalizeSessionTimestamp(gateway.lastSeenAt)
    ?? normalizeSessionTimestamp(gateway.createdAt)
    ?? nowIso();
  return {
    gatewayId: gateway.id,
    displayName: gateway.displayName,
    platform: gateway.platform,
    aggregateStatus: runtime.aggregateStatus,
    relayStatus: runtime.relayStatus,
    hostStatus: runtime.hostStatus,
    openclawStatus: runtime.openclawStatus,
    mobileControlStatus: runtime.mobileControlStatus,
    lastSeenAt,
    currentModel: runtime.currentModel ?? "--",
    contextUsage: runtime.contextUsage,
    contextLimit: runtime.contextLimit,
  };
}

function sendSocket(socket: WebSocket, envelope: RelayEnvelope): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(envelope));
  }
}

function broadcastToGatewayMembers(gatewayIdValue: string, envelope: RelayEnvelope, excludedSocket?: WebSocket): void {
  const memberships = store.snapshot().gatewayMemberships.filter((membership) => membership.gatewayId === gatewayIdValue);
  for (const membership of memberships) {
    for (const session of mobileSessions.values()) {
      if (session.userId === membership.userId && session.socket !== excludedSocket) {
        sendSocket(session.socket, envelope);
      }
    }
  }
}

function failPending(id: string, code: string, message: string): void {
  const pending = pendingResponses.get(id);
  if (!pending) return;
  pendingResponses.delete(id);
  metrics.commandFailures += 1;
  sendSocket(pending.socket, { type: "res", id, gatewayId: pending.gatewayId, ok: false, error: { code, message } });
  store.addAuditLog({
    id: randomUUID(),
    gatewayId: pending.gatewayId,
    userId: pending.userId,
    method: pending.method,
    riskLevel: pending.riskLevel,
    paramsMasked: pending.paramsMasked,
    resultOk: false,
    errorCode: code,
    durationMs: Date.now() - pending.startedAt,
    createdAt: nowIso(),
  });
}

function failPendingHostCommand(id: string, code: string, message: string): void {
  const pending = pendingHostCommands.get(id);
  if (!pending) return;
  pendingHostCommands.delete(id);
  clearTimeout(pending.timeout);
  metrics.commandFailures += 1;
  pending.reject(new Error(`${code}: ${message}`));
  store.addAuditLog({
    id: randomUUID(),
    gatewayId: pending.gatewayId,
    userId: pending.userId,
    method: pending.method,
    riskLevel: pending.riskLevel,
    paramsMasked: pending.paramsMasked,
    resultOk: false,
    errorCode: code,
    durationMs: Date.now() - pending.startedAt,
    createdAt: nowIso(),
  });
}

async function dispatchHostCommand(
  gatewayIdValue: string,
  userId: string,
  method: string,
  params: unknown,
): Promise<unknown> {
  const host = hostSessions.get(gatewayIdValue);
  if (!host) {
    throw new Error("gateway_offline: Gateway is offline");
  }

  const requestId = randomUUID();
  const riskLevel = classifyRisk(method);
  const paramsMasked = maskSensitive(params);

  metrics.commandRequests += 1;
  if (riskLevel === "L3") metrics.highRiskCommands += 1;

  return await new Promise<unknown>((resolve, reject) => {
    const timeout = setTimeout(() => {
      failPendingHostCommand(requestId, "timeout", "Gateway command timed out");
    }, 15_000);

    pendingHostCommands.set(requestId, {
      gatewayId: gatewayIdValue,
      userId,
      method,
      startedAt: Date.now(),
      paramsMasked,
      riskLevel,
      resolve,
      reject,
      timeout,
    });

    sendSocket(host.socket, {
      type: "cmd",
      id: requestId,
      gatewayId: gatewayIdValue,
      method,
      params,
    });
  });
}

function normalizeTaskScheduleKind(value: unknown): TaskScheduleKind | undefined {
  if (value === "once" || value === "repeat") {
    return value;
  }
  return undefined;
}

function normalizeTaskRepeatUnit(value: unknown): TaskRepeatUnit | undefined {
  if (value === "minutes" || value === "hours" || value === "days" || value === "weeks") {
    return value;
  }
  return undefined;
}

function normalizeTaskRepeatAmount(value: unknown): number | undefined {
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

function parseTaskDate(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  const parsed = Date.parse(trimmed);
  if (!Number.isFinite(parsed)) return undefined;
  return new Date(parsed).toISOString();
}

function taskRepeatIntervalMs(amount: number, unit: TaskRepeatUnit): number {
  const factors: Record<TaskRepeatUnit, number> = {
    minutes: 60 * 1000,
    hours: 60 * 60 * 1000,
    days: 24 * 60 * 60 * 1000,
    weeks: 7 * 24 * 60 * 60 * 1000,
  };
  return amount * factors[unit];
}

function computeNextTaskRun(task: TaskRecord, reference = new Date()): string | undefined {
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

function buildTaskTitle(prompt: string, fallback = "定时任务"): string {
  const normalized = prompt.trim().replace(/\s+/g, " ");
  if (!normalized) return fallback;
  const sentence = normalized.split(/[。！？!?;；,，、\n]/).find((segment) => segment.trim().length > 0)?.trim() ?? normalized;
  return sentence.slice(0, 40);
}

function formatTaskResultPreview(text: string, fallback: string): string {
  const normalized = text.trim().replace(/\s+/g, " ");
  if (!normalized) {
    return fallback;
  }
  return normalized.length > 160 ? `${normalized.slice(0, 160)}...` : normalized;
}

function normalizeTaskBody(
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

function listGatewayTasks(gatewayIdValue: string): TaskRecord[] {
  return Object.values(store.snapshot().tasks)
    .filter((task) => task.gatewayId === gatewayIdValue)
    .sort((left, right) => {
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

function broadcastTaskUpdate(gatewayIdValue: string, taskId: string, event = "task_updated"): void {
  broadcastToGatewayMembers(gatewayIdValue, {
    type: "event",
    gatewayId: gatewayIdValue,
    event,
    payload: { taskId, gatewayId: gatewayIdValue },
  });
}

function extractTaskResultText(payload: unknown): string {
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

function updateTaskFromChatEvent(gatewayIdValue: string, eventName: string | undefined, payload: unknown): void {
  if (eventName !== "chat" && eventName !== "agent") return;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return;
  const record = payload as Record<string, unknown>;
  const sessionKey = typeof record.sessionKey === "string" ? record.sessionKey : "";
  const role = typeof record.role === "string" ? record.role.trim().toLowerCase() : "";
  if (role === "user") return;
  const taskMatch = sessionKey.match(/^task:([^:]+):/);
  if (!taskMatch?.[1]) return;
  const taskId = taskMatch[1];
  const task = store.snapshot().tasks[taskId];
  if (!task || task.gatewayId !== gatewayIdValue) return;

  const state = typeof record.state === "string"
    ? record.state
    : typeof record.phase === "string"
      ? record.phase
      : typeof record.data === "object" && record.data && !Array.isArray(record.data)
        ? String((record.data as Record<string, unknown>).phase ?? "")
        : "";
  const normalizedState = state.trim().toLowerCase();
  if (normalizedState && !["final", "done", "completed", "complete", "end", "failed", "error", "fail", "aborted"].includes(normalizedState)) {
    return;
  }

  const resultText = extractTaskResultText(payload);
  if (normalizedState === "failed" || normalizedState === "error" || normalizedState === "fail") {
    task.lastResult = resultText ? `执行失败：${formatTaskResultPreview(resultText, "执行失败")}` : "执行失败";
  } else if (normalizedState === "aborted") {
    task.lastResult = resultText ? `已中止：${formatTaskResultPreview(resultText, "已中止")}` : "已中止";
  } else {
    task.lastResult = formatTaskResultPreview(resultText, task.lastResult || "执行完成");
  }
  task.updatedAt = nowIso();
  store.putTask(task);
  const pending = pendingTaskRunsBySessionKey.get(sessionKey);
  if (pending) {
    clearTimeout(pending.timeout);
    pendingTaskRunsBySessionKey.delete(sessionKey);
    pendingTaskRunsByTaskID.delete(pending.taskId);
  }
  broadcastTaskUpdate(gatewayIdValue, task.id, "task_updated");
  schedulePersist();
}

async function runDueTasksOnce(): Promise<void> {
  const now = new Date();
  const dueTasks = Object.values(store.snapshot().tasks)
    .filter((task) => task.enabled)
    .filter((task) => {
      if (!task.nextRunAt) return false;
      const dueAt = Date.parse(task.nextRunAt);
      return Number.isFinite(dueAt) && dueAt <= now.getTime();
    })
    .sort((left, right) => Date.parse(left.nextRunAt ?? left.createdAt) - Date.parse(right.nextRunAt ?? right.createdAt));

  for (const task of dueTasks) {
    if (pendingTaskRunsByTaskID.has(task.id)) {
      continue;
    }

    const runSessionKey = `task:${task.id}:${randomUUID()}`;
    const timeout = setTimeout(() => {
      pendingTaskRunsBySessionKey.delete(runSessionKey);
      pendingTaskRunsByTaskID.delete(task.id);
    }, taskRunTimeoutMs);
    timeout.unref?.();
    const pendingRun: PendingTaskRun = {
      taskId: task.id,
      gatewayId: task.gatewayId,
      userId: task.userId,
      sessionKey: runSessionKey,
      startedAt: Date.now(),
      timeout,
    };
    pendingTaskRunsByTaskID.set(task.id, pendingRun);
    pendingTaskRunsBySessionKey.set(runSessionKey, pendingRun);

    task.lastResult = "正在执行...";
    if (task.scheduleKind === "once") {
      task.enabled = false;
      task.nextRunAt = undefined;
    } else {
      task.nextRunAt = computeNextTaskRun(task, now);
    }
    task.updatedAt = nowIso();
    store.putTask(task);
    broadcastTaskUpdate(task.gatewayId, task.id);
    schedulePersist();

    try {
      await dispatchHostCommand(task.gatewayId, task.userId, "chat.send", {
        sessionKey: runSessionKey,
        message: task.prompt,
        idempotencyKey: runSessionKey,
        runId: runSessionKey,
      });
      task.lastResult = "已触发，等待主机返回";
      task.updatedAt = nowIso();
      store.putTask(task);
      broadcastTaskUpdate(task.gatewayId, task.id);
      schedulePersist();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      task.lastResult = `执行失败：${message}`;
      const pending = pendingTaskRunsByTaskID.get(task.id);
      if (pending) {
        clearTimeout(pending.timeout);
        pendingTaskRunsByTaskID.delete(task.id);
        pendingTaskRunsBySessionKey.delete(pending.sessionKey);
      }
      if (task.scheduleKind === "once") {
        task.enabled = false;
        task.nextRunAt = undefined;
      } else {
        task.nextRunAt = computeNextTaskRun(task, new Date());
      }
      task.updatedAt = nowIso();
      store.putTask(task);
      broadcastTaskUpdate(task.gatewayId, task.id);
      schedulePersist();
    }
  }
}

type HostSkillStatusEntry = {
  skillKey?: string;
  blockedByAllowlist?: boolean;
};

type HostSkillsStatusReport = {
  skills?: HostSkillStatusEntry[];
};

function decodePathSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseStringRecord(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) return undefined;

  const record: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawValue !== "string") {
      return undefined;
    }
    record[key] = rawValue;
  }
  return record;
}

function hostCommandErrorResponse(error: unknown): { status: number; body: { error: string } } {
  const message = error instanceof Error ? error.message : String(error);
  const code = message.split(":")[0]?.trim() || "host_error";
  switch (code) {
  case "gateway_offline":
    return { status: 503, body: { error: code } };
  case "timeout":
    return { status: 504, body: { error: code } };
  case "skill_not_found":
    return { status: 404, body: { error: code } };
  case "skill_blocked":
    return { status: 403, body: { error: code } };
  default:
    return { status: 502, body: { error: code } };
  }
}

async function persist(): Promise<void> {
  store.cleanupExpired(nowIso());
  await store.save();
}

let scheduledPersistTimer: NodeJS.Timeout | undefined;
let scheduledPersistTask: Promise<void> | undefined;
let persistRequestedWhileRunning = false;

function schedulePersist(delayMs = 250): void {
  if (scheduledPersistTask) {
    persistRequestedWhileRunning = true;
    return;
  }
  if (scheduledPersistTimer) return;
  scheduledPersistTimer = setTimeout(() => {
    scheduledPersistTimer = undefined;
    scheduledPersistTask = persist()
      .catch((error) => {
        console.error("[relay] async persist failed", error);
      })
      .finally(() => {
        scheduledPersistTask = undefined;
        if (persistRequestedWhileRunning) {
          persistRequestedWhileRunning = false;
          schedulePersist();
        }
      });
  }, delayMs);
  scheduledPersistTimer.unref?.();
}

let scheduledTaskSweepTimer: NodeJS.Timeout | undefined;
let scheduledTaskSweepTask: Promise<void> | undefined;
let taskSweepRequestedWhileRunning = false;

function scheduleTaskSweep(delayMs = 1000): void {
  if (scheduledTaskSweepTask) {
    taskSweepRequestedWhileRunning = true;
    return;
  }
  if (scheduledTaskSweepTimer) return;
  scheduledTaskSweepTimer = setTimeout(() => {
    scheduledTaskSweepTimer = undefined;
    scheduledTaskSweepTask = runDueTasksOnce()
      .catch((error) => {
        console.error("[relay] task sweep failed", error);
      })
      .finally(() => {
        scheduledTaskSweepTask = undefined;
        if (taskSweepRequestedWhileRunning) {
          taskSweepRequestedWhileRunning = false;
          scheduleTaskSweep();
          return;
        }
        scheduleTaskSweep(15_000);
      });
  }, delayMs);
  scheduledTaskSweepTimer.unref?.();
}

function issueAccessCode(): string {
  const snapshot = store.snapshot();
  const now = nowIso();
  for (let attempts = 0; attempts < 20; attempts += 1) {
    const accessCode = randomCode();
    const accessCodeHash = sha256(accessCode);
    const isDuplicate = Object.values(snapshot.gatewayPairingCodes).some(
      (record) => !record.usedAt && record.expiresAt > now && record.accessCodeHash === accessCodeHash,
    );
    if (!isDuplicate) {
      return accessCode;
    }
  }
  throw new Error("failed_to_issue_unique_access_code");
}

function findPairingCodeByAccessCode(accessCode: string): { gateway: GatewayRecord; pairingCode: { gatewayId: string; accessCodeHash: string; expiresAt: string; usedAt?: string; createdAt: string } } | null {
  const accessCodeHash = sha256(accessCode);
  const snapshot = store.snapshot();
  for (const pairingCode of Object.values(snapshot.gatewayPairingCodes)) {
    if (pairingCode.accessCodeHash !== accessCodeHash) {
      continue;
    }
    const gateway = snapshot.gateways[pairingCode.gatewayId];
    if (!gateway) {
      continue;
    }
    return { gateway, pairingCode };
  }
  return null;
}

async function handleRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const displayName = typeof body.displayName === "string" && body.displayName.trim() ? body.displayName.trim() : "PocketClaw Host";
  const platform = typeof body.platform === "string" && body.platform.trim() ? body.platform.trim() : "unknown";
  const agentVersion = typeof body.agentVersion === "string" && body.agentVersion.trim() ? body.agentVersion.trim() : "unknown";

  const id = gatewayId();
  const relaySecret = randomSecret();
  const now = nowIso();
  const gateway: GatewayRecord = {
    id,
    gatewayCode: gatewayCode(),
    relaySecretHash: sha256(relaySecret),
    displayName,
    platform,
    agentVersion,
    status: "offline",
    createdAt: now,
    updatedAt: now,
  };

  store.putGateway(gateway);
  touchGateway(id, {
    relayStatus: "offline",
    hostStatus: "offline",
    openclawStatus: "offline",
    aggregateStatus: "offline",
    mobileControlStatus: "idle",
  });

  const accessCode = issueAccessCode();
  store.putPairingCode({
    gatewayId: id,
    accessCodeHash: sha256(accessCode),
    expiresAt: addSeconds(new Date(), config.accessCodeTtlSeconds),
    createdAt: now,
  });

  await persist();
  json(res, 200, {
    gatewayId: id,
    relaySecret,
    accessCode,
    expiresAt: store.snapshot().gatewayPairingCodes[id]?.expiresAt,
  });
}

async function handleAccessCode(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const gatewayIdValue = typeof body.gatewayId === "string" ? body.gatewayId : "";
  const relaySecret = typeof body.relaySecret === "string" ? body.relaySecret : "";
  const gateway = store.snapshot().gateways[gatewayIdValue];

  if (!gateway || sha256(relaySecret) !== gateway.relaySecretHash) {
    json(res, 401, { error: "invalid_gateway_credentials" });
    return;
  }

  const accessCode = issueAccessCode();
  const expiresAt = addSeconds(new Date(), config.accessCodeTtlSeconds);
  store.putPairingCode({
    gatewayId: gatewayIdValue,
    accessCodeHash: sha256(accessCode),
    expiresAt,
    createdAt: nowIso(),
  });
  await persist();
  json(res, 200, { gatewayId: gatewayIdValue, accessCode, expiresAt });
}

async function handleAuthRegister(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : email;
  const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
  const platform = typeof body.platform === "string" ? body.platform : "ios";
  const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";

  if (!email || !email.includes("@")) {
    json(res, 400, { error: "valid_email_required" });
    return;
  }
  if (password.length < 8) {
    json(res, 400, { error: "password_too_short" });
    return;
  }
  if (findUserByEmail(email)) {
    json(res, 409, { error: "email_already_registered" });
    return;
  }

  const user: UserRecord = {
    id: `user_${randomUUID().replace(/-/g, "").slice(0, 12)}`,
    email,
    passwordHash: hashPassword(password),
    name,
    createdAt: nowIso(),
  };
  store.putUser(user);
  store.putMobileDevice({
    id: deviceId,
    userId: user.id,
    platform,
    appVersion,
    createdAt: nowIso(),
    lastSeenAt: nowIso(),
  });
  await persist();

  json(res, 200, {
    accessToken: makeAccessToken(user, deviceId, platform, appVersion),
    user: { id: user.id, email: user.email, name: user.name },
    deviceId,
  });
}

async function handleAuthLogin(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
  const password = typeof body.password === "string" ? body.password : "";
  const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
  const platform = typeof body.platform === "string" ? body.platform : "ios";
  const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";
  const user = findUserByEmail(email);

  if (!user || !verifyPassword(password, user.passwordHash)) {
    json(res, 401, { error: "invalid_credentials" });
    return;
  }

  store.putMobileDevice({
    id: deviceId,
    userId: user.id,
    platform,
    appVersion,
    createdAt: nowIso(),
    lastSeenAt: nowIso(),
  });
  await persist();

  json(res, 200, {
    accessToken: makeAccessToken(user, deviceId, platform, appVersion),
    user: { id: user.id, email: user.email, name: user.name },
    deviceId,
  });
}

async function handleMobilePair(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const gatewayIdValue = typeof body.gatewayId === "string" ? body.gatewayId : "";
  const accessCode = typeof body.accessCode === "string" ? body.accessCode : "";
  const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
  const platform = typeof body.platform === "string" ? body.platform : "ios";
  const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";

  let resolvedGatewayId = gatewayIdValue.trim();
  let gateway = resolvedGatewayId ? store.snapshot().gateways[resolvedGatewayId] : undefined;
  let pairingCode = resolvedGatewayId ? store.snapshot().gatewayPairingCodes[resolvedGatewayId] : undefined;

  if (!accessCode.trim()) {
    json(res, 400, { error: "pairing_code_required" });
    return;
  }

  if (!resolvedGatewayId) {
    const resolved = findPairingCodeByAccessCode(accessCode);
    if (!resolved) {
      json(res, 404, { error: "pairing_code_not_found" });
      return;
    }
    resolvedGatewayId = resolved.gateway.id;
    gateway = resolved.gateway;
    pairingCode = resolved.pairingCode;
  }

  if (!gateway || !pairingCode) {
    json(res, 404, { error: "pairing_code_not_found" });
    return;
  }
  if (pairingCode.expiresAt <= nowIso()) {
    json(res, 410, { error: "pairing_code_expired" });
    return;
  }
  if (sha256(accessCode) !== pairingCode.accessCodeHash) {
    json(res, 401, { error: "pairing_code_invalid" });
    return;
  }

  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const user = store.snapshot().users[userId];
  if (!user) {
    json(res, 401, { error: "unknown_user" });
    return;
  }

  const existingMembership = getMembership(resolvedGatewayId, userId);
  const existingOwner = store.snapshot().gatewayMemberships.find((membership) => membership.gatewayId === resolvedGatewayId && membership.role === "owner");
  let role: Role;
  if (existingMembership) {
    role = existingMembership.role;
  } else if (!existingOwner) {
    role = "owner";
  } else {
    json(res, 403, { error: "gateway_already_bound_to_another_account" });
    return;
  }

  if (!gateway.ownerUserId) {
    gateway.ownerUserId = userId;
    gateway.updatedAt = nowIso();
    store.putGateway(gateway);
  }

  if (!existingMembership) {
    store.putMembership({
      gatewayId: resolvedGatewayId,
      userId,
      role,
      createdAt: nowIso(),
    });
  }

  const device: MobileDeviceRecord = {
    id: deviceId,
    userId,
    platform,
    appVersion,
    createdAt: nowIso(),
    lastSeenAt: nowIso(),
  };
  store.putMobileDevice(device);

  pairingCode.usedAt = nowIso();
  store.putPairingCode(pairingCode);

  const accessToken = makeAccessToken(user, deviceId, platform, appVersion);

  await persist();
  json(res, 200, {
    accessToken,
    userId,
    deviceId,
    role,
    gateway: buildGatewaySummary(gateway),
  });
}

async function handleGatewayList(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const gateways = store.snapshot().gatewayMemberships
    .filter((membership) => membership.userId === userId)
    .map((membership) => {
      const gateway = store.snapshot().gateways[membership.gatewayId];
      return gateway ? { ...buildGatewaySummary(gateway), role: membership.role } : null;
    })
    .filter(Boolean);
  json(res, 200, { gateways });
}

async function handleGatewayDetail(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  const gateway = store.snapshot().gateways[gatewayIdValue];
  if (!membership || !gateway) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  json(res, 200, {
    gateway: {
      ...buildGatewaySummary(gateway),
      role: membership.role,
      runtime: normalizeGatewayRuntime(gatewayIdValue),
    },
  });
}

async function handleGatewayDelete(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  store.removeMembership(gatewayIdValue, userId);
  const runtime = normalizeGatewayRuntime(gatewayIdValue);
  if (runtime.controllerUserId === userId) {
    runtime.controllerUserId = undefined;
    runtime.controllerDeviceId = undefined;
    runtime.mobileControlStatus = "idle";
    store.putRuntimeState(runtime);
  }
  await persist();
  json(res, 200, { ok: true });
}

async function handleGatewayUpdate(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  const gateway = store.snapshot().gateways[gatewayIdValue];
  if (!membership || !gateway) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
  if (!displayName) {
    json(res, 400, { error: "display_name_required" });
    return;
  }
  if (displayName.length > 191) {
    json(res, 400, { error: "display_name_too_long" });
    return;
  }

  gateway.displayName = displayName;
  gateway.updatedAt = nowIso();
  store.putGateway(gateway);

  await persist();

  broadcastToGatewayMembers(gatewayIdValue, {
    type: "presence",
    gatewayId: gatewayIdValue,
    payload: buildGatewaySummary(gateway),
  });

  json(res, 200, {
    gateway: {
      ...buildGatewaySummary(gateway),
      role: membership.role,
    },
  });
}

async function handleGatewayModels(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "pocketclaw.model.list", {});
    touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: nowIso(),
    });
    schedulePersist();
    const result = (payload ?? {}) as { items?: unknown[] };
    const runtime = normalizeGatewayRuntime(gatewayIdValue);
    const currentModel = runtime.currentModel;
    const items = Array.isArray(result.items)
      ? result.items.map((item) => {
          if (!item || typeof item !== "object" || Array.isArray(item)) return item;
          const record = { ...(item as Record<string, unknown>) };
          if (typeof currentModel === "string" && currentModel.length > 0) {
            record.isSelected = record["alias"] === currentModel || record["name"] === currentModel;
          }
          return record;
        })
      : [];
    json(res, 200, { items });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

async function handleGatewaySkills(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "skills.status", {});
    touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: nowIso(),
    });
    schedulePersist();
    json(res, 200, payload ?? { skills: [] });
  } catch (error) {
    const response = hostCommandErrorResponse(error);
    json(res, response.status, response.body);
  }
}

async function handleGatewayTasks(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  if (req.method === "GET") {
    json(res, 200, { items: listGatewayTasks(gatewayIdValue) });
    return;
  }

  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const body = (await readJson<Record<string, unknown>>(req)) ?? {};

  if (req.method === "POST") {
    const normalized = normalizeTaskBody(body);
    if (normalized.error) {
      json(res, 400, { error: normalized.error });
      return;
    }

    const taskId = `task_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
    const now = nowIso();
    const task: TaskRecord = {
      id: taskId,
      gatewayId: gatewayIdValue,
      userId,
      title: normalized.title,
      prompt: normalized.prompt,
      scheduleKind: normalized.scheduleKind,
      scheduleAt: normalized.scheduleAt,
      repeatAmount: normalized.repeatAmount,
      repeatUnit: normalized.repeatUnit,
      enabled: normalized.enabled,
      lastResult: "",
      nextRunAt: normalized.scheduleKind === "repeat" ? computeNextTaskRun({
        id: taskId,
        gatewayId: gatewayIdValue,
        userId,
        title: normalized.title,
        prompt: normalized.prompt,
        scheduleKind: normalized.scheduleKind,
        scheduleAt: normalized.scheduleAt,
        repeatAmount: normalized.repeatAmount,
        repeatUnit: normalized.repeatUnit,
        enabled: normalized.enabled,
        lastResult: "",
        nextRunAt: undefined,
        createdAt: now,
        updatedAt: now,
      }, new Date(now)) : normalized.scheduleAt,
      createdAt: now,
      updatedAt: now,
    };
    if (!task.nextRunAt && task.scheduleKind === "once") {
      task.nextRunAt = task.scheduleAt;
    }
    store.putTask(task);
    await persist();
    broadcastTaskUpdate(gatewayIdValue, task.id);
    scheduleTaskSweep(0);
    json(res, 200, { task });
    return;
  }

  json(res, 405, { error: "method_not_allowed" });
}

async function handleGatewayTask(
  req: IncomingMessage,
  res: ServerResponse,
  gatewayIdValue: string,
  taskIdValue: string,
): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  const task = store.snapshot().tasks[taskIdValue];
  if (!task || task.gatewayId !== gatewayIdValue) {
    json(res, 404, { error: "task_not_found" });
    return;
  }

  if (req.method === "DELETE") {
    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }
    const pending = pendingTaskRunsByTaskID.get(taskIdValue);
    if (pending) {
      clearTimeout(pending.timeout);
      pendingTaskRunsByTaskID.delete(taskIdValue);
    }
    store.removeTask(taskIdValue);
    await persist();
    broadcastTaskUpdate(gatewayIdValue, taskIdValue);
    scheduleTaskSweep(0);
    json(res, 200, { ok: true });
    return;
  }

  if (req.method !== "PATCH") {
    json(res, 405, { error: "method_not_allowed" });
    return;
  }

  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const normalized = normalizeTaskBody(body, task);
  if (normalized.error) {
    json(res, 400, { error: normalized.error });
    return;
  }

  task.title = normalized.title;
  task.prompt = normalized.prompt;
  task.scheduleKind = normalized.scheduleKind;
  task.scheduleAt = normalized.scheduleAt;
  task.repeatAmount = normalized.repeatAmount;
  task.repeatUnit = normalized.repeatUnit;
  task.enabled = normalized.enabled;

  const scheduleFieldsChanged =
    body.title !== undefined ||
    body.prompt !== undefined ||
    body.scheduleKind !== undefined ||
    body.scheduleAt !== undefined ||
    body.repeatAmount !== undefined ||
    body.repeatUnit !== undefined;
  if (scheduleFieldsChanged || task.enabled) {
    task.nextRunAt = computeNextTaskRun(task, new Date());
  }
  task.updatedAt = nowIso();
  store.putTask(task);
  await persist();
  broadcastTaskUpdate(gatewayIdValue, task.id);
  scheduleTaskSweep(0);
  json(res, 200, { task });
}

async function handleGatewaySkillUpdate(
  req: IncomingMessage,
  res: ServerResponse,
  gatewayIdValue: string,
  skillKeyValue: string,
): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const skillKeyRaw = skillKeyValue.trim();
  if (!skillKeyRaw) {
    json(res, 400, { error: "skill_key_required" });
    return;
  }

  const enabledProvided = typeof body.enabled === "boolean";
  if (body.enabled !== undefined && !enabledProvided) {
    json(res, 400, { error: "enabled_invalid" });
    return;
  }

  const apiKeyProvided = body.apiKey !== undefined;
  if (apiKeyProvided && typeof body.apiKey !== "string") {
    json(res, 400, { error: "api_key_invalid" });
    return;
  }

  const envProvided = body.env !== undefined;
  const env = parseStringRecord(body.env);
  if (envProvided && (body.env === null || env === undefined)) {
    json(res, 400, { error: "env_invalid" });
    return;
  }

  const hasEnvEntries = env !== undefined && Object.keys(env).length > 0;

  if (!enabledProvided && !apiKeyProvided && !hasEnvEntries) {
    json(res, 400, { error: "update_payload_required" });
    return;
  }

  try {
    const report = await dispatchHostCommand(gatewayIdValue, userId, "skills.status", {});
    const statusReport = report as HostSkillsStatusReport | null | undefined;
    const currentSkill = statusReport?.skills?.find((skill) => skill && skill.skillKey === skillKeyRaw);
    if (!currentSkill) {
      json(res, 404, { error: "skill_not_found" });
      return;
    }
    if (body.enabled === true && currentSkill.blockedByAllowlist) {
      json(res, 403, { error: "skill_blocked" });
      return;
    }

    const updateParams: Record<string, unknown> = { skillKey: skillKeyRaw };
    if (enabledProvided) updateParams.enabled = body.enabled;
    if (apiKeyProvided) updateParams.apiKey = body.apiKey;
    if (envProvided && env !== undefined) updateParams.env = env;

    const payload = await dispatchHostCommand(gatewayIdValue, userId, "skills.update", updateParams);
    touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: nowIso(),
    });
    schedulePersist();
    json(res, 200, payload ?? { ok: true });
  } catch (error) {
    const response = hostCommandErrorResponse(error);
    json(res, response.status, response.body);
  }
}

async function handleGatewayChatHistory(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string, requestUrl: URL): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  const sessionKey = requestUrl.searchParams.get("sessionKey")?.trim() || "main";
  const requestedLimit = Number.parseInt(requestUrl.searchParams.get("limit") ?? "100", 10);
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 200)) : 100;

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "chat.history", {
      sessionKey,
      limit,
    });
    touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: nowIso(),
    });
    schedulePersist();
    const result = (payload ?? {}) as { messages?: unknown[] };
    const items = Array.isArray(result.messages)
      ? result.messages.flatMap((entry, index) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
          const record = entry as Record<string, unknown>;
          const role = typeof record.role === "string" ? record.role : "assistant";
          const createdAt =
            normalizeSessionTimestamp(record.createdAt)
            ?? normalizeSessionTimestamp(record.created_at)
            ?? normalizeSessionTimestamp(record.timestamp)
            ?? normalizeSessionTimestamp(record.ts)
            ?? normalizeSessionTimestamp(record.time);
          const content = Array.isArray(record.content)
            ? record.content
                .filter((block): block is Record<string, unknown> => Boolean(block) && typeof block === "object" && !Array.isArray(block))
                .filter((block) => block.type === "text" && typeof block.text === "string")
                .map((block) => String(block.text))
                .join("\n\n")
                .trim()
            : "";
          const normalizedContent = normalizeHistoryMessageContent(role, content);
          if (!normalizedContent) return [];
          return [{
            id: `history-${index}`,
            role,
            content: normalizedContent,
            createdAt,
          }];
        })
      : [];
    json(res, 200, { items });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

function normalizeSessionTimestamp(value: unknown): string | undefined {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  if (typeof value === "string") {
    const trimmedValue = value.trim();
    if (!trimmedValue) return undefined;
    const parsed = Date.parse(trimmedValue);
    if (!Number.isNaN(parsed)) {
      return new Date(parsed).toISOString();
    }
    return trimmedValue;
  }
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    const millis = value > 10_000_000_000 ? value : value * 1000;
    return new Date(millis).toISOString();
  }
  return undefined;
}

function normalizeHistoryMessageContent(role: string, content: string): string {
  const trimmed = content.trim();
  if (!trimmed || role !== "user") {
    return trimmed;
  }

  // Command-mode user turns can be persisted as a synthetic prompt bundle:
  // "System: [...] ...\n\n[time] actual user input". For mobile chat display,
  // keep only the actual user-entered portion so it can reconcile with the
  // optimistic local user bubble.
  const looksLikeSyntheticPrompt =
    /^System:\s*\[[^\]]+\]/.test(trimmed) && /\n\s*\n+\[[^\]]+\]\s*/.test(trimmed);
  if (!looksLikeSyntheticPrompt) {
    return trimmed;
  }

  const trailingBlock = trimmed
    .split(/\n\s*\n+/)
    .map((segment) => segment.trim())
    .filter(Boolean)
    .reverse()
    .find((segment) => !segment.startsWith("System:"));

  if (!trailingBlock) {
    return trimmed;
  }

  const normalized = trailingBlock.replace(/^\[[^\]]+\]\s*/, "").trim();
  return normalized || trimmed;
}

async function handleGatewayChatSessions(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string, requestUrl: URL): Promise<void> {
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }

  const requestedLimit = Number.parseInt(requestUrl.searchParams.get("limit") ?? "20", 10);
  const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 100)) : 20;

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "chat.list", { limit });
    touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: nowIso(),
    });
    schedulePersist();

    const payloadRecord = (payload && typeof payload === "object" && !Array.isArray(payload))
      ? (payload as Record<string, unknown>)
      : undefined;
    const rawItems =
      Array.isArray(payloadRecord?.items) ? payloadRecord.items
        : Array.isArray(payloadRecord?.sessions) ? payloadRecord.sessions
          : Array.isArray(payloadRecord?.list) ? payloadRecord.list
            : Array.isArray(payload) ? payload as unknown[]
              : [];

    const deduped = new Set<string>();
    const items = rawItems.flatMap((entry) => {
      if (typeof entry === "string") {
        const sessionKey = entry.trim();
        if (!sessionKey || deduped.has(sessionKey)) return [];
        deduped.add(sessionKey);
        return [{ sessionKey, lastActivityAt: undefined }];
      }
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
      const record = entry as Record<string, unknown>;
      const sessionKeyRaw =
        typeof record.sessionKey === "string" ? record.sessionKey
          : typeof record.key === "string" ? record.key
            : typeof record.id === "string" ? record.id
              : typeof record.session === "string" ? record.session
                : undefined;
      const sessionKey = sessionKeyRaw?.trim();
      if (!sessionKey || deduped.has(sessionKey)) return [];
      deduped.add(sessionKey);
      const lastActivityAt =
        normalizeSessionTimestamp(record.lastActivityAt)
        ?? normalizeSessionTimestamp(record.lastMessageAt)
        ?? normalizeSessionTimestamp(record.updatedAt)
        ?? normalizeSessionTimestamp(record.lastSeenAt)
        ?? normalizeSessionTimestamp(record.createdAt);
      return [{ sessionKey, lastActivityAt }];
    });

    items.sort((a, b) => {
      const aTime = a.lastActivityAt ? Date.parse(a.lastActivityAt) : 0;
      const bTime = b.lastActivityAt ? Date.parse(b.lastActivityAt) : 0;
      return bTime - aTime;
    });

    json(res, 200, { items });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

async function handleGatewayDefaultModelSelect(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const providerId = typeof body.providerId === "string" ? body.providerId.trim() : "";
  const modelId = typeof body.modelId === "string" ? body.modelId.trim() : "";
  const modelAlias = typeof body.modelAlias === "string" ? body.modelAlias.trim() : "";
  if (!providerId || !modelId) {
    json(res, 400, { error: "providerId_and_modelId_required" });
    return;
  }

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "pocketclaw.model.setDefault", {
      providerId,
      modelId,
      modelAlias,
    });
    const gateway = store.snapshot().gateways[gatewayIdValue];
    if (gateway) {
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "presence",
        gatewayId: gatewayIdValue,
        payload: buildGatewaySummary(gateway),
      });
    }
    broadcastToGatewayMembers(gatewayIdValue, {
      type: "event",
      gatewayId: gatewayIdValue,
      event: "default_model_updated",
      payload: {
        providerId,
        modelId,
        modelAlias,
      },
    });
    json(res, 200, { ok: true, payload });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

async function handleGatewayModelSelect(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership) {
    json(res, 404, { error: "gateway_not_found" });
    return;
  }
  if (membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }

  const providerId = typeof body.providerId === "string" ? body.providerId.trim() : "";
  const modelId = typeof body.modelId === "string" ? body.modelId.trim() : "";
  const modelAliasRaw = typeof body.modelAlias === "string" ? body.modelAlias.trim() : "";
  const modelName = typeof body.modelName === "string" ? body.modelName.trim() : "";
  const modelAlias = modelAliasRaw || modelName || modelId;
  if (!providerId || !modelId || !modelAlias) {
    json(res, 400, { error: "providerId_modelId_and_modelName_required" });
    return;
  }

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "chat.send", {
      sessionKey: "main",
      message: `/model ${modelAlias}`,
      idempotencyKey: randomUUID(),
    });
    touchGateway(gatewayIdValue, {
      currentModel: modelAlias,
      lastSeenAt: nowIso(),
    });
    schedulePersist();

    const gateway = store.snapshot().gateways[gatewayIdValue];
    if (gateway) {
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "presence",
        gatewayId: gatewayIdValue,
        payload: buildGatewaySummary(gateway),
      });
    }
    broadcastToGatewayMembers(gatewayIdValue, {
      type: "event",
      gatewayId: gatewayIdValue,
      event: "model_selected",
      payload: {
        providerId,
        modelId,
        modelAlias,
        modelName,
        currentModel: modelAlias,
      },
    });

    json(res, 200, { ok: true, payload });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

async function handleApproveSensitiveAction(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = requireAuthenticatedUser(req, res);
  if (!userId) return;
  const membership = getMembership(gatewayIdValue, userId);
  if (!membership || membership.role === "viewer") {
    json(res, 403, { error: "forbidden" });
    return;
  }
  const method = typeof body.method === "string" ? body.method : "";
  if (!method || !requiresApproval(method)) {
    json(res, 400, { error: "method_not_sensitive" });
    return;
  }
  const ttlSeconds =
    typeof body.ttlSeconds === "number" && Number.isFinite(body.ttlSeconds)
      ? Math.max(30, Math.min(900, body.ttlSeconds))
      : config.approvalTtlSeconds;
  store.addApproval({
    gatewayId: gatewayIdValue,
    userId,
    method,
    createdAt: nowIso(),
    expiresAt: addSeconds(new Date(), ttlSeconds),
  });
  await persist();
  json(res, 200, { ok: true, gatewayId: gatewayIdValue, method, expiresAt: addSeconds(new Date(), ttlSeconds) });
}

function metricsText(): string {
  const onlineGateways = Array.from(hostSessions.keys()).length;
  return [
    "# HELP relay_online_gateways Number of gateways with an online host session",
    "# TYPE relay_online_gateways gauge",
    `relay_online_gateways ${onlineGateways}`,
    "# HELP relay_host_connections Total active host websocket connections",
    "# TYPE relay_host_connections gauge",
    `relay_host_connections ${metrics.hostConnections}`,
    "# HELP relay_mobile_connections Total active mobile websocket connections",
    "# TYPE relay_mobile_connections gauge",
    `relay_mobile_connections ${metrics.mobileConnections}`,
    "# HELP relay_command_requests_total Total command requests",
    "# TYPE relay_command_requests_total counter",
    `relay_command_requests_total ${metrics.commandRequests}`,
    "# HELP relay_command_failures_total Total command failures",
    "# TYPE relay_command_failures_total counter",
    `relay_command_failures_total ${metrics.commandFailures}`,
    "# HELP relay_high_risk_commands_total Total high risk commands",
    "# TYPE relay_high_risk_commands_total counter",
    `relay_high_risk_commands_total ${metrics.highRiskCommands}`,
    "",
  ].join("\n");
}

const server = createServer((req, res) => {
  void (async () => {
    try {
      const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
      const clientIp = (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim() ?? req.socket.remoteAddress ?? "unknown";

      if (!ensureRateLimit("http", clientIp)) {
        json(res, 429, { error: "rate_limited" });
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/healthz") {
        json(res, 200, { ok: true, status: "healthy", now: nowIso() });
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/metrics") {
        text(res, 200, metricsText(), "text/plain; version=0.0.4; charset=utf-8");
        return;
      }

      if (req.method === "POST" && requestUrl.pathname === "/api/relay/register") {
        await handleRegister(req, res);
        return;
      }

      if (req.method === "POST" && requestUrl.pathname === "/api/auth/register") {
        await handleAuthRegister(req, res);
        return;
      }

      if (req.method === "POST" && requestUrl.pathname === "/api/auth/login") {
        await handleAuthLogin(req, res);
        return;
      }

      if (
        req.method === "POST" &&
        (requestUrl.pathname === "/api/relay/access-code" || requestUrl.pathname === "/api/relay/accesscode")
      ) {
        await handleAccessCode(req, res);
        return;
      }

      if (req.method === "POST" && requestUrl.pathname === "/api/mobile/pair") {
        await handleMobilePair(req, res);
        return;
      }

      if (req.method === "GET" && requestUrl.pathname === "/api/mobile/gateways") {
        await handleGatewayList(req, res);
        return;
      }

      const detailMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)$/);
      if (detailMatch && req.method === "GET") {
        await handleGatewayDetail(req, res, detailMatch[1]);
        return;
      }
      if (detailMatch && req.method === "PATCH") {
        await handleGatewayUpdate(req, res, detailMatch[1]);
        return;
      }
      if (detailMatch && req.method === "DELETE") {
        await handleGatewayDelete(req, res, detailMatch[1]);
        return;
      }

      const modelsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models$/);
      if (modelsMatch && req.method === "GET") {
        await handleGatewayModels(req, res, modelsMatch[1]);
        return;
      }

      const skillsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/skills$/);
      if (skillsMatch && req.method === "GET") {
        await handleGatewaySkills(req, res, skillsMatch[1]);
        return;
      }

      const tasksMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/tasks$/);
      if (tasksMatch && (req.method === "GET" || req.method === "POST")) {
        await handleGatewayTasks(req, res, decodePathSegment(tasksMatch[1]));
        return;
      }

      const taskDetailMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/tasks\/([^/]+)$/);
      if (taskDetailMatch && (req.method === "PATCH" || req.method === "DELETE")) {
        await handleGatewayTask(
          req,
          res,
          decodePathSegment(taskDetailMatch[1]),
          decodePathSegment(taskDetailMatch[2]),
        );
        return;
      }

      const skillUpdateMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/skills\/([^/]+)$/);
      if (skillUpdateMatch && req.method === "PATCH") {
        await handleGatewaySkillUpdate(req, res, decodePathSegment(skillUpdateMatch[1]), decodePathSegment(skillUpdateMatch[2]));
        return;
      }

      const chatHistoryMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/history$/);
      if (chatHistoryMatch && req.method === "GET") {
        await handleGatewayChatHistory(req, res, chatHistoryMatch[1], requestUrl);
        return;
      }

      const chatSessionsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/sessions$/);
      if (chatSessionsMatch && req.method === "GET") {
        await handleGatewayChatSessions(req, res, chatSessionsMatch[1], requestUrl);
        return;
      }

      const modelSelectMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models\/select$/);
      if (modelSelectMatch && req.method === "POST") {
        await handleGatewayModelSelect(req, res, modelSelectMatch[1]);
        return;
      }

      const defaultModelSelectMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models\/default$/);
      if (defaultModelSelectMatch && req.method === "POST") {
        await handleGatewayDefaultModelSelect(req, res, defaultModelSelectMatch[1]);
        return;
      }

      const approvalMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/approve-sensitive-action$/);
      if (approvalMatch && req.method === "POST") {
        await handleApproveSensitiveAction(req, res, approvalMatch[1]);
        return;
      }

      json(res, 404, { error: "not_found" });
    } catch (error) {
      console.error("[relay] http handler failed", error);
      if (!res.headersSent) {
        json(res, 500, { error: "internal_error" });
        return;
      }
      res.end();
    }
  })();
});

server.on("upgrade", (req, socket, head) => {
  const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (requestUrl.pathname === "/relay/ws" || /^\/relay\/[^/]+$/.test(requestUrl.pathname)) {
    hostWsServer.handleUpgrade(req, socket, head, (ws) => hostWsServer.emit("connection", ws, req));
    return;
  }
  if (requestUrl.pathname === "/mobile/ws") {
    mobileWsServer.handleUpgrade(req, socket, head, (ws) => mobileWsServer.emit("connection", ws, req));
    return;
  }
  socket.destroy();
});

hostWsServer.on("connection", async (socket, req) => {
  const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const gatewayIdValue =
    requestUrl.searchParams.get("gatewayId") ??
    requestUrl.pathname.match(/^\/relay\/([^/]+)$/)?.[1] ??
    "";
  const secret = requestUrl.searchParams.get("secret") ?? "";
  const gateway = store.snapshot().gateways[gatewayIdValue];

  if (!gateway || sha256(secret) !== gateway.relaySecretHash) {
    socket.close(4401, "unauthorized");
    return;
  }

  const previous = hostSessions.get(gatewayIdValue);
  if (previous) {
    metrics.wsReconnectKicks += 1;
    previous.socket.close(4000, "replaced_by_new_host");
  }

  hostSessions.set(gatewayIdValue, { gatewayId: gatewayIdValue, socket, lastSeenAt: nowIso() });
  metrics.hostConnections = hostSessions.size;
  touchGateway(gatewayIdValue, {
    relayStatus: "relay_connected",
    hostStatus: "relay_connected",
    lastSeenAt: nowIso(),
  });
  schedulePersist();

  broadcastToGatewayMembers(gatewayIdValue, {
    type: "presence",
    gatewayId: gatewayIdValue,
    payload: buildGatewaySummary(gateway),
  });

  socket.on("message", async (raw) => {
    const message = safeJsonParse<RelayEnvelope>(raw.toString());
    if (!message?.type) return;
    console.log(`[relay-host] gateway=${gatewayIdValue} type=${message.type}`);

    const session = hostSessions.get(gatewayIdValue);
    if (session) session.lastSeenAt = nowIso();

    if (message.type === "hello") {
      const platform = typeof message.platform === "string" ? message.platform : gateway.platform;
      const agentVersion = typeof message.agentVersion === "string" ? message.agentVersion : gateway.agentVersion;
      gateway.platform = platform;
      gateway.agentVersion = agentVersion;
      gateway.updatedAt = nowIso();
      store.putGateway(gateway);
      touchGateway(gatewayIdValue, {
        relayStatus: "relay_connected",
        hostStatus: "connecting_openclaw",
        lastSeenAt: nowIso(),
      });
      schedulePersist();
      sendSocket(socket, { type: "hello", role: "relay", gatewayId: gatewayIdValue, ok: true });
      return;
    }

    if (message.type === "heartbeat") {
      sendSocket(socket, { type: "heartbeat", gatewayId: gatewayIdValue, payload: { now: nowIso() } });
      return;
    }

    if (message.type === "gateway_connected") {
      touchGateway(gatewayIdValue, {
        relayStatus: "relay_connected",
        hostStatus: "healthy",
        openclawStatus: "healthy",
        lastSeenAt: nowIso(),
      });
      schedulePersist();
      broadcastToGatewayMembers(gatewayIdValue, { type: "presence", gatewayId: gatewayIdValue, payload: buildGatewaySummary(gateway) });
      scheduleTaskSweep(0);
      return;
    }

    if (message.type === "gateway_disconnected") {
      touchGateway(gatewayIdValue, {
        relayStatus: "relay_connected",
        hostStatus: "degraded",
        openclawStatus: "degraded",
        lastSeenAt: nowIso(),
      });
      schedulePersist();
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: "gateway_disconnected",
        payload: { reason: message.reason ?? "unknown" },
      });
      return;
    }

    if (message.type === "event") {
      const normalizedPayload =
        message.event === "chat" || message.event === "agent"
          ? normalizeRealtimeChatPayload(message.payload)
          : message.payload;
      const payloadRecord =
        normalizedPayload && typeof normalizedPayload === "object" && !Array.isArray(normalizedPayload)
          ? (normalizedPayload as Record<string, unknown>)
          : undefined;
      const currentModel =
        typeof payloadRecord?.currentModel === "string"
          ? payloadRecord.currentModel
          : typeof payloadRecord?.model === "string"
            ? payloadRecord.model
            : undefined;
      const { contextUsage, contextLimit } = extractContextMetrics(payloadRecord);
      const runtimePatch: Partial<GatewayRuntimeStateRecord> = {
        lastSeenAt: nowIso(),
      };
      if (currentModel) {
        runtimePatch.currentModel = currentModel;
      }
      if (contextUsage) {
        runtimePatch.contextUsage = contextUsage;
      }
      if (contextLimit) {
        runtimePatch.contextLimit = contextLimit;
      }
      touchGateway(gatewayIdValue, runtimePatch);
      schedulePersist();
      updateTaskFromChatEvent(gatewayIdValue, message.event, normalizedPayload);
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: message.event,
        payload: normalizedPayload,
      });
      if (currentModel || contextUsage || contextLimit) {
        broadcastToGatewayMembers(gatewayIdValue, {
          type: "presence",
          gatewayId: gatewayIdValue,
          payload: buildGatewaySummary(gateway),
        });
      }
      return;
    }

    if (message.type === "res" && message.id) {
      const pending = pendingResponses.get(message.id);
      if (pending) {
        pendingResponses.delete(message.id);
        if (!message.ok) metrics.commandFailures += 1;
        if (message.ok) {
          touchGateway(gatewayIdValue, {
            relayStatus: "relay_connected",
            hostStatus: "healthy",
            openclawStatus: "healthy",
            lastSeenAt: nowIso(),
          });
        }
        store.addAuditLog({
          id: randomUUID(),
          gatewayId: pending.gatewayId,
          userId: pending.userId,
          method: pending.method,
          riskLevel: pending.riskLevel,
          paramsMasked: pending.paramsMasked,
          resultOk: Boolean(message.ok),
          errorCode: message.error?.code ?? (message.ok ? undefined : "host_error"),
          durationMs: Date.now() - pending.startedAt,
          createdAt: nowIso(),
        });
        sendSocket(pending.socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: Boolean(message.ok),
          payload: message.payload,
          error: message.error,
        });
        schedulePersist();
        return;
      }

      const pendingHostCommand = pendingHostCommands.get(message.id);
      if (!pendingHostCommand) return;

      pendingHostCommands.delete(message.id);
      clearTimeout(pendingHostCommand.timeout);
      if (!message.ok) metrics.commandFailures += 1;
      if (message.ok) {
        touchGateway(gatewayIdValue, {
          relayStatus: "relay_connected",
          hostStatus: "healthy",
          openclawStatus: "healthy",
          lastSeenAt: nowIso(),
        });
      }
      store.addAuditLog({
        id: randomUUID(),
        gatewayId: pendingHostCommand.gatewayId,
        userId: pendingHostCommand.userId,
        method: pendingHostCommand.method,
        riskLevel: pendingHostCommand.riskLevel,
        paramsMasked: pendingHostCommand.paramsMasked,
        resultOk: Boolean(message.ok),
        errorCode: message.error?.code ?? (message.ok ? undefined : "host_error"),
        durationMs: Date.now() - pendingHostCommand.startedAt,
        createdAt: nowIso(),
      });
      schedulePersist();

      if (message.ok) {
        pendingHostCommand.resolve(message.payload);
      } else {
        pendingHostCommand.reject(new Error(message.error?.message ?? "host_error"));
      }
    }
  });

  socket.on("close", async () => {
    hostSessions.delete(gatewayIdValue);
    metrics.hostConnections = hostSessions.size;
    for (const [sessionKey, pending] of pendingTaskRunsBySessionKey.entries()) {
      if (pending.gatewayId !== gatewayIdValue) continue;
      clearTimeout(pending.timeout);
      pendingTaskRunsBySessionKey.delete(sessionKey);
      pendingTaskRunsByTaskID.delete(pending.taskId);
      const task = store.snapshot().tasks[pending.taskId];
      if (!task || task.gatewayId !== gatewayIdValue) continue;
      task.lastResult = "执行失败：网关断开连接";
      task.updatedAt = nowIso();
      store.putTask(task);
      broadcastTaskUpdate(gatewayIdValue, task.id);
    }
    touchGateway(gatewayIdValue, {
      relayStatus: "offline",
      hostStatus: "offline",
      openclawStatus: "offline",
      lastSeenAt: nowIso(),
      controllerUserId: undefined,
      controllerDeviceId: undefined,
      mobileControlStatus: "idle",
    });
    for (const [id, pending] of pendingResponses.entries()) {
      if (pending.gatewayId === gatewayIdValue) {
        failPending(id, "gateway_offline", "Gateway disconnected before responding");
      }
    }
    for (const [id, pending] of pendingHostCommands.entries()) {
      if (pending.gatewayId === gatewayIdValue) {
        failPendingHostCommand(id, "gateway_offline", "Gateway disconnected before responding");
      }
    }
    schedulePersist();
    broadcastToGatewayMembers(gatewayIdValue, {
      type: "presence",
      gatewayId: gatewayIdValue,
      payload: buildGatewaySummary(store.snapshot().gateways[gatewayIdValue]),
    });
  });
});

mobileWsServer.on("connection", async (socket, req) => {
  const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const accessToken = requestUrl.searchParams.get("accessToken") ?? "";
  const claims = verifyToken<TokenClaims>(accessToken, config.jwtSecret);

  if (!claims || claims.exp <= nowIso() || typeof claims.deviceId !== "string" || !claims.deviceId) {
    socket.close(4401, "unauthorized");
    return;
  }

  const sessionKey = `${claims.userId}:${claims.deviceId}`;
  const previous = mobileSessions.get(sessionKey);
  if (previous) previous.socket.close(4000, "replaced_by_new_mobile");
  mobileSessions.set(sessionKey, {
    userId: claims.userId,
    deviceId: claims.deviceId,
    socket,
    lastSeenAt: nowIso(),
  });
  metrics.mobileConnections = mobileSessions.size;

  const device = store.snapshot().mobileDevices[claims.deviceId];
  if (device) {
    device.lastSeenAt = nowIso();
    store.putMobileDevice(device);
  }
  schedulePersist();

  sendSocket(socket, {
    type: "hello",
    role: "relay",
    ok: true,
    payload: {
      userId: claims.userId,
      deviceId: claims.deviceId,
      gateways: store.snapshot().gatewayMemberships
        .filter((membership) => membership.userId === claims.userId)
        .map((membership) => {
          const gateway = store.snapshot().gateways[membership.gatewayId];
          return gateway ? { ...buildGatewaySummary(gateway), role: membership.role } : null;
        })
        .filter(Boolean),
    },
  });

  socket.on("message", async (raw) => {
    const message = safeJsonParse<RelayEnvelope>(raw.toString());
    if (!message?.type) return;

    const session = mobileSessions.get(sessionKey);
    if (session) session.lastSeenAt = nowIso();

    if (message.type === "heartbeat") {
      sendSocket(socket, { type: "heartbeat", payload: { now: nowIso() } });
      return;
    }

    if (message.type !== "cmd" || !message.method) return;

    const gatewayIdValue = typeof message.gatewayId === "string" ? message.gatewayId : "";
    const method = message.method;
    const membership = getMembership(gatewayIdValue, claims.userId);
    const gateway = store.snapshot().gateways[gatewayIdValue];
    const host = hostSessions.get(gatewayIdValue);
    const riskLevel = classifyRisk(method);
    const paramsMasked = maskSensitive(message.params);

    metrics.commandRequests += 1;
    if (riskLevel === "L3") metrics.highRiskCommands += 1;

    if (!membership || !gateway) {
      metrics.commandFailures += 1;
      sendSocket(socket, { type: "res", id: message.id, gatewayId: gatewayIdValue, ok: false, error: { code: "forbidden", message: "Gateway access denied" } });
      return;
    }
    if (!host) {
      metrics.commandFailures += 1;
      sendSocket(socket, { type: "res", id: message.id, gatewayId: gatewayIdValue, ok: false, error: { code: "gateway_offline", message: "Gateway is offline" } });
      return;
    }
    if (membership.role === "viewer" && !isReadOnly(method)) {
      metrics.commandFailures += 1;
      sendSocket(socket, { type: "res", id: message.id, gatewayId: gatewayIdValue, ok: false, error: { code: "forbidden", message: "Viewer role is read-only" } });
      return;
    }
    if (requiresApproval(method) && !store.consumeApproval(gatewayIdValue, claims.userId, method, nowIso())) {
      metrics.commandFailures += 1;
      sendSocket(socket, { type: "res", id: message.id, gatewayId: gatewayIdValue, ok: false, error: { code: "approval_required", message: "Sensitive command requires approval" } });
      schedulePersist();
      return;
    }

    const runtime = normalizeGatewayRuntime(gatewayIdValue);
    if (!isReadOnly(method)) {
      if (
        runtime.controllerDeviceId &&
        runtime.controllerDeviceId !== claims.deviceId &&
        runtime.controllerUserId !== claims.userId
      ) {
        metrics.commandFailures += 1;
        sendSocket(socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: false,
          error: { code: "controller_conflict", message: "Another mobile device currently owns write control" },
        });
        return;
      }
      runtime.controllerUserId = claims.userId;
      runtime.controllerDeviceId = claims.deviceId;
      runtime.mobileControlStatus = "claimed";
      if (method === "chat.send") {
        const paramsRecord =
          message.params && typeof message.params === "object" && !Array.isArray(message.params)
            ? (message.params as Record<string, unknown>)
            : undefined;
        const text = typeof paramsRecord?.message === "string" ? paramsRecord.message.trim() : "";
        const modelSwitchMatch = text.match(/^\/model\s+(.+)$/i);
        if (modelSwitchMatch) {
          runtime.currentModel = modelSwitchMatch[1].trim();
        }
      }
      store.putRuntimeState(runtime);
    }

    const requestId = message.id ?? randomUUID();
    pendingResponses.set(requestId, {
      socket,
      gatewayId: gatewayIdValue,
      userId: claims.userId,
      method,
      startedAt: Date.now(),
      paramsMasked,
      riskLevel,
    });

    if (method === "chat.send" || method === "agent") {
      const params = message.params as Record<string, unknown> | null;
      const text = params && typeof params.message === "string" ? params.message.trim() : "";
      const sessionKeyValue = params && typeof params.sessionKey === "string" ? params.sessionKey : undefined;
      if (text) {
        const eventTimestamp = Date.now();
        broadcastToGatewayMembers(gatewayIdValue, {
          type: "event",
          gatewayId: gatewayIdValue,
          event: "chat",
          payload: normalizeRealtimeChatPayload({
            state: "final",
            role: "user",
            sessionKey: sessionKeyValue,
            runId: requestId,
            ts: eventTimestamp,
            message: {
              role: "user",
              timestamp: eventTimestamp,
              content: [{ type: "text", text }],
            },
          }, eventTimestamp),
        }, socket);
      }
    }

    sendSocket(host.socket, {
      type: "cmd",
      id: requestId,
      gatewayId: gatewayIdValue,
      method,
      params: message.params,
    });
    schedulePersist();
  });

  socket.on("close", async () => {
    mobileSessions.delete(sessionKey);
    metrics.mobileConnections = mobileSessions.size;
    for (const runtime of Object.values(store.snapshot().gatewayRuntimeState)) {
      if (runtime.controllerDeviceId === claims.deviceId) {
        runtime.controllerDeviceId = undefined;
        runtime.controllerUserId = undefined;
        runtime.mobileControlStatus = "idle";
        store.putRuntimeState(runtime);
      }
    }
    schedulePersist();
  });
});

setInterval(async () => {
  const now = Date.now();
  for (const [gatewayIdValue, session] of hostSessions.entries()) {
    if (now - new Date(session.lastSeenAt).getTime() > config.wsIdleTimeoutMs) {
      session.socket.terminate();
      hostSessions.delete(gatewayIdValue);
    } else {
      sendSocket(session.socket, { type: "heartbeat", gatewayId: gatewayIdValue, payload: { now: nowIso() } });
    }
  }
  for (const [sessionKey, session] of mobileSessions.entries()) {
    if (now - new Date(session.lastSeenAt).getTime() > config.wsIdleTimeoutMs) {
      session.socket.terminate();
      mobileSessions.delete(sessionKey);
    } else {
      sendSocket(session.socket, { type: "heartbeat", payload: { now: nowIso() } });
    }
  }
  metrics.hostConnections = hostSessions.size;
  metrics.mobileConnections = mobileSessions.size;
  schedulePersist(config.heartbeatIntervalMs);
}, config.heartbeatIntervalMs).unref();

server.listen(config.port, config.host, () => {
  console.log(`PocketClaw relay server listening on http://${config.host}:${config.port}`);
});
