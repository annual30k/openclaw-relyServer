import type { IncomingMessage, ServerResponse } from "http";
import { randomUUID } from "crypto";
import { WebSocket, WebSocketServer } from "ws";
import { loadConfig } from "./config.js";
import { FileTransferRecord, FileTransferStore } from "./files/file-transfer-store.js";
import { canAccessFileTransfer } from "./files/file-formatters.js";
import { addSeconds, gatewayCode, gatewayId, hashPassword, maskSensitive, nowIso, randomCode, randomSecret, sha256, signToken, verifyPassword, verifyToken } from "./security.js";
import { classifyRisk } from "./risk.js";
import { RelayStore } from "./store.js";
import { json } from "./http/common.js";
import { createAuthRouteHandlers } from "./http/auth-routes.js";
import { createFileRouteHandlers } from "./http/file-routes.js";
import { createGatewayRouteHandlers } from "./http/gateway-routes.js";
import { metricsText as renderMetricsText } from "./http/metrics.js";
import { createRelayHttpServer } from "./http/server.js";
import { createChatRouteHandlers } from "./chat/chat-routes.js";
import { computeAggregateStatus, defaultGatewayRuntime } from "./gateway/runtime-state.js";
import { extractSessionKeysFromPayload, isIgnorableSessionDeleteError } from "./chat/session-utils.js";
import {
  buildGatewaySummary as buildGatewaySummarySnapshot,
  extractContextMetrics,
  normalizeRealtimeChatPayload,
} from "./runtime-utils.js";
import {
  computeNextTaskRun,
  formatTaskResultPreview,
  extractTaskResultText,
} from "./tasks/task-utils.js";
import { createTaskRouteHandlers } from "./tasks/task-routes.js";
import { attachRelayUpgradeHandlers } from "./ws/upgrade.js";
import { registerHostWsServer } from "./ws/host-server.js";
import { registerMobileWsServer } from "./ws/mobile-server.js";
import {
  broadcastToGatewayMembers as broadcastGatewayMembers,
  clearPendingStateForUser as clearPendingStateForUserImpl,
  disconnectMobileSessionsForUser as disconnectMobileSessionsForUserImpl,
  sendSocket,
  touchHostSessionActivity as touchHostSessionActivityImpl,
  touchMobileSessionActivity as touchMobileSessionActivityImpl,
} from "./ws/session-helpers.js";
import type { HostSession, Metrics, MobileSession, PendingHostCommand, PendingResponse, PendingTaskRun, TokenClaims } from "./ws/runtime-types.js";
import type {
  GatewayMembershipRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  RelayEnvelope,
  UserRecord,
} from "./types.js";

const config = loadConfig();
const store = await RelayStore.create(config.databaseUrl);
const fileStore = await FileTransferStore.create({
  dataDir: config.dataDir,
  databaseUrl: config.databaseUrl,
  chunkSizeBytes: config.fileChunkSizeBytes,
  uploadTtlMs: config.fileUploadTtlSeconds * 1000,
  fileTtlMs: config.fileTtlSeconds * 1000,
  storageBackend: config.fileStorageDriver,
  minio: config.minio,
});

const metrics: Metrics = {
  hostConnections: 0,
  mobileConnections: 0,
  commandRequests: 0,
  commandFailures: 0,
  wsReconnectKicks: 0,
  highRiskCommands: 0,
};

const hostSessions = new Map<string, HostSession>();
const mobileSessions = new Map<string, MobileSession>();
const pendingResponses = new Map<string, PendingResponse>();
const pendingHostCommands = new Map<string, PendingHostCommand>();
const rateLimitBuckets = new Map<string, number[]>();
const pendingTaskRunsBySessionKey = new Map<string, PendingTaskRun>();
const pendingTaskRunsByTaskID = new Map<string, PendingTaskRun>();
const taskRunTimeoutMs = 30 * 60 * 1000;
let fileCleanupInFlight = false;

const hostWsServer = new WebSocketServer({ noServer: true });
const mobileWsServer = new WebSocketServer({ noServer: true });

function normalizeGatewayRuntime(gatewayIdValue: string): GatewayRuntimeStateRecord {
  const current = store.snapshot().gatewayRuntimeState[gatewayIdValue];
  return current ?? defaultGatewayRuntime(gatewayIdValue);
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

function membershipsForUser(userId: string): GatewayMembershipRecord[] {
  return store.snapshot().gatewayMemberships.filter((membership) => membership.userId === userId);
}

function disconnectMobileSessionsForUser(userId: string, reason = "account_deleted"): void {
  disconnectMobileSessionsForUserImpl(mobileSessions, metrics, userId, reason);
}

function clearPendingStateForUser(userId: string): void {
  clearPendingStateForUserImpl({
    userId,
    pendingResponses,
    pendingHostCommands,
    pendingTaskRunsBySessionKey,
    pendingTaskRunsByTaskID,
    failPending,
    failPendingHostCommand,
  });
}

async function deleteGatewayChatDataForAccount(gatewayIdValue: string, userId: string): Promise<string[]> {
  const warnings: string[] = [];

  try {
    const payload = await dispatchHostCommand(gatewayIdValue, userId, "sessions.list", {
      limit: 1000,
      includeGlobal: true,
      includeUnknown: true,
    });
    for (const sessionKey of extractSessionKeysFromPayload(payload)) {
      try {
        await dispatchHostCommand(gatewayIdValue, userId, "sessions.delete", {
          key: sessionKey,
          deleteTranscript: true,
        });
      } catch (error) {
        if (!isIgnorableSessionDeleteError(error)) {
          warnings.push(`sessions.delete failed for ${sessionKey}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
    }
  } catch (error) {
    warnings.push(`sessions.list failed: ${error instanceof Error ? error.message : String(error)}`);
  }

  return warnings;
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

function userExists(userId: string): boolean {
  return Boolean(store.snapshot().users[userId]);
}

function requireAuthenticatedUser(req: IncomingMessage, res: ServerResponse): string | null {
  const claims = requireAuthenticatedClaims(req, res);
  if (!claims) {
    return null;
  }
  return claims.userId;
}

function requireAuthenticatedClaims(req: IncomingMessage, res: ServerResponse): TokenClaims | null {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const claims = verifyToken<TokenClaims>(auth.slice("Bearer ".length), config.jwtSecret);
    if (
      claims &&
      claims.exp > nowIso() &&
      typeof claims.userId === "string" &&
      claims.userId &&
      userExists(claims.userId)
    ) {
      return claims;
    }
  }
  json(res, 401, { error: "unauthorized" });
  return null;
}

function touchHostSessionActivity(gatewayIdValue: string): void {
  touchHostSessionActivityImpl(hostSessions, gatewayIdValue, nowIso);
}

function touchMobileSessionActivity(userId: string, deviceId: string): void {
  touchMobileSessionActivityImpl(mobileSessions, userId, deviceId, nowIso);
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

function buildGatewaySummary(gateway: GatewayRecord) {
  const runtime = normalizeGatewayRuntime(gateway.id);
  return buildGatewaySummarySnapshot(gateway, runtime);
}

function broadcastToGatewayMembers(gatewayIdValue: string, envelope: RelayEnvelope, excludedSocket?: WebSocket): void {
  broadcastGatewayMembers(gatewayIdValue, envelope, store.snapshot().gatewayMemberships, mobileSessions.values(), excludedSocket);
}

function broadcastFileTransfer(gatewayIdValue: string, record: FileTransferRecord): void {
  const payload = fileStore.toChatEventPayload(record);
  const memberships = store.snapshot().gatewayMemberships.filter((membership) => membership.gatewayId === gatewayIdValue);
  for (const membership of memberships) {
    if (!canAccessFileTransfer(record, membership.userId)) {
      continue;
    }
    for (const session of mobileSessions.values()) {
      if (session.userId !== membership.userId) {
        continue;
      }
      sendSocket(session.socket, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: "file",
        payload,
      });
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

function broadcastTaskUpdate(gatewayIdValue: string, taskId: string, event = "task_updated"): void {
  broadcastToGatewayMembers(gatewayIdValue, {
    type: "event",
    gatewayId: gatewayIdValue,
    event,
    payload: { taskId, gatewayId: gatewayIdValue },
  });
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

const authRouteHandlers = createAuthRouteHandlers({
  config,
  store,
  nowIso,
  addSeconds,
  gatewayId,
  gatewayCode,
  randomSecret,
  randomCode,
  sha256,
  hashPassword,
  verifyPassword,
  makeAccessToken,
  touchGateway,
  persist,
  schedulePersist,
  requireAuthenticatedUser,
  requireAuthenticatedClaims,
  findUserByEmail,
  membershipsForUser,
  getMembership,
  deleteGatewayChatDataForAccount,
  clearPendingStateForUser,
  disconnectMobileSessionsForUser,
  deleteFilesForGateway: (gatewayIdValue) => fileStore.deleteFilesForGateway(gatewayIdValue),
  buildGatewaySummary,
});

const fileRouteHandlers = createFileRouteHandlers({
  fileStore,
  sha256,
  store,
  requireAuthenticatedClaims,
  getMembership,
  touchHostSessionActivity,
  touchMobileSessionActivity,
  broadcastFileTransfer,
});

const gatewayRouteHandlers = createGatewayRouteHandlers({
  store,
  approvalTtlSeconds: config.approvalTtlSeconds,
  nowIso,
  addSeconds,
  persist,
  schedulePersist,
  requireAuthenticatedUser,
  getMembership,
  normalizeGatewayRuntime,
  buildGatewaySummary,
  dispatchHostCommand,
  touchGateway,
  broadcastToGatewayMembers,
});

const taskRouteHandlers = createTaskRouteHandlers({
  store,
  nowIso,
  persist,
  schedulePersist,
  scheduleTaskSweep,
  requireAuthenticatedUser,
  getMembership,
  dispatchHostCommand,
  touchGateway,
  broadcastTaskUpdate,
  pendingTaskRunsByTaskID,
});

const chatRouteHandlers = createChatRouteHandlers({
  fileStore,
  nowIso,
  schedulePersist,
  requireAuthenticatedUser,
  getMembership,
  dispatchHostCommand,
  touchGateway,
});

const {
  handleRegister,
  handleAccessCode,
  handleAuthRegister,
  handleAuthLogin,
  handleAuthDeleteAccount,
  handleMobilePair,
} = authRouteHandlers;

const {
  handleMobileFileUploadInit,
  handleHostFileUploadInit,
  handleMobileFileUploadChunk,
  handleHostFileUploadChunk,
  handleMobileFileUploadComplete,
  handleHostFileUploadComplete,
  handleMobileFileDownload,
} = fileRouteHandlers;

const {
  handleGatewayList,
  handleGatewayDetail,
  handleGatewayDelete,
  handleGatewayUpdate,
  handleGatewayModels,
  handleGatewaySkills,
  handleGatewayBackups,
  handleGatewayBackup,
  handleGatewayBackupRestore,
  handleGatewaySkillUpdate,
  handleGatewayDefaultModelSelect,
  handleGatewayModelSelect,
  handleApproveSensitiveAction,
} = gatewayRouteHandlers;

const {
  handleGatewayTasks,
  handleGatewayTask,
} = taskRouteHandlers;

const {
  handleGatewayChatHistory,
  handleGatewayChatReady,
  handleGatewayChatSessions,
  handleGatewayChatSessionDelete,
} = chatRouteHandlers;

const server = createRelayHttpServer({
  ensureRateLimit,
  metricsText: () => renderMetricsText(metrics, hostSessions),
  nowIso,
  handleRegister,
  handleAuthRegister,
  handleAuthLogin,
  handleAuthDeleteAccount,
  handleAccessCode,
  handleMobilePair,
  handleGatewayList,
  handleGatewayDetail,
  handleGatewayUpdate,
  handleGatewayDelete,
  handleGatewayModels,
  handleGatewaySkills,
  handleGatewayBackups,
  handleGatewayBackupRestore,
  handleGatewayBackup,
  handleGatewayTasks,
  handleGatewayTask,
  handleGatewaySkillUpdate,
  handleGatewayChatHistory,
  handleGatewayChatReady,
  handleGatewayChatSessions,
  handleGatewayChatSessionDelete,
  handleMobileFileUploadInit,
  handleHostFileUploadInit,
  handleMobileFileUploadChunk,
  handleHostFileUploadChunk,
  handleMobileFileUploadComplete,
  handleHostFileUploadComplete,
  handleMobileFileDownload,
  handleGatewayModelSelect,
  handleGatewayDefaultModelSelect,
  handleApproveSensitiveAction,
});

attachRelayUpgradeHandlers(server, hostWsServer, mobileWsServer);

registerHostWsServer(hostWsServer, {
  store,
  metrics,
  hostSessions,
  pendingResponses,
  pendingHostCommands,
  pendingTaskRunsBySessionKey,
  pendingTaskRunsByTaskID,
  nowIso,
  schedulePersist,
  scheduleTaskSweep,
  touchGateway,
  buildGatewaySummary,
  broadcastToGatewayMembers,
  sendSocket,
  normalizeRealtimeChatPayload,
  extractContextMetrics,
  updateTaskFromChatEvent,
  broadcastTaskUpdate,
  failPending,
  failPendingHostCommand,
});

registerMobileWsServer(mobileWsServer, {
  store,
  jwtSecret: config.jwtSecret,
  metrics,
  hostSessions,
  mobileSessions,
  pendingResponses,
  userExists,
  getMembership,
  normalizeGatewayRuntime,
  buildGatewaySummary,
  sendSocket,
  broadcastToGatewayMembers,
  normalizeRealtimeChatPayload,
  schedulePersist,
});

setInterval(() => {
  if (fileCleanupInFlight) {
    return;
  }
  fileCleanupInFlight = true;
  void (async () => {
    try {
      const now = Date.now();
      await fileStore.cleanupExpired(new Date(now));
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
    } catch (error) {
      console.error("[relay] maintenance tick failed", error);
    } finally {
      fileCleanupInFlight = false;
    }
  })();
}, config.heartbeatIntervalMs).unref();

server.listen(config.port, config.host, () => {
  console.log(`PocketClaw relay server listening on http://${config.host}:${config.port}`);
});
