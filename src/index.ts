import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { randomUUID } from "crypto";
import { WebSocket, WebSocketServer } from "ws";
import { loadConfig } from "./config.js";
import { addSeconds, gatewayCode, gatewayId, maskSensitive, nowIso, randomCode, randomSecret, safeJsonParse, sha256, signToken, verifyToken } from "./security.js";
import { classifyRisk, isReadOnly, requiresApproval } from "./risk.js";
import { RelayStore } from "./store.js";
import type {
  GatewayMembershipRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  MobileDeviceRecord,
  RelayEnvelope,
  Role,
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

type TokenClaims = {
  userId: string;
  deviceId: string;
  platform: string;
  appVersion?: string;
  exp: string;
};

const hostSessions = new Map<string, HostSession>();
const mobileSessions = new Map<string, MobileSession>();
const pendingResponses = new Map<string, PendingResponse>();
const pendingHostCommands = new Map<string, PendingHostCommand>();
const rateLimitBuckets = new Map<string, number[]>();

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

function getUserIdFromRequest(req: IncomingMessage, body?: Record<string, unknown> | null): string {
  const auth = req.headers.authorization;
  if (auth?.startsWith("Bearer ")) {
    const claims = verifyToken<TokenClaims>(auth.slice("Bearer ".length), config.jwtSecret);
    if (claims && claims.exp > nowIso()) return claims.userId;
  }
  const headerId = req.headers["x-user-id"];
  if (typeof headerId === "string" && headerId.trim()) return headerId.trim();
  const bodyId = body?.userId;
  if (typeof bodyId === "string" && bodyId.trim()) return bodyId.trim();
  return "demo-user";
}

function ensureUser(userId: string): UserRecord {
  const existing = store.snapshot().users[userId];
  if (existing) return existing;
  const user: UserRecord = { id: userId, name: userId, createdAt: nowIso() };
  store.putUser(user);
  return user;
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
  return {
    gatewayId: gateway.id,
    displayName: gateway.displayName,
    platform: gateway.platform,
    aggregateStatus: runtime.aggregateStatus,
    relayStatus: runtime.relayStatus,
    hostStatus: runtime.hostStatus,
    openclawStatus: runtime.openclawStatus,
    mobileControlStatus: runtime.mobileControlStatus,
    lastSeenAt: gateway.lastSeenAt ?? gateway.createdAt,
    currentModel: runtime.currentModel ?? "--",
    contextUsage: runtime.contextUsage ?? 0,
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

async function persist(): Promise<void> {
  store.cleanupExpired(nowIso());
  await store.save();
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

  const accessCode = randomCode();
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

  const accessCode = randomCode();
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

async function handleMobilePair(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const gatewayIdValue = typeof body.gatewayId === "string" ? body.gatewayId : "";
  const accessCode = typeof body.accessCode === "string" ? body.accessCode : "";
  const deviceId = typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
  const platform = typeof body.platform === "string" ? body.platform : "ios";
  const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";
  const gateway = store.snapshot().gateways[gatewayIdValue];
  const pairingCode = store.snapshot().gatewayPairingCodes[gatewayIdValue];

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

  const userId = getUserIdFromRequest(req, body);
  ensureUser(userId);

  const existingOwner = store.snapshot().gatewayMemberships.some((membership) => membership.gatewayId === gatewayIdValue && membership.role === "owner");
  const role: Role = existingOwner ? "admin" : "owner";

  if (!gateway.ownerUserId) {
    gateway.ownerUserId = userId;
    gateway.updatedAt = nowIso();
    store.putGateway(gateway);
  }

  store.putMembership({
    gatewayId: gatewayIdValue,
    userId,
    role,
    createdAt: nowIso(),
  });

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

  const accessToken = signToken(
    {
      userId,
      deviceId,
      platform,
      appVersion,
      exp: addSeconds(new Date(), 60 * 60 * 24 * 7),
    },
    config.jwtSecret,
  );

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
  const userId = getUserIdFromRequest(req, null);
  ensureUser(userId);
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
  const userId = getUserIdFromRequest(req, null);
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
  const userId = getUserIdFromRequest(req, null);
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

async function handleGatewayModels(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const userId = getUserIdFromRequest(req, null);
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
    await persist();
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

async function handleGatewayChatHistory(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string, requestUrl: URL): Promise<void> {
  const userId = getUserIdFromRequest(req, null);
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
    await persist();
    const result = (payload ?? {}) as { messages?: unknown[] };
    const items = Array.isArray(result.messages)
      ? result.messages.flatMap((entry, index) => {
          if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
          const record = entry as Record<string, unknown>;
          const role = typeof record.role === "string" ? record.role : "assistant";
          const content = Array.isArray(record.content)
            ? record.content
                .filter((block): block is Record<string, unknown> => Boolean(block) && typeof block === "object" && !Array.isArray(block))
                .filter((block) => block.type === "text" && typeof block.text === "string")
                .map((block) => String(block.text))
                .join("\n\n")
                .trim()
            : "";
          if (!content) return [];
          return [{
            id: `history-${index}`,
            role,
            content,
          }];
        })
      : [];
    json(res, 200, { items });
  } catch (error) {
    json(res, 502, { error: String(error) });
  }
}

async function handleGatewayDefaultModelSelect(req: IncomingMessage, res: ServerResponse, gatewayIdValue: string): Promise<void> {
  const body = (await readJson<Record<string, unknown>>(req)) ?? {};
  const userId = getUserIdFromRequest(req, body);
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
  const userId = getUserIdFromRequest(req, body);
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
  const modelName = typeof body.modelName === "string" ? body.modelName.trim() : modelAlias;
  if (!providerId || !modelId || !modelAlias) {
    json(res, 400, { error: "providerId_modelId_and_modelAlias_required" });
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
    await persist();

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
  const userId = getUserIdFromRequest(req, body);
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

const server = createServer(async (req, res) => {
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
  if (detailMatch && req.method === "DELETE") {
    await handleGatewayDelete(req, res, detailMatch[1]);
    return;
  }

  const modelsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models$/);
  if (modelsMatch && req.method === "GET") {
    await handleGatewayModels(req, res, modelsMatch[1]);
    return;
  }

  const chatHistoryMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/history$/);
  if (chatHistoryMatch && req.method === "GET") {
    await handleGatewayChatHistory(req, res, chatHistoryMatch[1], requestUrl);
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
  await persist();

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
      await persist();
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
      await persist();
      broadcastToGatewayMembers(gatewayIdValue, { type: "presence", gatewayId: gatewayIdValue, payload: buildGatewaySummary(gateway) });
      return;
    }

    if (message.type === "gateway_disconnected") {
      touchGateway(gatewayIdValue, {
        relayStatus: "relay_connected",
        hostStatus: "degraded",
        openclawStatus: "degraded",
        lastSeenAt: nowIso(),
      });
      await persist();
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: "gateway_disconnected",
        payload: { reason: message.reason ?? "unknown" },
      });
      return;
    }

    if (message.type === "event") {
      touchGateway(gatewayIdValue, { lastSeenAt: nowIso() });
      await persist();
      broadcastToGatewayMembers(gatewayIdValue, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: message.event,
        payload: message.payload,
      });
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
        await persist();
        sendSocket(pending.socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: Boolean(message.ok),
          payload: message.payload,
          error: message.error,
        });
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
      await persist();

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
    await persist();
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

  if (!claims || claims.exp <= nowIso()) {
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
  await persist();

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
      await persist();
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
        broadcastToGatewayMembers(gatewayIdValue, {
          type: "event",
          gatewayId: gatewayIdValue,
          event: "chat",
          payload: {
            state: "final",
            role: "user",
            sessionKey: sessionKeyValue,
            runId: requestId,
            message: {
              content: [{ type: "text", text }],
            },
          },
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
    await persist();
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
    await persist();
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
  await persist();
}, config.heartbeatIntervalMs).unref();

server.listen(config.port, config.host, () => {
  console.log(`PocketClaw relay server listening on http://${config.host}:${config.port}`);
});
