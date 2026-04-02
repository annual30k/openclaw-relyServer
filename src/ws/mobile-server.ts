import { randomUUID } from "crypto";
import type { WebSocket, WebSocketServer } from "ws";
import { classifyRisk, isReadOnly, requiresApproval } from "../risk.js";
import { maskSensitive, nowIso, safeJsonParse, verifyToken } from "../security.js";
import { RelayStore } from "../store.js";
import type { GatewayMembershipRecord, GatewayRecord, GatewayRuntimeStateRecord, RelayEnvelope } from "../types.js";
import type { HostSession, Metrics, MobileSession, PendingResponse, TokenClaims } from "./runtime-types.js";

interface RegisterMobileWsServerOptions {
  store: RelayStore;
  jwtSecret: string;
  metrics: Metrics;
  hostSessions: Map<string, HostSession>;
  mobileSessions: Map<string, MobileSession>;
  pendingResponses: Map<string, PendingResponse>;
  userExists: (userId: string) => boolean;
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  normalizeGatewayRuntime: (gatewayIdValue: string) => GatewayRuntimeStateRecord;
  buildGatewaySummary: (gateway: GatewayRecord) => unknown;
  sendSocket: (socket: WebSocket, envelope: RelayEnvelope) => void;
  broadcastToGatewayMembers: (gatewayIdValue: string, envelope: RelayEnvelope, excludedSocket?: WebSocket) => void;
  normalizeRealtimeChatPayload: (rawPayload: unknown, fallbackTimestamp?: number) => unknown;
  schedulePersist: (delayMs?: number) => void;
}

export function registerMobileWsServer(
  mobileWsServer: WebSocketServer,
  options: RegisterMobileWsServerOptions,
): void {
  mobileWsServer.on("connection", async (socket, req) => {
    const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const accessToken = requestUrl.searchParams.get("accessToken") ?? "";
    const claims = verifyToken<TokenClaims>(accessToken, options.jwtSecret);

    if (
      !claims
      || claims.exp <= nowIso()
      || typeof claims.deviceId !== "string"
      || !claims.deviceId
      || typeof claims.userId !== "string"
      || !claims.userId
      || !options.userExists(claims.userId)
    ) {
      socket.close(4401, "unauthorized");
      return;
    }

    const sessionKey = `${claims.userId}:${claims.deviceId}`;
    const previous = options.mobileSessions.get(sessionKey);
    if (previous) {
      previous.socket.close(4000, "replaced_by_new_mobile");
    }
    options.mobileSessions.set(sessionKey, {
      userId: claims.userId,
      deviceId: claims.deviceId,
      socket,
      lastSeenAt: nowIso(),
    });
    options.metrics.mobileConnections = options.mobileSessions.size;

    const device = options.store.snapshot().mobileDevices[claims.deviceId];
    if (device) {
      device.lastSeenAt = nowIso();
      options.store.putMobileDevice(device);
    }
    options.schedulePersist();

    options.sendSocket(socket, {
      type: "hello",
      role: "relay",
      ok: true,
      payload: {
        userId: claims.userId,
        deviceId: claims.deviceId,
        gateways: options.store.snapshot().gatewayMemberships
          .filter((membership) => membership.userId === claims.userId)
          .flatMap((membership) => {
            const gateway = options.store.snapshot().gateways[membership.gatewayId];
            if (!gateway) {
              return [];
            }
            return [{ ...toRecord(options.buildGatewaySummary(gateway)), role: membership.role }];
          }),
      },
    });

    socket.on("message", async (raw) => {
      const message = safeJsonParse<RelayEnvelope>(raw.toString());
      if (!message?.type) {
        return;
      }

      const session = options.mobileSessions.get(sessionKey);
      if (session) {
        session.lastSeenAt = nowIso();
      }

      if (message.type === "heartbeat") {
        options.sendSocket(socket, { type: "heartbeat", payload: { now: nowIso() } });
        return;
      }

      if (message.type !== "cmd" || !message.method) {
        return;
      }

      const gatewayIdValue = typeof message.gatewayId === "string" ? message.gatewayId : "";
      const method = message.method;
      const membership = options.getMembership(gatewayIdValue, claims.userId);
      const gateway = options.store.snapshot().gateways[gatewayIdValue];
      const host = options.hostSessions.get(gatewayIdValue);
      const riskLevel = classifyRisk(method);
      const paramsMasked = maskSensitive(message.params);

      options.metrics.commandRequests += 1;
      if (riskLevel === "L3") {
        options.metrics.highRiskCommands += 1;
      }

      if (!membership || !gateway) {
        options.metrics.commandFailures += 1;
        options.sendSocket(socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: false,
          error: { code: "forbidden", message: "Gateway access denied" },
        });
        return;
      }
      if (!host) {
        options.metrics.commandFailures += 1;
        options.sendSocket(socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: false,
          error: { code: "gateway_offline", message: "Gateway is offline" },
        });
        return;
      }
      if (membership.role === "viewer" && !isReadOnly(method)) {
        options.metrics.commandFailures += 1;
        options.sendSocket(socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: false,
          error: { code: "forbidden", message: "Viewer role is read-only" },
        });
        return;
      }
      if (requiresApproval(method) && !options.store.consumeApproval(gatewayIdValue, claims.userId, method, nowIso())) {
        options.metrics.commandFailures += 1;
        options.sendSocket(socket, {
          type: "res",
          id: message.id,
          gatewayId: gatewayIdValue,
          ok: false,
          error: { code: "approval_required", message: "Sensitive command requires approval" },
        });
        options.schedulePersist();
        return;
      }

      const runtime = options.normalizeGatewayRuntime(gatewayIdValue);
      if (!isReadOnly(method)) {
        if (
          runtime.controllerDeviceId
          && runtime.controllerDeviceId !== claims.deviceId
          && runtime.controllerUserId !== claims.userId
        ) {
          options.metrics.commandFailures += 1;
          options.sendSocket(socket, {
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
        options.store.putRuntimeState(runtime);
      }

      const requestId = message.id ?? randomUUID();
      options.pendingResponses.set(requestId, {
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
          options.broadcastToGatewayMembers(
            gatewayIdValue,
            {
              type: "event",
              gatewayId: gatewayIdValue,
              event: "chat",
              payload: options.normalizeRealtimeChatPayload(
                {
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
                },
                eventTimestamp,
              ),
            },
            socket,
          );
        }
      }

      options.sendSocket(host.socket, {
        type: "cmd",
        id: requestId,
        gatewayId: gatewayIdValue,
        method,
        params: message.params,
      });
      options.schedulePersist();
    });

    socket.on("close", async () => {
      options.mobileSessions.delete(sessionKey);
      options.metrics.mobileConnections = options.mobileSessions.size;
      for (const runtime of Object.values(options.store.snapshot().gatewayRuntimeState)) {
        if (runtime.controllerDeviceId === claims.deviceId) {
          runtime.controllerDeviceId = undefined;
          runtime.controllerUserId = undefined;
          runtime.mobileControlStatus = "idle";
          options.store.putRuntimeState(runtime);
        }
      }
      options.schedulePersist();
    });
  });
}

function toRecord(value: unknown): Record<string, unknown> {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}
