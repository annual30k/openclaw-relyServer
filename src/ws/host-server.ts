import { randomUUID } from "crypto";
import type { WebSocket, WebSocketServer } from "ws";
import { safeJsonParse, sha256 } from "../security.js";
import { RelayStore } from "../store.js";
import type { GatewayRecord, GatewayRuntimeStateRecord, RelayEnvelope } from "../types.js";
import type { Metrics, PendingHostCommand, PendingResponse, PendingTaskRun } from "./runtime-types.js";

interface RegisterHostWsServerOptions {
  store: RelayStore;
  metrics: Metrics;
  hostSessions: Map<string, { gatewayId: string; socket: WebSocket; lastSeenAt: string }>;
  pendingResponses: Map<string, PendingResponse>;
  pendingHostCommands: Map<string, PendingHostCommand>;
  pendingTaskRunsBySessionKey: Map<string, PendingTaskRun>;
  pendingTaskRunsByTaskID: Map<string, PendingTaskRun>;
  nowIso: () => string;
  schedulePersist: (delayMs?: number) => void;
  scheduleTaskSweep: (delayMs?: number) => void;
  touchGateway: (gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>) => void;
  buildGatewaySummary: (gateway: GatewayRecord) => unknown;
  broadcastToGatewayMembers: (gatewayIdValue: string, envelope: RelayEnvelope, excludedSocket?: WebSocket) => void;
  sendSocket: (socket: WebSocket, envelope: RelayEnvelope) => void;
  normalizeRealtimeChatPayload: (rawPayload: unknown, fallbackTimestamp?: number) => unknown;
  extractContextMetrics: (
    payloadRecord: Record<string, unknown> | undefined,
  ) => Pick<GatewayRuntimeStateRecord, "contextUsage" | "contextLimit">;
  updateTaskFromChatEvent: (gatewayIdValue: string, eventName: string | undefined, payload: unknown) => void;
  broadcastTaskUpdate: (gatewayIdValue: string, taskId: string, event?: string) => void;
  failPending: (id: string, code: string, message: string) => void;
  failPendingHostCommand: (id: string, code: string, message: string) => void;
}

export function registerHostWsServer(
  hostWsServer: WebSocketServer,
  options: RegisterHostWsServerOptions,
): void {
  hostWsServer.on("connection", async (socket, req) => {
    const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const gatewayIdValue =
      requestUrl.searchParams.get("gatewayId")
      ?? requestUrl.pathname.match(/^\/relay\/([^/]+)$/)?.[1]
      ?? "";
    const secret = requestUrl.searchParams.get("secret") ?? "";
    const gateway = options.store.snapshot().gateways[gatewayIdValue];

    if (!gateway || sha256(secret) !== gateway.relaySecretHash) {
      socket.close(4401, "unauthorized");
      return;
    }

    const previous = options.hostSessions.get(gatewayIdValue);
    if (previous) {
      options.metrics.wsReconnectKicks += 1;
      previous.socket.close(4000, "replaced_by_new_host");
    }

    options.hostSessions.set(gatewayIdValue, { gatewayId: gatewayIdValue, socket, lastSeenAt: options.nowIso() });
    options.metrics.hostConnections = options.hostSessions.size;
    options.touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "relay_connected",
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();

    options.broadcastToGatewayMembers(gatewayIdValue, {
      type: "presence",
      gatewayId: gatewayIdValue,
      payload: options.buildGatewaySummary(gateway),
    });

    socket.on("message", async (raw) => {
      const message = safeJsonParse<RelayEnvelope>(raw.toString());
      if (!message?.type) {
        return;
      }
      console.log(`[relay-host] gateway=${gatewayIdValue} type=${message.type}`);

      const session = options.hostSessions.get(gatewayIdValue);
      if (session) {
        session.lastSeenAt = options.nowIso();
      }

      if (message.type === "hello") {
        const platform = typeof message.platform === "string" ? message.platform : gateway.platform;
        const agentVersion = typeof message.agentVersion === "string" ? message.agentVersion : gateway.agentVersion;
        gateway.platform = platform;
        gateway.agentVersion = agentVersion;
        gateway.updatedAt = options.nowIso();
        options.store.putGateway(gateway);
        options.touchGateway(gatewayIdValue, {
          relayStatus: "relay_connected",
          hostStatus: "connecting_openclaw",
          lastSeenAt: options.nowIso(),
        });
        options.schedulePersist();
        options.sendSocket(socket, { type: "hello", role: "relay", gatewayId: gatewayIdValue, ok: true });
        return;
      }

      if (message.type === "heartbeat") {
        options.sendSocket(socket, { type: "heartbeat", gatewayId: gatewayIdValue, payload: { now: options.nowIso() } });
        return;
      }

      if (message.type === "gateway_connected") {
        options.touchGateway(gatewayIdValue, {
          relayStatus: "relay_connected",
          hostStatus: "healthy",
          openclawStatus: "healthy",
          lastSeenAt: options.nowIso(),
        });
        options.schedulePersist();
        options.broadcastToGatewayMembers(gatewayIdValue, {
          type: "presence",
          gatewayId: gatewayIdValue,
          payload: options.buildGatewaySummary(gateway),
        });
        options.scheduleTaskSweep(0);
        return;
      }

      if (message.type === "gateway_disconnected") {
        options.touchGateway(gatewayIdValue, {
          relayStatus: "relay_connected",
          hostStatus: "degraded",
          openclawStatus: "degraded",
          lastSeenAt: options.nowIso(),
        });
        options.schedulePersist();
        options.broadcastToGatewayMembers(gatewayIdValue, {
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
            ? options.normalizeRealtimeChatPayload(message.payload)
            : message.payload;
        const payloadRecord =
          normalizedPayload && typeof normalizedPayload === "object" && !Array.isArray(normalizedPayload)
            ? (normalizedPayload as Record<string, unknown>)
            : undefined;
        const currentModelRaw =
          typeof payloadRecord?.currentModel === "string"
            ? payloadRecord.currentModel
            : typeof payloadRecord?.model === "string"
              ? payloadRecord.model
              : undefined;
        const currentModel =
          typeof currentModelRaw === "string" && currentModelRaw.trim().length > 0
            ? currentModelRaw.trim()
            : undefined;
        const { contextUsage, contextLimit } = options.extractContextMetrics(payloadRecord);
        const runtime = options.store.snapshot().gatewayRuntimeState[gatewayIdValue];
        const runtimePatch: Partial<GatewayRuntimeStateRecord> = {
          lastSeenAt: options.nowIso(),
        };
        const existingCurrentModel = typeof runtime?.currentModel === "string" ? runtime.currentModel.trim() : "";
        const shouldUpdateCurrentModel =
          currentModel !== undefined
          && (message.event !== "context_usage"
            || existingCurrentModel.length === 0
            || existingCurrentModel === currentModel);
        if (shouldUpdateCurrentModel) {
          runtimePatch.currentModel = currentModel;
        }
        if (contextUsage !== undefined) {
          runtimePatch.contextUsage = contextUsage;
        }
        if (contextLimit !== undefined) {
          runtimePatch.contextLimit = contextLimit;
        }
        options.touchGateway(gatewayIdValue, runtimePatch);
        options.schedulePersist();
        options.updateTaskFromChatEvent(gatewayIdValue, message.event, normalizedPayload);
        options.broadcastToGatewayMembers(gatewayIdValue, {
          type: "event",
          gatewayId: gatewayIdValue,
          event: message.event,
          payload: normalizedPayload,
        });
        if (currentModel !== undefined || contextUsage !== undefined || contextLimit !== undefined) {
          options.broadcastToGatewayMembers(gatewayIdValue, {
            type: "presence",
            gatewayId: gatewayIdValue,
            payload: options.buildGatewaySummary(gateway),
          });
        }
        return;
      }

      if (message.type === "res" && message.id) {
        const pending = options.pendingResponses.get(message.id);
        if (pending) {
          options.pendingResponses.delete(message.id);
          if (!message.ok) {
            options.metrics.commandFailures += 1;
          }
          if (message.ok) {
            options.touchGateway(gatewayIdValue, {
              relayStatus: "relay_connected",
              hostStatus: "healthy",
              openclawStatus: "healthy",
              lastSeenAt: options.nowIso(),
            });
          }
          options.store.addAuditLog({
            id: randomUUID(),
            gatewayId: pending.gatewayId,
            userId: pending.userId,
            method: pending.method,
            riskLevel: pending.riskLevel,
            paramsMasked: pending.paramsMasked,
            resultOk: Boolean(message.ok),
            errorCode: message.error?.code ?? (message.ok ? undefined : "host_error"),
            durationMs: Date.now() - pending.startedAt,
            createdAt: options.nowIso(),
          });
          options.sendSocket(pending.socket, {
            type: "res",
            id: message.id,
            gatewayId: gatewayIdValue,
            ok: Boolean(message.ok),
            payload: message.payload,
            error: message.error,
          });
          options.schedulePersist();
          return;
        }

        const pendingHostCommand = options.pendingHostCommands.get(message.id);
        if (!pendingHostCommand) {
          return;
        }

        options.pendingHostCommands.delete(message.id);
        clearTimeout(pendingHostCommand.timeout);
        if (!message.ok) {
          options.metrics.commandFailures += 1;
        }
        if (message.ok) {
          options.touchGateway(gatewayIdValue, {
            relayStatus: "relay_connected",
            hostStatus: "healthy",
            openclawStatus: "healthy",
            lastSeenAt: options.nowIso(),
          });
        }
        options.store.addAuditLog({
          id: randomUUID(),
          gatewayId: pendingHostCommand.gatewayId,
          userId: pendingHostCommand.userId,
          method: pendingHostCommand.method,
          riskLevel: pendingHostCommand.riskLevel,
          paramsMasked: pendingHostCommand.paramsMasked,
          resultOk: Boolean(message.ok),
          errorCode: message.error?.code ?? (message.ok ? undefined : "host_error"),
          durationMs: Date.now() - pendingHostCommand.startedAt,
          createdAt: options.nowIso(),
        });
        options.schedulePersist();

        if (message.ok) {
          pendingHostCommand.resolve(message.payload);
        } else {
          const code = message.error?.code ?? "host_error";
          const messageText = message.error?.message ?? "host_error";
          pendingHostCommand.reject(new Error(`${code}: ${messageText}`));
        }
      }
    });

    socket.on("close", async () => {
      options.hostSessions.delete(gatewayIdValue);
      options.metrics.hostConnections = options.hostSessions.size;
      for (const [sessionKey, pending] of options.pendingTaskRunsBySessionKey.entries()) {
        if (pending.gatewayId !== gatewayIdValue) {
          continue;
        }
        clearTimeout(pending.timeout);
        options.pendingTaskRunsBySessionKey.delete(sessionKey);
        options.pendingTaskRunsByTaskID.delete(pending.taskId);
        const task = options.store.snapshot().tasks[pending.taskId];
        if (!task || task.gatewayId !== gatewayIdValue) {
          continue;
        }
        task.lastResult = "执行失败：网关断开连接";
        task.updatedAt = options.nowIso();
        options.store.putTask(task);
        options.broadcastTaskUpdate(gatewayIdValue, task.id);
      }
      options.touchGateway(gatewayIdValue, {
        relayStatus: "offline",
        hostStatus: "offline",
        openclawStatus: "offline",
        lastSeenAt: options.nowIso(),
        controllerUserId: undefined,
        controllerDeviceId: undefined,
        mobileControlStatus: "idle",
      });
      for (const [id, pending] of options.pendingResponses.entries()) {
        if (pending.gatewayId === gatewayIdValue) {
          options.failPending(id, "gateway_offline", "Gateway disconnected before responding");
        }
      }
      for (const [id, pending] of options.pendingHostCommands.entries()) {
        if (pending.gatewayId === gatewayIdValue) {
          options.failPendingHostCommand(id, "gateway_offline", "Gateway disconnected before responding");
        }
      }
      options.schedulePersist();
      options.broadcastToGatewayMembers(gatewayIdValue, {
        type: "presence",
        gatewayId: gatewayIdValue,
        payload: options.buildGatewaySummary(options.store.snapshot().gateways[gatewayIdValue]),
      });
    });
  });
}
