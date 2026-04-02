import { WebSocket } from "ws";
import type { GatewayMembershipRecord, RelayEnvelope } from "../types.js";
import type { HostSession, Metrics, MobileSession, PendingHostCommand, PendingResponse, PendingTaskRun } from "./runtime-types.js";

type SessionBroadcastTarget = Pick<MobileSession, "userId" | "socket">;

export function sendSocket(socket: WebSocket, envelope: RelayEnvelope): void {
  if (socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(envelope));
  }
}

export function touchHostSessionActivity(
  hostSessions: Map<string, HostSession>,
  gatewayIdValue: string,
  nowIso: () => string,
): void {
  const session = hostSessions.get(gatewayIdValue);
  if (session) {
    session.lastSeenAt = nowIso();
  }
}

export function touchMobileSessionActivity(
  mobileSessions: Map<string, MobileSession>,
  userId: string,
  deviceId: string,
  nowIso: () => string,
): void {
  const session = mobileSessions.get(`${userId}:${deviceId}`);
  if (session) {
    session.lastSeenAt = nowIso();
  }
}

export function broadcastToGatewayMembers(
  gatewayIdValue: string,
  envelope: RelayEnvelope,
  memberships: GatewayMembershipRecord[],
  mobileSessions: Iterable<SessionBroadcastTarget>,
  excludedSocket?: WebSocket,
): void {
  for (const membership of memberships) {
    if (membership.gatewayId !== gatewayIdValue) {
      continue;
    }
    for (const session of mobileSessions) {
      if (session.userId === membership.userId && session.socket !== excludedSocket) {
        sendSocket(session.socket, envelope);
      }
    }
  }
}

export function disconnectMobileSessionsForUser(
  mobileSessions: Map<string, MobileSession>,
  metrics: Metrics,
  userId: string,
  reason = "account_deleted",
): void {
  for (const [sessionKey, session] of mobileSessions.entries()) {
    if (session.userId !== userId) {
      continue;
    }
    session.socket.close(4001, reason);
    mobileSessions.delete(sessionKey);
  }
  metrics.mobileConnections = mobileSessions.size;
}

export function clearPendingStateForUser(options: {
  userId: string;
  pendingResponses: Map<string, PendingResponse>;
  pendingHostCommands: Map<string, PendingHostCommand>;
  pendingTaskRunsBySessionKey: Map<string, PendingTaskRun>;
  pendingTaskRunsByTaskID: Map<string, PendingTaskRun>;
  failPending: (id: string, code: string, message: string) => void;
  failPendingHostCommand: (id: string, code: string, message: string) => void;
}): void {
  for (const [id, pending] of options.pendingResponses.entries()) {
    if (pending.userId === options.userId) {
      options.failPending(id, "account_deleted", "Account deleted");
    }
  }

  for (const [id, pending] of options.pendingHostCommands.entries()) {
    if (pending.userId === options.userId) {
      options.failPendingHostCommand(id, "account_deleted", "Account deleted");
    }
  }

  for (const [sessionKey, pending] of options.pendingTaskRunsBySessionKey.entries()) {
    if (pending.userId !== options.userId) {
      continue;
    }
    clearTimeout(pending.timeout);
    options.pendingTaskRunsBySessionKey.delete(sessionKey);
    options.pendingTaskRunsByTaskID.delete(pending.taskId);
  }
}
