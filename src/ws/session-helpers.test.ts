import assert from "node:assert/strict";
import test from "node:test";
import { WebSocket } from "ws";
import type { Metrics, MobileSession, PendingHostCommand, PendingResponse, PendingTaskRun } from "./runtime-types.js";
import {
  broadcastToGatewayMembers,
  clearPendingStateForUser,
  disconnectMobileSessionsForUser,
  sendSocket,
  touchHostSessionActivity,
  touchMobileSessionActivity,
} from "./session-helpers.js";

type FakeSocket = WebSocket & { sent: string[]; closed: Array<[number, string]> };

function createFakeSocket(): FakeSocket {
  return {
    readyState: WebSocket.OPEN,
    sent: [] as string[],
    closed: [] as Array<[number, string]>,
    send(this: FakeSocket, payload: string) {
      this.sent.push(payload);
    },
    close(this: FakeSocket, code: number, reason: string) {
      this.closed.push([code, reason]);
    },
  } as FakeSocket;
}

test("sendSocket only writes to open sockets", () => {
  const socket = createFakeSocket();
  sendSocket(socket, { type: "heartbeat", payload: { now: "2026-04-01T00:00:00.000Z" } });
  assert.equal(socket.sent.length, 1);
});

test("broadcastToGatewayMembers skips excluded sockets and non-members", () => {
  const first = createFakeSocket();
  const second = createFakeSocket();
  const outsider = createFakeSocket();

  broadcastToGatewayMembers(
    "gw_1",
    { type: "event", gatewayId: "gw_1", event: "ping" },
    [
      { gatewayId: "gw_1", userId: "user_1", role: "viewer", createdAt: "2026-04-01T00:00:00.000Z" },
      { gatewayId: "gw_2", userId: "user_1", role: "viewer", createdAt: "2026-04-01T00:00:00.000Z" },
    ],
    [
      { userId: "user_1", deviceId: "device_1", socket: first, lastSeenAt: "2026-03-31T00:00:00.000Z" } as MobileSession,
      { userId: "user_1", deviceId: "device_2", socket: second, lastSeenAt: "2026-03-31T00:00:00.000Z" } as MobileSession,
      { userId: "user_2", deviceId: "device_3", socket: outsider, lastSeenAt: "2026-03-31T00:00:00.000Z" } as MobileSession,
    ],
    first,
  );

  assert.equal(first.sent.length, 0);
  assert.equal(second.sent.length, 1);
  assert.equal(outsider.sent.length, 0);
});

test("touch helpers refresh last seen timestamps", () => {
  const hostSessions = new Map([
    ["gw_1", { gatewayId: "gw_1", socket: createFakeSocket(), lastSeenAt: "2026-03-31T00:00:00.000Z" }],
  ]);
  const mobileSessions = new Map([
    ["user_1:device_1", { userId: "user_1", deviceId: "device_1", socket: createFakeSocket(), lastSeenAt: "2026-03-31T00:00:00.000Z" }],
  ]);

  touchHostSessionActivity(hostSessions, "gw_1", () => "2026-04-01T00:00:00.000Z");
  touchMobileSessionActivity(mobileSessions, "user_1", "device_1", () => "2026-04-01T00:00:00.000Z");

  assert.equal(hostSessions.get("gw_1")?.lastSeenAt, "2026-04-01T00:00:00.000Z");
  assert.equal(mobileSessions.get("user_1:device_1")?.lastSeenAt, "2026-04-01T00:00:00.000Z");
});

test("disconnectMobileSessionsForUser closes only matching sessions", () => {
  const first = createFakeSocket();
  const second = createFakeSocket();
  const mobileSessions = new Map([
    ["user_1:device_1", { userId: "user_1", deviceId: "device_1", socket: first, lastSeenAt: "now" }],
    ["user_2:device_2", { userId: "user_2", deviceId: "device_2", socket: second, lastSeenAt: "now" }],
  ]);
  const metrics: Metrics = {
    hostConnections: 0,
    mobileConnections: 2,
    commandRequests: 0,
    commandFailures: 0,
    wsReconnectKicks: 0,
    highRiskCommands: 0,
  };

  disconnectMobileSessionsForUser(mobileSessions, metrics, "user_1", "deleted");

  assert.equal(mobileSessions.has("user_1:device_1"), false);
  assert.equal(mobileSessions.has("user_2:device_2"), true);
  assert.equal(metrics.mobileConnections, 1);
  assert.deepEqual(first.closed[0], [4001, "deleted"]);
  assert.equal(second.closed.length, 0);
});

test("clearPendingStateForUser notifies all pending maps for the account", () => {
  const responseSocket = createFakeSocket();
  const hostSocket = createFakeSocket();
  const pendingResponses = new Map<string, PendingResponse>([
    [
      "res_1",
      {
        socket: responseSocket,
        gatewayId: "gw_1",
        userId: "user_1",
        method: "chat.send",
        startedAt: 1,
        paramsMasked: "{}",
        riskLevel: "L1",
      },
    ],
  ]);
  const pendingHostCommands = new Map<string, PendingHostCommand>([
    [
      "cmd_1",
      {
        gatewayId: "gw_1",
        userId: "user_1",
        method: "chat.send",
        startedAt: 1,
        paramsMasked: "{}",
        riskLevel: "L1",
        resolve() {},
        reject() {},
        timeout: setTimeout(() => undefined, 10),
      },
    ],
  ]);
  const pendingTaskRunsBySessionKey = new Map<string, PendingTaskRun>([
    [
      "task:1",
      {
        taskId: "task_1",
        gatewayId: "gw_1",
        userId: "user_1",
        sessionKey: "task:1",
        startedAt: 1,
        timeout: setTimeout(() => undefined, 10),
      },
    ],
  ]);
  const pendingTaskRunsByTaskID = new Map<string, PendingTaskRun>([
    [
      "task_1",
      {
        taskId: "task_1",
        gatewayId: "gw_1",
        userId: "user_1",
        sessionKey: "task:1",
        startedAt: 1,
        timeout: setTimeout(() => undefined, 10),
      },
    ],
  ]);
  const failPendingCalls: Array<[string, string, string]> = [];
  const failPendingHostCommandCalls: Array<[string, string, string]> = [];

  clearTimeout(pendingHostCommands.get("cmd_1")!.timeout);
  clearTimeout(pendingTaskRunsBySessionKey.get("task:1")!.timeout);
  clearTimeout(pendingTaskRunsByTaskID.get("task_1")!.timeout);

  clearPendingStateForUser({
    userId: "user_1",
    pendingResponses,
    pendingHostCommands,
    pendingTaskRunsBySessionKey,
    pendingTaskRunsByTaskID,
    failPending: (id, code, message) => failPendingCalls.push([id, code, message]),
    failPendingHostCommand: (id, code, message) => failPendingHostCommandCalls.push([id, code, message]),
  });

  assert.deepEqual(failPendingCalls, [["res_1", "account_deleted", "Account deleted"]]);
  assert.deepEqual(failPendingHostCommandCalls, [["cmd_1", "account_deleted", "Account deleted"]]);
  assert.equal(pendingResponses.size, 1);
  assert.equal(pendingHostCommands.size, 1);
  assert.equal(pendingTaskRunsBySessionKey.size, 0);
  assert.equal(pendingTaskRunsByTaskID.size, 0);
});
