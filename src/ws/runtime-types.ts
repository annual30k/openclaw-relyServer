import type { WebSocket } from "ws";
import type { RiskLevel } from "../types.js";

export type Metrics = {
  hostConnections: number;
  mobileConnections: number;
  commandRequests: number;
  commandFailures: number;
  wsReconnectKicks: number;
  highRiskCommands: number;
};

export type HostSession = {
  gatewayId: string;
  socket: WebSocket;
  lastSeenAt: string;
};

export type MobileSession = {
  userId: string;
  deviceId: string;
  socket: WebSocket;
  lastSeenAt: string;
};

export type PendingResponse = {
  socket: WebSocket;
  gatewayId: string;
  userId: string;
  method: string;
  startedAt: number;
  paramsMasked: string;
  riskLevel: RiskLevel;
};

export type PendingHostCommand = {
  gatewayId: string;
  userId: string;
  method: string;
  startedAt: number;
  paramsMasked: string;
  riskLevel: RiskLevel;
  resolve: (payload: unknown) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
};

export type PendingTaskRun = {
  taskId: string;
  gatewayId: string;
  userId: string;
  sessionKey: string;
  startedAt: number;
  timeout: NodeJS.Timeout;
};

export type TokenClaims = {
  userId: string;
  deviceId: string;
  platform: string;
  appVersion?: string;
  exp: string;
  email?: string;
};
