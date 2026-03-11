export type GatewayAggregateStatus = "offline" | "connecting" | "healthy" | "degraded";
export type HostStatus =
  | "offline"
  | "connecting_relay"
  | "relay_connected"
  | "connecting_openclaw"
  | "healthy"
  | "degraded"
  | "backoff";
export type MobileControlStatus = "idle" | "claimed" | "transfer_pending";
export type Role = "owner" | "admin" | "viewer";
export type RiskLevel = "L1" | "L2" | "L3";

export interface UserRecord {
  id: string;
  email: string;
  passwordHash: string;
  name: string;
  createdAt: string;
}

export interface MobileDeviceRecord {
  id: string;
  userId: string;
  platform: string;
  appVersion?: string;
  createdAt: string;
  lastSeenAt: string;
}

export interface GatewayRecord {
  id: string;
  ownerUserId?: string;
  gatewayCode: string;
  relaySecretHash: string;
  displayName: string;
  platform: string;
  agentVersion: string;
  openclawVersion?: string;
  status: GatewayAggregateStatus;
  lastSeenAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface GatewayPairingCodeRecord {
  gatewayId: string;
  accessCodeHash: string;
  expiresAt: string;
  usedAt?: string;
  createdAt: string;
}

export interface GatewayMembershipRecord {
  gatewayId: string;
  userId: string;
  role: Role;
  createdAt: string;
}

export interface GatewayRuntimeStateRecord {
  gatewayId: string;
  relayStatus: HostStatus;
  hostStatus: HostStatus;
  openclawStatus: HostStatus;
  aggregateStatus: GatewayAggregateStatus;
  lastSeenAt?: string;
  currentModel?: string;
  contextUsage?: number;
  controllerUserId?: string;
  controllerDeviceId?: string;
  mobileControlStatus: MobileControlStatus;
}

export interface CommandAuditLogRecord {
  id: string;
  gatewayId: string;
  userId: string;
  method: string;
  riskLevel: RiskLevel;
  paramsMasked: string;
  resultOk: boolean;
  errorCode?: string;
  durationMs: number;
  createdAt: string;
}

export interface ApprovalRecord {
  gatewayId: string;
  userId: string;
  method: string;
  expiresAt: string;
  createdAt: string;
}

export interface RelayState {
  users: Record<string, UserRecord>;
  mobileDevices: Record<string, MobileDeviceRecord>;
  gateways: Record<string, GatewayRecord>;
  gatewayPairingCodes: Record<string, GatewayPairingCodeRecord>;
  gatewayMemberships: GatewayMembershipRecord[];
  gatewayRuntimeState: Record<string, GatewayRuntimeStateRecord>;
  commandAuditLogs: CommandAuditLogRecord[];
  approvals: ApprovalRecord[];
}

export interface RelayEnvelope {
  type: string;
  id?: string;
  gatewayId?: string;
  method?: string;
  event?: string;
  role?: "host" | "mobile" | "relay";
  ok?: boolean;
  payload?: unknown;
  params?: unknown;
  error?: { code?: string; message?: string };
  [key: string]: unknown;
}
