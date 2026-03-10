import mysql, { type Pool, type RowDataPacket } from "mysql2/promise";
import type {
  ApprovalRecord,
  CommandAuditLogRecord,
  GatewayMembershipRecord,
  GatewayPairingCodeRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  MobileDeviceRecord,
  RelayState,
  UserRecord,
} from "./types.js";

const EMPTY_STATE: RelayState = {
  users: {},
  mobileDevices: {},
  gateways: {},
  gatewayPairingCodes: {},
  gatewayMemberships: [],
  gatewayRuntimeState: {},
  commandAuditLogs: [],
  approvals: [],
};

function toSqlDate(value?: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toISOString().slice(0, 19).replace("T", " ");
  }
  return value.slice(0, 19).replace("T", " ");
}

function toIso(value: unknown): string | undefined {
  if (value == null) return undefined;
  const stringValue = String(value);
  if (!stringValue) return undefined;
  return stringValue.includes("T") ? stringValue : `${stringValue.replace(" ", "T")}Z`;
}

type UserRow = RowDataPacket & { id: string; name: string; created_at: string };
type MobileDeviceRow = RowDataPacket & {
  id: string;
  user_id: string;
  platform: string;
  app_version: string | null;
  created_at: string;
  last_seen_at: string;
};
type GatewayRow = RowDataPacket & {
  id: string;
  owner_user_id: string | null;
  gateway_code: string;
  relay_secret_hash: string;
  display_name: string;
  platform: string;
  agent_version: string;
  openclaw_version: string | null;
  status: GatewayRecord["status"];
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
};
type PairingCodeRow = RowDataPacket & {
  gateway_id: string;
  access_code_hash: string;
  expires_at: string;
  used_at: string | null;
  created_at: string;
};
type MembershipRow = RowDataPacket & {
  gateway_id: string;
  user_id: string;
  role: GatewayMembershipRecord["role"];
  created_at: string;
};
type RuntimeRow = RowDataPacket & {
  gateway_id: string;
  relay_status: GatewayRuntimeStateRecord["relayStatus"];
  host_status: GatewayRuntimeStateRecord["hostStatus"];
  openclaw_status: GatewayRuntimeStateRecord["openclawStatus"];
  aggregate_status: GatewayRuntimeStateRecord["aggregateStatus"];
  current_model: string | null;
  context_usage: number | null;
  controller_user_id: string | null;
  controller_device_id: string | null;
  mobile_control_status: GatewayRuntimeStateRecord["mobileControlStatus"];
  last_seen_at: string | null;
};
type AuditRow = RowDataPacket & {
  id: number;
  gateway_id: string;
  user_id: string;
  method: string;
  risk_level: CommandAuditLogRecord["riskLevel"];
  params_masked: string;
  result_ok: number;
  error_code: string | null;
  duration_ms: number;
  created_at: string;
};
type ApprovalRow = RowDataPacket & {
  gateway_id: string;
  user_id: string;
  method: string;
  expires_at: string;
  created_at: string;
};

export class RelayStore {
  private state: RelayState = structuredClone(EMPTY_STATE);
  private saveQueue: Promise<void> = Promise.resolve();

  private constructor(private readonly pool: Pool) {}

  static async create(databaseUrl: string): Promise<RelayStore> {
    const pool = mysql.createPool(databaseUrl);
    const store = new RelayStore(pool);
    await store.ensureSchema();
    await store.load();
    return store;
  }

  private async ensureSchema(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS approvals (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        gateway_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        method VARCHAR(128) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uk_approvals_gateway_user_method (gateway_id, user_id, method),
        KEY idx_approvals_expires_at (expires_at),
        CONSTRAINT fk_approvals_gateway
          FOREIGN KEY (gateway_id) REFERENCES gateways (id)
          ON DELETE CASCADE,
        CONSTRAINT fk_approvals_user
          FOREIGN KEY (user_id) REFERENCES users (id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
  }

  private async load(): Promise<void> {
    const [users] = await this.pool.query<UserRow[]>("SELECT id, name, created_at FROM users");
    const [devices] = await this.pool.query<MobileDeviceRow[]>(
      "SELECT id, user_id, platform, app_version, created_at, last_seen_at FROM mobile_devices",
    );
    const [gateways] = await this.pool.query<GatewayRow[]>(
      "SELECT id, owner_user_id, gateway_code, relay_secret_hash, display_name, platform, agent_version, openclaw_version, status, last_seen_at, created_at, updated_at FROM gateways",
    );
    const [pairingCodes] = await this.pool.query<PairingCodeRow[]>(
      "SELECT gateway_id, access_code_hash, expires_at, used_at, created_at FROM gateway_pairing_codes",
    );
    const [memberships] = await this.pool.query<MembershipRow[]>(
      "SELECT gateway_id, user_id, role, created_at FROM gateway_memberships",
    );
    const [runtimeStates] = await this.pool.query<RuntimeRow[]>(
      "SELECT gateway_id, relay_status, host_status, openclaw_status, aggregate_status, current_model, context_usage, controller_user_id, controller_device_id, mobile_control_status, last_seen_at FROM gateway_runtime_state",
    );
    const [auditLogs] = await this.pool.query<AuditRow[]>(
      "SELECT id, gateway_id, user_id, method, risk_level, params_masked, result_ok, error_code, duration_ms, created_at FROM command_audit_logs ORDER BY id DESC LIMIT 5000",
    );
    const [approvals] = await this.pool.query<ApprovalRow[]>(
      "SELECT gateway_id, user_id, method, expires_at, created_at FROM approvals",
    );

    this.state = structuredClone(EMPTY_STATE);

    for (const row of users) {
      this.state.users[row.id] = {
        id: row.id,
        name: row.name,
        createdAt: toIso(row.created_at) ?? new Date().toISOString(),
      };
    }

    for (const row of devices) {
      this.state.mobileDevices[row.id] = {
        id: row.id,
        userId: row.user_id,
        platform: row.platform,
        appVersion: row.app_version ?? undefined,
        createdAt: toIso(row.created_at) ?? new Date().toISOString(),
        lastSeenAt: toIso(row.last_seen_at) ?? new Date().toISOString(),
      };
    }

    for (const row of gateways) {
      this.state.gateways[row.id] = {
        id: row.id,
        ownerUserId: row.owner_user_id ?? undefined,
        gatewayCode: row.gateway_code,
        relaySecretHash: row.relay_secret_hash,
        displayName: row.display_name,
        platform: row.platform,
        agentVersion: row.agent_version,
        openclawVersion: row.openclaw_version ?? undefined,
        status: row.status,
        lastSeenAt: toIso(row.last_seen_at),
        createdAt: toIso(row.created_at) ?? new Date().toISOString(),
        updatedAt: toIso(row.updated_at) ?? new Date().toISOString(),
      };
    }

    for (const row of pairingCodes) {
      this.state.gatewayPairingCodes[row.gateway_id] = {
        gatewayId: row.gateway_id,
        accessCodeHash: row.access_code_hash,
        expiresAt: toIso(row.expires_at) ?? new Date().toISOString(),
        usedAt: toIso(row.used_at),
        createdAt: toIso(row.created_at) ?? new Date().toISOString(),
      };
    }

    this.state.gatewayMemberships = memberships.map((row) => ({
      gatewayId: row.gateway_id,
      userId: row.user_id,
      role: row.role,
      createdAt: toIso(row.created_at) ?? new Date().toISOString(),
    }));

    for (const row of runtimeStates) {
      this.state.gatewayRuntimeState[row.gateway_id] = {
        gatewayId: row.gateway_id,
        relayStatus: row.relay_status,
        hostStatus: row.host_status,
        openclawStatus: row.openclaw_status,
        aggregateStatus: row.aggregate_status,
        currentModel: row.current_model ?? undefined,
        contextUsage: row.context_usage ?? undefined,
        controllerUserId: row.controller_user_id ?? undefined,
        controllerDeviceId: row.controller_device_id ?? undefined,
        mobileControlStatus: row.mobile_control_status,
        lastSeenAt: toIso(row.last_seen_at),
      };
    }

    this.state.commandAuditLogs = auditLogs.map((row) => ({
      id: String(row.id),
      gatewayId: row.gateway_id,
      userId: row.user_id,
      method: row.method,
      riskLevel: row.risk_level,
      paramsMasked: row.params_masked,
      resultOk: Boolean(row.result_ok),
      errorCode: row.error_code ?? undefined,
      durationMs: row.duration_ms,
      createdAt: toIso(row.created_at) ?? new Date().toISOString(),
    }));

    this.state.approvals = approvals.map((row) => ({
      gatewayId: row.gateway_id,
      userId: row.user_id,
      method: row.method,
      expiresAt: toIso(row.expires_at) ?? new Date().toISOString(),
      createdAt: toIso(row.created_at) ?? new Date().toISOString(),
    }));
  }

  async save(): Promise<void> {
    this.saveQueue = this.saveQueue.then(async () => {
      const conn = await this.pool.getConnection();
      try {
        await conn.beginTransaction();

        await conn.query("DELETE FROM approvals");
        await conn.query("DELETE FROM command_audit_logs");
        await conn.query("DELETE FROM gateway_runtime_state");
        await conn.query("DELETE FROM gateway_memberships");
        await conn.query("DELETE FROM gateway_pairing_codes");
        await conn.query("DELETE FROM mobile_devices");
        await conn.query("DELETE FROM gateways");
        await conn.query("DELETE FROM users");

        for (const user of Object.values(this.state.users)) {
          await conn.query(
            "INSERT INTO users (id, name, created_at, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE name = VALUES(name), updated_at = VALUES(updated_at)",
            [user.id, user.name, toSqlDate(user.createdAt), toSqlDate(new Date().toISOString())],
          );
        }

        for (const gateway of Object.values(this.state.gateways)) {
          await conn.query(
            "INSERT INTO gateways (id, owner_user_id, gateway_code, relay_secret_hash, display_name, platform, agent_version, openclaw_version, status, last_seen_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
              gateway.id,
              gateway.ownerUserId ?? null,
              gateway.gatewayCode,
              gateway.relaySecretHash,
              gateway.displayName,
              gateway.platform,
              gateway.agentVersion,
              gateway.openclawVersion ?? null,
              gateway.status,
              toSqlDate(gateway.lastSeenAt),
              toSqlDate(gateway.createdAt),
              toSqlDate(gateway.updatedAt),
            ],
          );
        }

        for (const device of Object.values(this.state.mobileDevices)) {
          await conn.query(
            "INSERT INTO mobile_devices (id, user_id, platform, app_version, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
            [
              device.id,
              device.userId,
              device.platform,
              device.appVersion ?? null,
              toSqlDate(device.createdAt),
              toSqlDate(device.lastSeenAt),
            ],
          );
        }

        for (const code of Object.values(this.state.gatewayPairingCodes)) {
          await conn.query(
            "INSERT INTO gateway_pairing_codes (gateway_id, access_code_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?)",
            [
              code.gatewayId,
              code.accessCodeHash,
              toSqlDate(code.expiresAt),
              toSqlDate(code.usedAt),
              toSqlDate(code.createdAt),
            ],
          );
        }

        for (const membership of this.state.gatewayMemberships) {
          await conn.query(
            "INSERT INTO gateway_memberships (gateway_id, user_id, role, created_at) VALUES (?, ?, ?, ?)",
            [
              membership.gatewayId,
              membership.userId,
              membership.role,
              toSqlDate(membership.createdAt),
            ],
          );
        }

        for (const runtime of Object.values(this.state.gatewayRuntimeState)) {
          await conn.query(
            "INSERT INTO gateway_runtime_state (gateway_id, relay_status, host_status, openclaw_status, aggregate_status, current_model, context_usage, controller_user_id, controller_device_id, mobile_control_status, last_seen_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
              runtime.gatewayId,
              runtime.relayStatus,
              runtime.hostStatus,
              runtime.openclawStatus,
              runtime.aggregateStatus,
              runtime.currentModel ?? null,
              runtime.contextUsage ?? null,
              runtime.controllerUserId ?? null,
              runtime.controllerDeviceId ?? null,
              runtime.mobileControlStatus,
              toSqlDate(runtime.lastSeenAt),
              toSqlDate(new Date().toISOString()),
            ],
          );
        }

        for (const log of this.state.commandAuditLogs.slice(0, 5000)) {
          await conn.query(
            "INSERT INTO command_audit_logs (gateway_id, user_id, method, risk_level, params_masked, result_ok, error_code, duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
              log.gatewayId,
              log.userId,
              log.method,
              log.riskLevel,
              log.paramsMasked,
              log.resultOk ? 1 : 0,
              log.errorCode ?? null,
              log.durationMs,
              toSqlDate(log.createdAt),
            ],
          );
        }

        for (const approval of this.state.approvals) {
          await conn.query(
            "INSERT INTO approvals (gateway_id, user_id, method, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            [
              approval.gatewayId,
              approval.userId,
              approval.method,
              toSqlDate(approval.expiresAt),
              toSqlDate(approval.createdAt),
            ],
          );
        }

        await conn.commit();
      } catch (error) {
        await conn.rollback();
        throw error;
      } finally {
        conn.release();
      }
    });
    return this.saveQueue;
  }

  snapshot(): RelayState {
    return this.state;
  }

  putUser(user: UserRecord): void {
    this.state.users[user.id] = user;
  }

  putMobileDevice(device: MobileDeviceRecord): void {
    this.state.mobileDevices[device.id] = device;
  }

  putGateway(gateway: GatewayRecord): void {
    this.state.gateways[gateway.id] = gateway;
  }

  putPairingCode(record: GatewayPairingCodeRecord): void {
    this.state.gatewayPairingCodes[record.gatewayId] = record;
  }

  putRuntimeState(runtime: GatewayRuntimeStateRecord): void {
    this.state.gatewayRuntimeState[runtime.gatewayId] = runtime;
  }

  putMembership(record: GatewayMembershipRecord): void {
    const existing = this.state.gatewayMemberships.find(
      (membership) => membership.gatewayId === record.gatewayId && membership.userId === record.userId,
    );
    if (existing) {
      existing.role = record.role;
      return;
    }
    this.state.gatewayMemberships.push(record);
  }

  removeMembership(gatewayId: string, userId: string): void {
    this.state.gatewayMemberships = this.state.gatewayMemberships.filter(
      (membership) => !(membership.gatewayId === gatewayId && membership.userId === userId),
    );
  }

  addAuditLog(log: CommandAuditLogRecord): void {
    this.state.commandAuditLogs.unshift(log);
    this.state.commandAuditLogs = this.state.commandAuditLogs.slice(0, 5000);
  }

  addApproval(approval: ApprovalRecord): void {
    this.state.approvals = this.state.approvals.filter(
      (current) =>
        !(
          current.gatewayId === approval.gatewayId &&
          current.userId === approval.userId &&
          current.method === approval.method
        ),
    );
    this.state.approvals.push(approval);
  }

  consumeApproval(gatewayId: string, userId: string, method: string, now: string): boolean {
    const index = this.state.approvals.findIndex(
      (approval) =>
        approval.gatewayId === gatewayId &&
        approval.userId === userId &&
        approval.method === method &&
        approval.expiresAt > now,
    );
    if (index < 0) return false;
    this.state.approvals.splice(index, 1);
    return true;
  }

  cleanupExpired(now: string): void {
    for (const [gatewayId, code] of Object.entries(this.state.gatewayPairingCodes)) {
      if (code.expiresAt <= now || code.usedAt) {
        delete this.state.gatewayPairingCodes[gatewayId];
      }
    }
    this.state.approvals = this.state.approvals.filter((approval) => approval.expiresAt > now);
  }
}
