import mysql, { type Pool, type RowDataPacket } from "mysql2/promise";
import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import type {
  ApprovalRecord,
  CommandAuditLogRecord,
  GatewayMembershipRecord,
  GatewayPairingCodeRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  MobileDeviceRecord,
  RelayState,
  TaskRecord,
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
  tasks: {},
};

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const KEY_SEPARATOR = "\u0000";

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

function isClosedConnectionError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
  const message = error instanceof Error ? error.message : String(error);
  return code === "PROTOCOL_CONNECTION_LOST" || message.includes("closed state");
}

type UserRow = RowDataPacket & { id: string; email: string | null; password_hash: string | null; name: string; created_at: string };
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
  context_limit: number | null;
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
type TaskRow = RowDataPacket & {
  id: string;
  gateway_id: string;
  user_id: string;
  title: string;
  prompt: string;
  schedule_kind: TaskRecord["scheduleKind"];
  schedule_at: string | null;
  repeat_amount: number | null;
  repeat_unit: TaskRecord["repeatUnit"] | null;
  enabled: number;
  last_result: string;
  next_run_at: string | null;
  created_at: string;
  updated_at: string;
};

type PendingChanges = {
  users: Set<string>;
  mobileDevices: Set<string>;
  gateways: Set<string>;
  pairingCodes: Set<string>;
  deletedPairingCodes: Set<string>;
  runtimeStates: Set<string>;
  memberships: Set<string>;
  deletedMemberships: Set<string>;
  approvals: Set<string>;
  deletedApprovals: Set<string>;
  tasks: Set<string>;
  deletedTasks: Set<string>;
  auditLogs: CommandAuditLogRecord[];
  trimAuditLogs: boolean;
};

function createPendingChanges(): PendingChanges {
  return {
    users: new Set(),
    mobileDevices: new Set(),
    gateways: new Set(),
    pairingCodes: new Set(),
    deletedPairingCodes: new Set(),
    runtimeStates: new Set(),
    memberships: new Set(),
    deletedMemberships: new Set(),
    approvals: new Set(),
    deletedApprovals: new Set(),
    tasks: new Set(),
    deletedTasks: new Set(),
    auditLogs: [],
    trimAuditLogs: false,
  };
}

function membershipKey(gatewayId: string, userId: string): string {
  return `${gatewayId}${KEY_SEPARATOR}${userId}`;
}

function parseMembershipKey(value: string): [string, string] {
  const separatorIndex = value.indexOf(KEY_SEPARATOR);
  if (separatorIndex < 0) return [value, ""];
  return [value.slice(0, separatorIndex), value.slice(separatorIndex + 1)];
}

function approvalKey(gatewayId: string, userId: string, method: string): string {
  return `${gatewayId}${KEY_SEPARATOR}${userId}${KEY_SEPARATOR}${method}`;
}

function parseApprovalKey(value: string): [string, string, string] {
  const parts = value.split(KEY_SEPARATOR);
  return [parts[0] ?? "", parts[1] ?? "", parts.slice(2).join(KEY_SEPARATOR)];
}

function hasPendingChanges(pending: PendingChanges): boolean {
  return (
    pending.users.size > 0 ||
    pending.mobileDevices.size > 0 ||
    pending.gateways.size > 0 ||
    pending.pairingCodes.size > 0 ||
    pending.deletedPairingCodes.size > 0 ||
    pending.runtimeStates.size > 0 ||
    pending.memberships.size > 0 ||
    pending.deletedMemberships.size > 0 ||
    pending.approvals.size > 0 ||
    pending.deletedApprovals.size > 0 ||
    pending.tasks.size > 0 ||
    pending.deletedTasks.size > 0 ||
    pending.auditLogs.length > 0 ||
    pending.trimAuditLogs
  );
}

export class RelayStore {
  private state: RelayState = structuredClone(EMPTY_STATE);
  private saveQueue: Promise<void> = Promise.resolve();
  private pendingChanges: PendingChanges = createPendingChanges();

  private constructor(private readonly pool: Pool) {}

  static async create(databaseUrl: string): Promise<RelayStore> {
    const pool = mysql.createPool(databaseUrl);
    const store = new RelayStore(pool);
    await store.ensureSchema();
    await store.load();
    return store;
  }

  async deleteUserAccount(userId: string): Promise<void> {
    const conn = await this.pool.getConnection();
    let shouldDestroyConnection = false;
    try {
      await conn.ping();
      await conn.beginTransaction();
      await conn.query(
        `
          DELETE FROM relay_sessions
          WHERE user_id = ?
             OR device_id IN (
               SELECT id
               FROM mobile_devices
               WHERE user_id = ?
             )
        `,
        [userId, userId],
      );
      await conn.query("DELETE FROM users WHERE id = ?", [userId]);
      await conn.commit();
    } catch (error) {
      shouldDestroyConnection = isClosedConnectionError(error);
      try {
        await conn.rollback();
      } catch (rollbackError) {
        if (!isClosedConnectionError(rollbackError)) {
          console.error("[relay-store] rollback failed", rollbackError);
        }
      }
      throw error;
    } finally {
      if (shouldDestroyConnection) {
        (conn as { destroy?: () => void }).destroy?.();
      }
      conn.release();
    }
    await this.load();
  }

  private async ensureSchema(): Promise<void> {
    const schemaPath = join(__dirname, "..", "mysql", "init", "001_schema.sql");
    const schemaSql = readFileSync(schemaPath, "utf8");
    const statements = schemaSql
      .split(/;\s*(?:\r?\n|$)/)
      .map((statement) => statement.trim())
      .filter((statement) => statement.length > 0)
      .filter((statement) => {
        const upper = statement.toUpperCase();
        return !upper.startsWith("CREATE DATABASE ") && !upper.startsWith("USE ");
      });

    for (const statement of statements) {
      await this.pool.query(statement);
    }

    const [userColumns] = await this.pool.query<RowDataPacket[]>(
      "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'users'",
    );
    const userColumnSet = new Set(userColumns.map((row) => String(row.COLUMN_NAME)));
    if (!userColumnSet.has("email")) {
      await this.pool.query("ALTER TABLE users ADD COLUMN email VARCHAR(255) NULL");
    }
    if (!userColumnSet.has("password_hash")) {
      await this.pool.query("ALTER TABLE users ADD COLUMN password_hash TEXT NULL");
    }
    const [runtimeColumns] = await this.pool.query<RowDataPacket[]>(
      "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'gateway_runtime_state'",
    );
    const runtimeColumnSet = new Set(runtimeColumns.map((row) => String(row.COLUMN_NAME)));
    if (!runtimeColumnSet.has("context_limit")) {
      await this.pool.query("ALTER TABLE gateway_runtime_state ADD COLUMN context_limit INT DEFAULT NULL AFTER context_usage");
    }
    const [fileTransferColumns] = await this.pool.query<RowDataPacket[]>(
      "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'file_transfers'",
    );
    const fileTransferColumnSet = new Set(fileTransferColumns.map((row) => String(row.COLUMN_NAME)));
    if (!fileTransferColumnSet.has("sort_timestamp_ms")) {
      await this.pool.query(
        "ALTER TABLE file_transfers ADD COLUMN sort_timestamp_ms BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER expires_at",
      );
    }
    await this.pool.query(
      "UPDATE file_transfers SET sort_timestamp_ms = UNIX_TIMESTAMP(created_at) * 1000 WHERE sort_timestamp_ms = 0",
    );
    const [fileTransferIndexes] = await this.pool.query<RowDataPacket[]>(
      "SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'file_transfers'",
    );
    const fileTransferIndexSet = new Set(fileTransferIndexes.map((row) => String(row.INDEX_NAME)));
    if (!fileTransferIndexSet.has("idx_file_transfers_gateway_status_sort_timestamp_ms")) {
      await this.pool.query(
        "ALTER TABLE file_transfers ADD INDEX idx_file_transfers_gateway_status_sort_timestamp_ms (gateway_id, status, sort_timestamp_ms)",
      );
    }
    if (!fileTransferIndexSet.has("idx_file_transfers_gateway_session_status_sort_timestamp_ms")) {
      await this.pool.query(
        "ALTER TABLE file_transfers ADD INDEX idx_file_transfers_gateway_session_status_sort_timestamp_ms (gateway_id, session_key, status, sort_timestamp_ms)",
      );
    }
    if (!fileTransferIndexSet.has("idx_file_transfers_gateway_status_created_at")) {
      await this.pool.query(
        "ALTER TABLE file_transfers ADD INDEX idx_file_transfers_gateway_status_created_at (gateway_id, status, created_at)",
      );
    }
    if (!fileTransferIndexSet.has("idx_file_transfers_gateway_session_status_created_at")) {
      await this.pool.query(
        "ALTER TABLE file_transfers ADD INDEX idx_file_transfers_gateway_session_status_created_at (gateway_id, session_key, status, created_at)",
      );
    }
    await this.pool.query(`
      UPDATE users
      SET
        email = COALESCE(NULLIF(email, ''), CONCAT(id, '@local.invalid')),
        password_hash = COALESCE(password_hash, '')
    `);
  }

  private async load(): Promise<void> {
    const [users] = await this.pool.query<UserRow[]>("SELECT id, email, password_hash, name, created_at FROM users");
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
      "SELECT gateway_id, relay_status, host_status, openclaw_status, aggregate_status, current_model, context_usage, context_limit, controller_user_id, controller_device_id, mobile_control_status, last_seen_at FROM gateway_runtime_state",
    );
    const [auditLogs] = await this.pool.query<AuditRow[]>(
      "SELECT id, gateway_id, user_id, method, risk_level, params_masked, result_ok, error_code, duration_ms, created_at FROM command_audit_logs ORDER BY id DESC LIMIT 5000",
    );
    const [approvals] = await this.pool.query<ApprovalRow[]>(
      "SELECT gateway_id, user_id, method, expires_at, created_at FROM approvals",
    );
    const [tasks] = await this.pool.query<TaskRow[]>(
      "SELECT id, gateway_id, user_id, title, prompt, schedule_kind, schedule_at, repeat_amount, repeat_unit, enabled, last_result, next_run_at, created_at, updated_at FROM gateway_tasks",
    );

    this.state = structuredClone(EMPTY_STATE);

    for (const row of users) {
      this.state.users[row.id] = {
        id: row.id,
        email: row.email ?? `${row.id}@local.invalid`,
        passwordHash: row.password_hash ?? "",
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
        contextLimit: row.context_limit ?? undefined,
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

    for (const row of tasks) {
      this.state.tasks[row.id] = {
        id: row.id,
        gatewayId: row.gateway_id,
        userId: row.user_id,
        title: row.title,
        prompt: row.prompt,
        scheduleKind: row.schedule_kind,
        scheduleAt: toIso(row.schedule_at),
        repeatAmount: row.repeat_amount ?? undefined,
        repeatUnit: row.repeat_unit ?? undefined,
        enabled: Boolean(row.enabled),
        lastResult: row.last_result ?? "",
        nextRunAt: toIso(row.next_run_at),
        createdAt: toIso(row.created_at) ?? new Date().toISOString(),
        updatedAt: toIso(row.updated_at) ?? new Date().toISOString(),
      };
    }

    this.pendingChanges = createPendingChanges();
  }

  async save(): Promise<void> {
    this.saveQueue = this.saveQueue.catch(() => undefined).then(async () => {
      const pending = this.takePendingChanges();
      if (!hasPendingChanges(pending)) {
        return;
      }

      const maxAttempts = 2;
      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        const conn = await this.pool.getConnection();
        let shouldDestroyConnection = false;
        try {
          // Long-lived relay processes can pull a stale pooled connection after MySQL
          // closes it underneath us. Ping first so we can retry with a fresh socket.
          await conn.ping();
          await conn.beginTransaction();

          for (const userId of pending.users) {
            const user = this.state.users[userId];
            if (!user) continue;
            await conn.query(
              "INSERT INTO users (id, email, password_hash, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) AS new_user ON DUPLICATE KEY UPDATE email = new_user.email, password_hash = new_user.password_hash, name = new_user.name, updated_at = new_user.updated_at",
              [user.id, user.email, user.passwordHash, user.name, toSqlDate(user.createdAt), toSqlDate(new Date().toISOString())],
            );
          }

          for (const gatewayId of pending.gateways) {
            const gateway = this.state.gateways[gatewayId];
            if (!gateway) continue;
            await conn.query(
              "INSERT INTO gateways (id, owner_user_id, gateway_code, relay_secret_hash, display_name, platform, agent_version, openclaw_version, status, last_seen_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS new_gateway ON DUPLICATE KEY UPDATE owner_user_id = new_gateway.owner_user_id, gateway_code = new_gateway.gateway_code, relay_secret_hash = new_gateway.relay_secret_hash, display_name = new_gateway.display_name, platform = new_gateway.platform, agent_version = new_gateway.agent_version, openclaw_version = new_gateway.openclaw_version, status = new_gateway.status, last_seen_at = new_gateway.last_seen_at, created_at = new_gateway.created_at, updated_at = new_gateway.updated_at",
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

          for (const deviceId of pending.mobileDevices) {
            const device = this.state.mobileDevices[deviceId];
            if (!device) continue;
            await conn.query(
              "INSERT INTO mobile_devices (id, user_id, platform, app_version, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?) AS new_device ON DUPLICATE KEY UPDATE user_id = new_device.user_id, platform = new_device.platform, app_version = new_device.app_version, created_at = new_device.created_at, last_seen_at = new_device.last_seen_at",
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

          for (const gatewayId of pending.pairingCodes) {
            const code = this.state.gatewayPairingCodes[gatewayId];
            if (!code) continue;
            await conn.query(
              "INSERT INTO gateway_pairing_codes (gateway_id, access_code_hash, expires_at, used_at, created_at) VALUES (?, ?, ?, ?, ?) AS new_code ON DUPLICATE KEY UPDATE access_code_hash = new_code.access_code_hash, expires_at = new_code.expires_at, used_at = new_code.used_at, created_at = new_code.created_at",
              [
                code.gatewayId,
                code.accessCodeHash,
                toSqlDate(code.expiresAt),
                toSqlDate(code.usedAt),
                toSqlDate(code.createdAt),
              ],
            );
          }

          for (const key of pending.memberships) {
            const [gatewayId, userId] = parseMembershipKey(key);
            const membership = this.state.gatewayMemberships.find(
              (candidate) => candidate.gatewayId === gatewayId && candidate.userId === userId,
            );
            if (!membership) continue;
            await conn.query(
              "INSERT INTO gateway_memberships (gateway_id, user_id, role, created_at) VALUES (?, ?, ?, ?) AS new_membership ON DUPLICATE KEY UPDATE role = new_membership.role, created_at = new_membership.created_at",
              [
                membership.gatewayId,
                membership.userId,
                membership.role,
                toSqlDate(membership.createdAt),
              ],
            );
          }

          for (const gatewayId of pending.runtimeStates) {
            const runtime = this.state.gatewayRuntimeState[gatewayId];
            if (!runtime) continue;
            await conn.query(
              "INSERT INTO gateway_runtime_state (gateway_id, relay_status, host_status, openclaw_status, aggregate_status, current_model, context_usage, context_limit, controller_user_id, controller_device_id, mobile_control_status, last_seen_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS new_runtime ON DUPLICATE KEY UPDATE relay_status = new_runtime.relay_status, host_status = new_runtime.host_status, openclaw_status = new_runtime.openclaw_status, aggregate_status = new_runtime.aggregate_status, current_model = new_runtime.current_model, context_usage = new_runtime.context_usage, context_limit = new_runtime.context_limit, controller_user_id = new_runtime.controller_user_id, controller_device_id = new_runtime.controller_device_id, mobile_control_status = new_runtime.mobile_control_status, last_seen_at = new_runtime.last_seen_at, updated_at = new_runtime.updated_at",
              [
                runtime.gatewayId,
                runtime.relayStatus,
                runtime.hostStatus,
                runtime.openclawStatus,
                runtime.aggregateStatus,
                runtime.currentModel ?? null,
                runtime.contextUsage ?? null,
                runtime.contextLimit ?? null,
                runtime.controllerUserId ?? null,
                runtime.controllerDeviceId ?? null,
                runtime.mobileControlStatus,
                toSqlDate(runtime.lastSeenAt),
                toSqlDate(new Date().toISOString()),
              ],
            );
          }

          for (const log of pending.auditLogs) {
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
          if (pending.trimAuditLogs) {
            await conn.query(`
              DELETE FROM command_audit_logs
              WHERE id NOT IN (
                SELECT id
                FROM (
                  SELECT id
                  FROM command_audit_logs
                  ORDER BY id DESC
                  LIMIT 5000
                ) AS recent_logs
              )
            `);
          }

          for (const key of pending.approvals) {
            const [gatewayId, userId, method] = parseApprovalKey(key);
            const approval = this.state.approvals.find(
              (candidate) =>
                candidate.gatewayId === gatewayId &&
                candidate.userId === userId &&
                candidate.method === method,
            );
            if (!approval) continue;
            await conn.query(
              "INSERT INTO approvals (gateway_id, user_id, method, expires_at, created_at) VALUES (?, ?, ?, ?, ?) AS new_approval ON DUPLICATE KEY UPDATE expires_at = new_approval.expires_at, created_at = new_approval.created_at",
              [
                approval.gatewayId,
                approval.userId,
                approval.method,
                toSqlDate(approval.expiresAt),
                toSqlDate(approval.createdAt),
              ],
            );
          }

          for (const taskId of pending.tasks) {
            const task = this.state.tasks[taskId];
            if (!task) continue;
            await conn.query(
              "INSERT INTO gateway_tasks (id, gateway_id, user_id, title, prompt, schedule_kind, schedule_at, repeat_amount, repeat_unit, enabled, last_result, next_run_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) AS new_task ON DUPLICATE KEY UPDATE gateway_id = new_task.gateway_id, user_id = new_task.user_id, title = new_task.title, prompt = new_task.prompt, schedule_kind = new_task.schedule_kind, schedule_at = new_task.schedule_at, repeat_amount = new_task.repeat_amount, repeat_unit = new_task.repeat_unit, enabled = new_task.enabled, last_result = new_task.last_result, next_run_at = new_task.next_run_at, created_at = new_task.created_at, updated_at = new_task.updated_at",
              [
                task.id,
                task.gatewayId,
                task.userId,
                task.title,
                task.prompt,
                task.scheduleKind,
                toSqlDate(task.scheduleAt),
                task.repeatAmount ?? null,
                task.repeatUnit ?? null,
                task.enabled ? 1 : 0,
                task.lastResult,
                toSqlDate(task.nextRunAt),
                toSqlDate(task.createdAt),
                toSqlDate(task.updatedAt),
              ],
            );
          }

          for (const gatewayId of pending.deletedPairingCodes) {
            await conn.query("DELETE FROM gateway_pairing_codes WHERE gateway_id = ?", [gatewayId]);
          }

          for (const key of pending.deletedMemberships) {
            const [gatewayId, userId] = parseMembershipKey(key);
            await conn.query("DELETE FROM gateway_memberships WHERE gateway_id = ? AND user_id = ?", [gatewayId, userId]);
          }

          for (const key of pending.deletedApprovals) {
            const [gatewayId, userId, method] = parseApprovalKey(key);
            await conn.query("DELETE FROM approvals WHERE gateway_id = ? AND user_id = ? AND method = ?", [gatewayId, userId, method]);
          }

          for (const taskId of pending.deletedTasks) {
            await conn.query("DELETE FROM gateway_tasks WHERE id = ?", [taskId]);
          }

          await conn.commit();
          return;
        } catch (error) {
          shouldDestroyConnection = isClosedConnectionError(error);
          try {
            await conn.rollback();
          } catch (rollbackError) {
            if (!isClosedConnectionError(rollbackError)) {
              console.error("[relay-store] rollback failed", rollbackError);
            }
          }
          if (!shouldDestroyConnection || attempt >= maxAttempts) {
            this.restorePendingChanges(pending);
            throw error;
          }
          console.warn(`[relay-store] retrying save after stale MySQL connection (attempt ${attempt}/${maxAttempts})`);
        } finally {
          if (shouldDestroyConnection) {
            (conn as { destroy?: () => void }).destroy?.();
          }
          conn.release();
        }
      }
    });
    return this.saveQueue;
  }

  snapshot(): RelayState {
    return this.state;
  }

  putUser(user: UserRecord): void {
    this.state.users[user.id] = user;
    this.pendingChanges.users.add(user.id);
  }

  putMobileDevice(device: MobileDeviceRecord): void {
    this.state.mobileDevices[device.id] = device;
    this.pendingChanges.mobileDevices.add(device.id);
  }

  putGateway(gateway: GatewayRecord): void {
    this.state.gateways[gateway.id] = gateway;
    this.pendingChanges.gateways.add(gateway.id);
  }

  putPairingCode(record: GatewayPairingCodeRecord): void {
    this.state.gatewayPairingCodes[record.gatewayId] = record;
    this.pendingChanges.pairingCodes.add(record.gatewayId);
    this.pendingChanges.deletedPairingCodes.delete(record.gatewayId);
  }

  putRuntimeState(runtime: GatewayRuntimeStateRecord): void {
    this.state.gatewayRuntimeState[runtime.gatewayId] = runtime;
    this.pendingChanges.runtimeStates.add(runtime.gatewayId);
  }

  putMembership(record: GatewayMembershipRecord): void {
    const existing = this.state.gatewayMemberships.find(
      (membership) => membership.gatewayId === record.gatewayId && membership.userId === record.userId,
    );
    if (existing) {
      existing.role = record.role;
      existing.createdAt = record.createdAt;
      this.pendingChanges.memberships.add(membershipKey(record.gatewayId, record.userId));
      this.pendingChanges.deletedMemberships.delete(membershipKey(record.gatewayId, record.userId));
      return;
    }
    this.state.gatewayMemberships.push(record);
    this.pendingChanges.memberships.add(membershipKey(record.gatewayId, record.userId));
    this.pendingChanges.deletedMemberships.delete(membershipKey(record.gatewayId, record.userId));
  }

  removeMembership(gatewayId: string, userId: string): void {
    this.state.gatewayMemberships = this.state.gatewayMemberships.filter(
      (membership) => !(membership.gatewayId === gatewayId && membership.userId === userId),
    );
    const key = membershipKey(gatewayId, userId);
    this.pendingChanges.memberships.delete(key);
    this.pendingChanges.deletedMemberships.add(key);
  }

  addAuditLog(log: CommandAuditLogRecord): void {
    this.state.commandAuditLogs.unshift(log);
    this.state.commandAuditLogs = this.state.commandAuditLogs.slice(0, 5000);
    this.pendingChanges.auditLogs.push(log);
    this.pendingChanges.trimAuditLogs = true;
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
    const key = approvalKey(approval.gatewayId, approval.userId, approval.method);
    this.pendingChanges.approvals.add(key);
    this.pendingChanges.deletedApprovals.delete(key);
  }

  putTask(task: TaskRecord): void {
    this.state.tasks[task.id] = task;
    this.pendingChanges.tasks.add(task.id);
    this.pendingChanges.deletedTasks.delete(task.id);
  }

  removeTask(taskId: string): void {
    delete this.state.tasks[taskId];
    this.pendingChanges.tasks.delete(taskId);
    this.pendingChanges.deletedTasks.add(taskId);
  }

  tasksForGateway(gatewayId: string): TaskRecord[] {
    return Object.values(this.state.tasks).filter((task) => task.gatewayId === gatewayId);
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
    const [approval] = this.state.approvals.splice(index, 1);
    const key = approvalKey(approval.gatewayId, approval.userId, approval.method);
    this.pendingChanges.approvals.delete(key);
    this.pendingChanges.deletedApprovals.add(key);
    return true;
  }

  cleanupExpired(now: string): void {
    for (const [gatewayId, code] of Object.entries(this.state.gatewayPairingCodes)) {
      if (code.expiresAt <= now || code.usedAt) {
        delete this.state.gatewayPairingCodes[gatewayId];
        this.pendingChanges.pairingCodes.delete(gatewayId);
        this.pendingChanges.deletedPairingCodes.add(gatewayId);
      }
    }
    const remainingApprovals: ApprovalRecord[] = [];
    for (const approval of this.state.approvals) {
      if (approval.expiresAt > now) {
        remainingApprovals.push(approval);
        continue;
      }
      const key = approvalKey(approval.gatewayId, approval.userId, approval.method);
      this.pendingChanges.approvals.delete(key);
      this.pendingChanges.deletedApprovals.add(key);
    }
    this.state.approvals = remainingApprovals;
  }

  private takePendingChanges(): PendingChanges {
    const current = this.pendingChanges;
    this.pendingChanges = createPendingChanges();
    return current;
  }

  private restorePendingChanges(pending: PendingChanges): void {
    for (const value of pending.users) this.pendingChanges.users.add(value);
    for (const value of pending.mobileDevices) this.pendingChanges.mobileDevices.add(value);
    for (const value of pending.gateways) this.pendingChanges.gateways.add(value);
    for (const value of pending.pairingCodes) this.pendingChanges.pairingCodes.add(value);
    for (const value of pending.deletedPairingCodes) this.pendingChanges.deletedPairingCodes.add(value);
    for (const value of pending.runtimeStates) this.pendingChanges.runtimeStates.add(value);
    for (const value of pending.memberships) this.pendingChanges.memberships.add(value);
    for (const value of pending.deletedMemberships) this.pendingChanges.deletedMemberships.add(value);
    for (const value of pending.approvals) this.pendingChanges.approvals.add(value);
    for (const value of pending.deletedApprovals) this.pendingChanges.deletedApprovals.add(value);
    for (const value of pending.tasks) this.pendingChanges.tasks.add(value);
    for (const value of pending.deletedTasks) this.pendingChanges.deletedTasks.add(value);
    this.pendingChanges.auditLogs = [...pending.auditLogs, ...this.pendingChanges.auditLogs];
    this.pendingChanges.trimAuditLogs = this.pendingChanges.trimAuditLogs || pending.trimAuditLogs;

    for (const gatewayId of Array.from(this.pendingChanges.pairingCodes)) {
      if (!this.state.gatewayPairingCodes[gatewayId]) {
        this.pendingChanges.pairingCodes.delete(gatewayId);
      }
    }
    for (const gatewayId of Array.from(this.pendingChanges.deletedPairingCodes)) {
      if (this.state.gatewayPairingCodes[gatewayId]) {
        this.pendingChanges.deletedPairingCodes.delete(gatewayId);
      }
    }
    for (const key of Array.from(this.pendingChanges.memberships)) {
      const [gatewayId, userId] = parseMembershipKey(key);
      const exists = this.state.gatewayMemberships.some(
        (membership) => membership.gatewayId === gatewayId && membership.userId === userId,
      );
      if (!exists) {
        this.pendingChanges.memberships.delete(key);
      }
    }
    for (const key of Array.from(this.pendingChanges.deletedMemberships)) {
      const [gatewayId, userId] = parseMembershipKey(key);
      const exists = this.state.gatewayMemberships.some(
        (membership) => membership.gatewayId === gatewayId && membership.userId === userId,
      );
      if (exists) {
        this.pendingChanges.deletedMemberships.delete(key);
      }
    }
    for (const key of Array.from(this.pendingChanges.approvals)) {
      const [gatewayId, userId, method] = parseApprovalKey(key);
      const exists = this.state.approvals.some(
        (approval) => approval.gatewayId === gatewayId && approval.userId === userId && approval.method === method,
      );
      if (!exists) {
        this.pendingChanges.approvals.delete(key);
      }
    }
    for (const key of Array.from(this.pendingChanges.deletedApprovals)) {
      const [gatewayId, userId, method] = parseApprovalKey(key);
      const exists = this.state.approvals.some(
        (approval) => approval.gatewayId === gatewayId && approval.userId === userId && approval.method === method,
      );
      if (exists) {
        this.pendingChanges.deletedApprovals.delete(key);
      }
    }
    for (const taskId of Array.from(this.pendingChanges.tasks)) {
      if (!this.state.tasks[taskId]) {
        this.pendingChanges.tasks.delete(taskId);
      }
    }
    for (const taskId of Array.from(this.pendingChanges.deletedTasks)) {
      if (this.state.tasks[taskId]) {
        this.pendingChanges.deletedTasks.delete(taskId);
      }
    }
  }
}
