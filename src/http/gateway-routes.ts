import type { IncomingMessage, ServerResponse } from "http";
import { randomUUID } from "crypto";
import { requiresApproval } from "../risk.js";
import type { RelayStore } from "../store.js";
import { hostCommandErrorResponse, json, parseStringRecord, readJson } from "./common.js";
import type {
  GatewayMembershipRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  RelayEnvelope,
} from "../types.js";

type HostSkillStatusEntry = {
  skillKey?: string;
  blockedByAllowlist?: boolean;
};

type HostSkillsStatusReport = {
  skills?: HostSkillStatusEntry[];
};

type HostBackupRecord = {
  id?: string;
  title?: string;
  detail?: string;
  filename?: string;
  sizeBytes?: number;
  createdAt?: string;
  updatedAt?: string;
};

type HostBackupListReport = {
  backups?: HostBackupRecord[];
  maxBackups?: number;
};

type HostBackupMutationReport = HostBackupListReport & {
  backup?: HostBackupRecord;
};

export interface GatewayRouteHandlers {
  handleGatewayList: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleGatewayDetail: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayDelete: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayUpdate: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayModels: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewaySkills: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayBackups: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleGatewayBackup: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    backupIdValue: string,
  ) => Promise<void>;
  handleGatewayBackupRestore: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    backupIdValue: string,
  ) => Promise<void>;
  handleGatewaySkillUpdate: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    skillKeyValue: string,
  ) => Promise<void>;
  handleGatewayDefaultModelSelect: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ) => Promise<void>;
  handleGatewayModelSelect: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ) => Promise<void>;
  handleApproveSensitiveAction: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ) => Promise<void>;
}

export interface GatewayRouteOptions {
  store: RelayStore;
  approvalTtlSeconds: number;
  nowIso: () => string;
  addSeconds: (date: Date, seconds: number) => string;
  persist: () => Promise<void>;
  schedulePersist: (delayMs?: number) => void;
  requireAuthenticatedUser: (req: IncomingMessage, res: ServerResponse) => string | null;
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  normalizeGatewayRuntime: (gatewayIdValue: string) => GatewayRuntimeStateRecord;
  buildGatewaySummary: (gateway: GatewayRecord) => Record<string, unknown>;
  dispatchHostCommand: (gatewayIdValue: string, userId: string, method: string, params: unknown) => Promise<unknown>;
  touchGateway: (gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>) => void;
  broadcastToGatewayMembers: (gatewayIdValue: string, envelope: RelayEnvelope) => void;
}

export function resolveModelSelectionSessionKey(rawSessionKey: unknown): string {
  if (typeof rawSessionKey !== "string") {
    return "main";
  }
  const trimmed = rawSessionKey.trim();
  return trimmed.length > 0 ? trimmed : "main";
}

export function createGatewayRouteHandlers(options: GatewayRouteOptions): GatewayRouteHandlers {
  const markGatewayHealthy = (gatewayIdValue: string): void => {
    options.touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();
  };

  const handleGatewayList = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const snapshot = options.store.snapshot();
    const gateways = snapshot.gatewayMemberships
      .filter((membership) => membership.userId === userId)
      .map((membership) => {
        const gateway = snapshot.gateways[membership.gatewayId];
        return gateway ? { ...options.buildGatewaySummary(gateway), role: membership.role } : null;
      })
      .filter(Boolean);
    json(res, 200, { gateways });
  };

  const handleGatewayDetail = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    const gateway = options.store.snapshot().gateways[gatewayIdValue];
    if (!membership || !gateway) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    json(res, 200, {
      gateway: {
        ...options.buildGatewaySummary(gateway),
        role: membership.role,
        runtime: options.normalizeGatewayRuntime(gatewayIdValue),
      },
    });
  };

  const handleGatewayDelete = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    const gateway = options.store.snapshot().gateways[gatewayIdValue];
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    options.store.removeMembership(gatewayIdValue, userId);
    if (gateway) {
      const nextOwner = options.store.snapshot().gatewayMemberships.find(
        (candidate) => candidate.gatewayId === gatewayIdValue && candidate.role === "owner",
      );
      gateway.ownerUserId = nextOwner?.userId;
      gateway.updatedAt = options.nowIso();
      options.store.putGateway(gateway);
    }
    const runtime = options.normalizeGatewayRuntime(gatewayIdValue);
    if (runtime.controllerUserId === userId) {
      runtime.controllerUserId = undefined;
      runtime.controllerDeviceId = undefined;
      runtime.mobileControlStatus = "idle";
      options.store.putRuntimeState(runtime);
    }
    await options.persist();
    json(res, 200, { ok: true });
  };

  const handleGatewayUpdate = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    const gateway = options.store.snapshot().gateways[gatewayIdValue];
    if (!membership || !gateway) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    const displayName = typeof body.displayName === "string" ? body.displayName.trim() : "";
    if (!displayName) {
      json(res, 400, { error: "display_name_required" });
      return;
    }
    if (displayName.length > 191) {
      json(res, 400, { error: "display_name_too_long" });
      return;
    }

    gateway.displayName = displayName;
    gateway.updatedAt = options.nowIso();
    options.store.putGateway(gateway);

    await options.persist();

    options.broadcastToGatewayMembers(gatewayIdValue, {
      type: "presence",
      gatewayId: gatewayIdValue,
      payload: options.buildGatewaySummary(gateway),
    });

    json(res, 200, {
      gateway: {
        ...options.buildGatewaySummary(gateway),
        role: membership.role,
      },
    });
  };

  const handleGatewayModels = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "pocketclaw.model.list", {});
      markGatewayHealthy(gatewayIdValue);
      const result = (payload ?? {}) as { items?: unknown[] };
      const runtime = options.normalizeGatewayRuntime(gatewayIdValue);
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
  };

  const handleGatewaySkills = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "skills.status", {});
      markGatewayHealthy(gatewayIdValue);
      json(res, 200, payload ?? { skills: [] });
    } catch (error) {
      const response = hostCommandErrorResponse(error);
      json(res, response.status, response.body);
    }
  };

  const handleGatewayBackups = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    if (req.method === "GET") {
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "clawpilot.backup.list", {});
        markGatewayHealthy(gatewayIdValue);
        const result = (payload ?? {}) as HostBackupListReport;
        json(res, 200, {
          backups: Array.isArray(result.backups) ? result.backups : [],
          maxBackups: typeof result.maxBackups === "number" ? result.maxBackups : 5,
        });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    const body = (await readJson<Record<string, unknown>>(req)) ?? {};

    if (req.method === "POST") {
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "clawpilot.backup.create", {
          title: body.title,
          detail: body.detail,
          filename: body.filename,
        });
        markGatewayHealthy(gatewayIdValue);
        const result = (payload ?? {}) as HostBackupMutationReport;
        json(res, 200, {
          backup: result.backup,
          backups: Array.isArray(result.backups) ? result.backups : [],
          maxBackups: typeof result.maxBackups === "number" ? result.maxBackups : 5,
        });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    json(res, 405, { error: "method_not_allowed" });
  };

  const handleGatewayBackup = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    backupIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    if (req.method === "PATCH") {
      const body = (await readJson<Record<string, unknown>>(req)) ?? {};
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "clawpilot.backup.update", {
          backupId: backupIdValue,
          title: body.title,
          detail: body.detail,
          filename: body.filename,
        });
        markGatewayHealthy(gatewayIdValue);
        const result = (payload ?? {}) as HostBackupMutationReport;
        json(res, 200, {
          backup: result.backup,
          backups: Array.isArray(result.backups) ? result.backups : [],
          maxBackups: typeof result.maxBackups === "number" ? result.maxBackups : 5,
        });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    if (req.method === "DELETE") {
      try {
        const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "clawpilot.backup.delete", {
          backupId: backupIdValue,
        });
        markGatewayHealthy(gatewayIdValue);
        const result = (payload ?? {}) as HostBackupMutationReport;
        json(res, 200, {
          backup: result.backup,
          backups: Array.isArray(result.backups) ? result.backups : [],
          maxBackups: typeof result.maxBackups === "number" ? result.maxBackups : 5,
        });
      } catch (error) {
        const response = hostCommandErrorResponse(error);
        json(res, response.status, response.body);
      }
      return;
    }

    json(res, 405, { error: "method_not_allowed" });
  };

  const handleGatewayBackupRestore = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    backupIdValue: string,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }
    if (req.method !== "POST") {
      json(res, 405, { error: "method_not_allowed" });
      return;
    }

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "clawpilot.backup.restore", {
        backupId: backupIdValue,
      });
      markGatewayHealthy(gatewayIdValue);
      const result = (payload ?? {}) as HostBackupMutationReport;
      json(res, 200, {
        backup: result.backup,
        backups: Array.isArray(result.backups) ? result.backups : [],
        maxBackups: typeof result.maxBackups === "number" ? result.maxBackups : 5,
      });
    } catch (error) {
      const response = hostCommandErrorResponse(error);
      json(res, response.status, response.body);
    }
  };

  const handleGatewaySkillUpdate = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    skillKeyValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    if (membership.role === "viewer") {
      json(res, 403, { error: "forbidden" });
      return;
    }

    const skillKeyRaw = skillKeyValue.trim();
    if (!skillKeyRaw) {
      json(res, 400, { error: "skill_key_required" });
      return;
    }

    const enabledProvided = typeof body.enabled === "boolean";
    if (body.enabled !== undefined && !enabledProvided) {
      json(res, 400, { error: "enabled_invalid" });
      return;
    }

    const apiKeyProvided = body.apiKey !== undefined;
    if (apiKeyProvided && typeof body.apiKey !== "string") {
      json(res, 400, { error: "api_key_invalid" });
      return;
    }

    const envProvided = body.env !== undefined;
    const env = parseStringRecord(body.env);
    if (envProvided && (body.env === null || env === undefined)) {
      json(res, 400, { error: "env_invalid" });
      return;
    }

    const hasEnvEntries = env !== undefined && Object.keys(env).length > 0;

    if (!enabledProvided && !apiKeyProvided && !hasEnvEntries) {
      json(res, 400, { error: "update_payload_required" });
      return;
    }

    try {
      const report = await options.dispatchHostCommand(gatewayIdValue, userId, "skills.status", {});
      const statusReport = report as HostSkillsStatusReport | null | undefined;
      const currentSkill = statusReport?.skills?.find((skill) => skill && skill.skillKey === skillKeyRaw);
      if (!currentSkill) {
        json(res, 404, { error: "skill_not_found" });
        return;
      }
      if (body.enabled === true && currentSkill.blockedByAllowlist) {
        json(res, 403, { error: "skill_blocked" });
        return;
      }

      const updateParams: Record<string, unknown> = { skillKey: skillKeyRaw };
      if (enabledProvided) updateParams.enabled = body.enabled;
      if (apiKeyProvided) updateParams.apiKey = body.apiKey;
      if (envProvided && env !== undefined) updateParams.env = env;

      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "skills.update", updateParams);
      markGatewayHealthy(gatewayIdValue);
      json(res, 200, payload ?? { ok: true });
    } catch (error) {
      const response = hostCommandErrorResponse(error);
      json(res, response.status, response.body);
    }
  };

  const handleGatewayDefaultModelSelect = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
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
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "pocketclaw.model.setDefault", {
        providerId,
        modelId,
        modelAlias,
      });
      const gateway = options.store.snapshot().gateways[gatewayIdValue];
      if (gateway) {
        options.broadcastToGatewayMembers(gatewayIdValue, {
          type: "presence",
          gatewayId: gatewayIdValue,
          payload: options.buildGatewaySummary(gateway),
        });
      }
      options.broadcastToGatewayMembers(gatewayIdValue, {
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
  };

  const handleGatewayModelSelect = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
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
    const modelAliasRaw = typeof body.modelAlias === "string" ? body.modelAlias.trim() : "";
    const modelName = typeof body.modelName === "string" ? body.modelName.trim() : "";
    const modelAlias = modelAliasRaw || modelName || modelId;
    const sessionKey = resolveModelSelectionSessionKey(body.sessionKey);
    if (!providerId || !modelId || !modelAlias) {
      json(res, 400, { error: "providerId_modelId_and_modelName_required" });
      return;
    }

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "chat.send", {
        sessionKey,
        message: `/model ${modelAlias}`,
        idempotencyKey: randomUUID(),
      });
      options.touchGateway(gatewayIdValue, {
        currentModel: modelAlias,
        lastSeenAt: options.nowIso(),
      });
      options.schedulePersist();

      const gateway = options.store.snapshot().gateways[gatewayIdValue];
      if (gateway) {
        options.broadcastToGatewayMembers(gatewayIdValue, {
          type: "presence",
          gatewayId: gatewayIdValue,
          payload: options.buildGatewaySummary(gateway),
        });
      }
      options.broadcastToGatewayMembers(gatewayIdValue, {
        type: "event",
        gatewayId: gatewayIdValue,
        event: "model_selected",
        payload: {
          providerId,
          modelId,
          modelAlias,
          modelName,
          sessionKey,
          currentModel: modelAlias,
        },
      });

      json(res, 200, { ok: true, payload });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleApproveSensitiveAction = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
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
        : options.approvalTtlSeconds;
    options.store.addApproval({
      gatewayId: gatewayIdValue,
      userId,
      method,
      createdAt: options.nowIso(),
      expiresAt: options.addSeconds(new Date(), ttlSeconds),
    });
    await options.persist();
    json(res, 200, {
      ok: true,
      gatewayId: gatewayIdValue,
      method,
      expiresAt: options.addSeconds(new Date(), ttlSeconds),
    });
  };

  return {
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
  };
}
