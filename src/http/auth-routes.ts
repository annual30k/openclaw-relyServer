import type { IncomingMessage, ServerResponse } from "http";
import { randomUUID } from "crypto";
import { json, readJson } from "./common.js";
import type { RelayStore } from "../store.js";
import type {
  GatewayMembershipRecord,
  GatewayPairingCodeRecord,
  GatewayRecord,
  GatewayRuntimeStateRecord,
  MobileDeviceRecord,
  Role,
  UserRecord,
} from "../types.js";
import type { TokenClaims } from "../ws/runtime-types.js";

export interface AuthRouteHandlers {
  handleRegister: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleAccessCode: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleAuthRegister: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleAuthLogin: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleAuthDeleteAccount: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
  handleMobilePair: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}

interface AuthRouteOptions {
  config: {
    accessCodeTtlSeconds: number;
    authTokenTtlSeconds: number;
  };
  store: RelayStore;
  nowIso: () => string;
  addSeconds: (date: Date, seconds: number) => string;
  gatewayId: () => string;
  gatewayCode: () => string;
  randomSecret: () => string;
  randomCode: () => string;
  sha256: (value: string) => string;
  hashPassword: (password: string) => string;
  verifyPassword: (password: string, encoded: string) => boolean;
  makeAccessToken: (user: UserRecord, deviceId: string, platform: string, appVersion: string) => string;
  touchGateway: (gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>) => void;
  persist: () => Promise<void>;
  schedulePersist: (delayMs?: number) => void;
  requireAuthenticatedUser: (req: IncomingMessage, res: ServerResponse) => string | null;
  requireAuthenticatedClaims: (req: IncomingMessage, res: ServerResponse) => TokenClaims | null;
  findUserByEmail: (email: string) => UserRecord | undefined;
  membershipsForUser: (userId: string) => GatewayMembershipRecord[];
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  deleteGatewayChatDataForAccount: (gatewayIdValue: string, userId: string) => Promise<string[]>;
  clearPendingStateForUser: (userId: string) => void;
  disconnectMobileSessionsForUser: (userId: string, reason?: string) => void;
  deleteFilesForGateway: (gatewayIdValue: string) => Promise<number>;
  buildGatewaySummary: (gateway: GatewayRecord) => unknown;
}

export function createAuthRouteHandlers(options: AuthRouteOptions): AuthRouteHandlers {
  const issueAccessCode = (): string => {
    const snapshot = options.store.snapshot();
    const now = options.nowIso();
    for (let attempts = 0; attempts < 20; attempts += 1) {
      const accessCode = options.randomCode();
      const accessCodeHash = options.sha256(accessCode);
      const isDuplicate = Object.values(snapshot.gatewayPairingCodes).some(
        (record) => !record.usedAt && record.expiresAt > now && record.accessCodeHash === accessCodeHash,
      );
      if (!isDuplicate) {
        return accessCode;
      }
    }
    throw new Error("failed_to_issue_unique_access_code");
  };

  const findPairingCodeByAccessCode = (
    accessCode: string,
  ): { gateway: GatewayRecord; pairingCode: GatewayPairingCodeRecord } | null => {
    const accessCodeHash = options.sha256(accessCode);
    const snapshot = options.store.snapshot();
    for (const pairingCode of Object.values(snapshot.gatewayPairingCodes)) {
      if (pairingCode.accessCodeHash !== accessCodeHash) {
        continue;
      }
      const gateway = snapshot.gateways[pairingCode.gatewayId];
      if (!gateway) {
        continue;
      }
      return { gateway, pairingCode };
    }
    return null;
  };

  const handleRegister = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const displayName =
      typeof body.displayName === "string" && body.displayName.trim() ? body.displayName.trim() : "PocketClaw Host";
    const platform = typeof body.platform === "string" && body.platform.trim() ? body.platform.trim() : "unknown";
    const agentVersion =
      typeof body.agentVersion === "string" && body.agentVersion.trim() ? body.agentVersion.trim() : "unknown";

    const id = options.gatewayId();
    const relaySecret = options.randomSecret();
    const now = options.nowIso();
    const gateway: GatewayRecord = {
      id,
      gatewayCode: options.gatewayCode(),
      relaySecretHash: options.sha256(relaySecret),
      displayName,
      platform,
      agentVersion,
      status: "offline",
      createdAt: now,
      updatedAt: now,
    };

    options.store.putGateway(gateway);
    options.touchGateway(id, {
      relayStatus: "offline",
      hostStatus: "offline",
      openclawStatus: "offline",
      aggregateStatus: "offline",
      mobileControlStatus: "idle",
    });

    const accessCode = issueAccessCode();
    options.store.putPairingCode({
      gatewayId: id,
      accessCodeHash: options.sha256(accessCode),
      expiresAt: options.addSeconds(new Date(), options.config.accessCodeTtlSeconds),
      createdAt: now,
    });

    await options.persist();
    json(res, 200, {
      gatewayId: id,
      relaySecret,
      accessCode,
      expiresAt: options.store.snapshot().gatewayPairingCodes[id]?.expiresAt,
    });
  };

  const handleAccessCode = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const gatewayIdValue = typeof body.gatewayId === "string" ? body.gatewayId : "";
    const relaySecret = typeof body.relaySecret === "string" ? body.relaySecret : "";
    const gateway = options.store.snapshot().gateways[gatewayIdValue];

    if (!gateway || options.sha256(relaySecret) !== gateway.relaySecretHash) {
      json(res, 401, { error: "invalid_gateway_credentials" });
      return;
    }

    const accessCode = issueAccessCode();
    const expiresAt = options.addSeconds(new Date(), options.config.accessCodeTtlSeconds);
    options.store.putPairingCode({
      gatewayId: gatewayIdValue,
      accessCodeHash: options.sha256(accessCode),
      expiresAt,
      createdAt: options.nowIso(),
    });
    await options.persist();
    json(res, 200, { gatewayId: gatewayIdValue, accessCode, expiresAt });
  };

  const handleAuthRegister = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const name = typeof body.name === "string" && body.name.trim() ? body.name.trim() : email;
    const deviceId =
      typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
    const platform = typeof body.platform === "string" ? body.platform : "ios";
    const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";

    if (!email || !email.includes("@")) {
      json(res, 400, { error: "valid_email_required" });
      return;
    }
    if (password.length < 8) {
      json(res, 400, { error: "password_too_short" });
      return;
    }
    if (options.findUserByEmail(email)) {
      json(res, 409, { error: "email_already_registered" });
      return;
    }

    const user: UserRecord = {
      id: `user_${randomUUID().replace(/-/g, "").slice(0, 12)}`,
      email,
      passwordHash: options.hashPassword(password),
      name,
      createdAt: options.nowIso(),
    };
    options.store.putUser(user);
    options.store.putMobileDevice({
      id: deviceId,
      userId: user.id,
      platform,
      appVersion,
      createdAt: options.nowIso(),
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();

    json(res, 200, {
      accessToken: options.makeAccessToken(user, deviceId, platform, appVersion),
      user: { id: user.id, email: user.email, name: user.name },
      deviceId,
    });
  };

  const handleAuthLogin = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const email = typeof body.email === "string" ? body.email.trim().toLowerCase() : "";
    const password = typeof body.password === "string" ? body.password : "";
    const deviceId =
      typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
    const platform = typeof body.platform === "string" ? body.platform : "ios";
    const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";
    const user = options.findUserByEmail(email);

    if (!user) {
      json(res, 404, { error: "user_not_registered" });
      return;
    }

    if (!options.verifyPassword(password, user.passwordHash)) {
      json(res, 401, { error: "invalid_credentials" });
      return;
    }

    options.store.putMobileDevice({
      id: deviceId,
      userId: user.id,
      platform,
      appVersion,
      createdAt: options.nowIso(),
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();

    json(res, 200, {
      accessToken: options.makeAccessToken(user, deviceId, platform, appVersion),
      user: { id: user.id, email: user.email, name: user.name },
      deviceId,
    });
  };

  const handleAuthDeleteAccount = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const claims = options.requireAuthenticatedClaims(req, res);
    if (!claims) {
      return;
    }

    const memberships = options.membershipsForUser(claims.userId);
    const cleanupWarnings: Array<{ gatewayId: string; step: string; error: string }> = [];

    for (const membership of memberships) {
      const chatWarnings = await options.deleteGatewayChatDataForAccount(membership.gatewayId, claims.userId);
      for (const warning of chatWarnings) {
        cleanupWarnings.push({
          gatewayId: membership.gatewayId,
          step: "chat",
          error: warning,
        });
      }

      try {
        await options.deleteFilesForGateway(membership.gatewayId);
      } catch (error) {
        cleanupWarnings.push({
          gatewayId: membership.gatewayId,
          step: "files",
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    try {
      options.clearPendingStateForUser(claims.userId);
      options.disconnectMobileSessionsForUser(claims.userId);
      await options.store.deleteUserAccount(claims.userId);

      if (cleanupWarnings.length > 0) {
        console.warn(
          `[auth.delete-account] completed with cleanup warnings user=${claims.userId} warnings=${cleanupWarnings.length}`,
        );
      }
      json(res, 200, { ok: true, cleanupWarnings });
    } catch (error) {
      console.error(`[auth.delete-account] failed user=${claims.userId}`, error);
      json(res, 500, { error: "internal_error" });
    }
  };

  const handleMobilePair = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const gatewayIdValue = typeof body.gatewayId === "string" ? body.gatewayId : "";
    const accessCode = typeof body.accessCode === "string" ? body.accessCode : "";
    const deviceId =
      typeof body.deviceId === "string" && body.deviceId.trim() ? body.deviceId.trim() : `ios_${randomUUID().slice(0, 8)}`;
    const platform = typeof body.platform === "string" ? body.platform : "ios";
    const appVersion = typeof body.appVersion === "string" ? body.appVersion : "unknown";

    let resolvedGatewayId = gatewayIdValue.trim();
    let gateway = resolvedGatewayId ? options.store.snapshot().gateways[resolvedGatewayId] : undefined;
    let pairingCode = resolvedGatewayId ? options.store.snapshot().gatewayPairingCodes[resolvedGatewayId] : undefined;

    if (!accessCode.trim()) {
      json(res, 400, { error: "pairing_code_required" });
      return;
    }

    if (!resolvedGatewayId) {
      const resolved = findPairingCodeByAccessCode(accessCode);
      if (!resolved) {
        json(res, 404, { error: "pairing_code_not_found" });
        return;
      }
      resolvedGatewayId = resolved.gateway.id;
      gateway = resolved.gateway;
      pairingCode = resolved.pairingCode;
    }

    if (!gateway || !pairingCode) {
      json(res, 404, { error: "pairing_code_not_found" });
      return;
    }
    if (pairingCode.expiresAt <= options.nowIso()) {
      json(res, 410, { error: "pairing_code_expired" });
      return;
    }
    if (options.sha256(accessCode) !== pairingCode.accessCodeHash) {
      json(res, 401, { error: "pairing_code_invalid" });
      return;
    }

    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) {
      return;
    }
    const user = options.store.snapshot().users[userId];
    if (!user) {
      json(res, 401, { error: "unknown_user" });
      return;
    }

    const existingMembership = options.getMembership(resolvedGatewayId, userId);
    const existingOwner = options.store.snapshot().gatewayMemberships.find(
      (membership) => membership.gatewayId === resolvedGatewayId && membership.role === "owner",
    );
    let role: Role;
    if (existingMembership) {
      role = existingMembership.role;
    } else if (!existingOwner) {
      role = "owner";
    } else {
      json(res, 403, { error: "gateway_already_bound_to_another_account" });
      return;
    }

    if (!gateway.ownerUserId) {
      gateway.ownerUserId = userId;
      gateway.updatedAt = options.nowIso();
      options.store.putGateway(gateway);
    }

    if (!existingMembership) {
      options.store.putMembership({
        gatewayId: resolvedGatewayId,
        userId,
        role,
        createdAt: options.nowIso(),
      });
    }

    const device: MobileDeviceRecord = {
      id: deviceId,
      userId,
      platform,
      appVersion,
      createdAt: options.nowIso(),
      lastSeenAt: options.nowIso(),
    };
    options.store.putMobileDevice(device);

    pairingCode.usedAt = options.nowIso();
    options.store.putPairingCode(pairingCode);

    const accessToken = options.makeAccessToken(user, deviceId, platform, appVersion);

    options.schedulePersist();
    json(res, 200, {
      accessToken,
      userId,
      deviceId,
      role,
      gateway: options.buildGatewaySummary(gateway),
    });
  };

  return {
    handleRegister,
    handleAccessCode,
    handleAuthRegister,
    handleAuthLogin,
    handleAuthDeleteAccount,
    handleMobilePair,
  };
}
