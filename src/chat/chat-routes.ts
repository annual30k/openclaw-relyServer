import type { IncomingMessage, ServerResponse } from "http";
import type { FileTransferStore } from "../files/file-transfer-store.js";
import { json } from "../http/common.js";
import {
  extractHistoryContentBlocks,
  extractHistoryTextFromBlocks,
  hasToolContentBlocks,
  normalizeHistoryMessageContent,
  normalizeSessionTimestamp,
  resolveDesktopChatReadiness,
  resolveDesktopChatReadinessFromLogs,
} from "../runtime-utils.js";
import type { GatewayMembershipRecord, GatewayRuntimeStateRecord } from "../types.js";

export interface MobileChatSessionItem {
  sessionKey: string;
  lastActivityAt?: string;
  displayName?: string;
  label?: string;
  derivedTitle?: string;
  kind?: string;
}

export interface ChatRouteHandlers {
  handleGatewayChatHistory: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
  ) => Promise<void>;
  handleGatewayChatReady: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ) => Promise<void>;
  handleGatewayChatSessions: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
  ) => Promise<void>;
  handleGatewayChatSessionDelete: (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
  ) => Promise<void>;
}

export interface ChatRouteOptions {
  fileStore: FileTransferStore;
  nowIso: () => string;
  schedulePersist: (delayMs?: number) => void;
  requireAuthenticatedUser: (req: IncomingMessage, res: ServerResponse) => string | null;
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  dispatchHostCommand: (gatewayIdValue: string, userId: string, method: string, params: unknown) => Promise<unknown>;
  touchGateway: (gatewayIdValue: string, patch: Partial<GatewayRuntimeStateRecord>) => void;
}

function toPayloadRecord(payload: unknown): Record<string, unknown> | undefined {
  return payload && typeof payload === "object" && !Array.isArray(payload)
    ? (payload as Record<string, unknown>)
    : undefined;
}

export function buildMobileChatSessionItems(payload: unknown): MobileChatSessionItem[] {
  const payloadRecord = toPayloadRecord(payload);
  const rawItems =
    Array.isArray(payloadRecord?.sessions) ? payloadRecord.sessions
      : Array.isArray(payloadRecord?.items) ? payloadRecord.items
        : Array.isArray(payloadRecord?.list) ? payloadRecord.list
          : Array.isArray(payload) ? payload as unknown[]
            : [];

  const deduped = new Set<string>();
  const items: MobileChatSessionItem[] = [];
  for (const entry of rawItems) {
    if (typeof entry === "string") {
      const sessionKey = entry.trim();
      if (!sessionKey || deduped.has(sessionKey)) continue;
      deduped.add(sessionKey);
      items.push({ sessionKey });
      continue;
    }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    const sessionKeyRaw =
      typeof record.key === "string" ? record.key
        : typeof record.sessionKey === "string" ? record.sessionKey
          : typeof record.id === "string" ? record.id
            : typeof record.session === "string" ? record.session
              : undefined;
    const sessionKey = sessionKeyRaw?.trim();
    if (!sessionKey || deduped.has(sessionKey)) continue;
    deduped.add(sessionKey);
    const lastActivityAt =
      normalizeSessionTimestamp(record.updatedAt)
      ?? normalizeSessionTimestamp(record.lastActivityAt)
      ?? normalizeSessionTimestamp(record.lastMessageAt)
      ?? normalizeSessionTimestamp(record.lastSeenAt)
      ?? normalizeSessionTimestamp(record.createdAt);
    const displayName = typeof record.displayName === "string" ? record.displayName.trim() : undefined;
    const label = typeof record.label === "string" ? record.label.trim() : undefined;
    const derivedTitle = typeof record.derivedTitle === "string" ? record.derivedTitle.trim() : undefined;
    const kind = typeof record.kind === "string" ? record.kind.trim() : undefined;
    items.push({
      sessionKey,
      lastActivityAt,
      displayName: displayName || undefined,
      label: label || undefined,
      derivedTitle: derivedTitle || undefined,
      kind: kind || undefined,
    });
  }

  items.sort((a, b) => {
    const aTime = a.lastActivityAt ? Date.parse(a.lastActivityAt) : 0;
    const bTime = b.lastActivityAt ? Date.parse(b.lastActivityAt) : 0;
    return bTime - aTime;
  });

  return items;
}

export function createChatRouteHandlers(options: ChatRouteOptions): ChatRouteHandlers {
  const markGatewayHealthy = (gatewayIdValue: string): void => {
    options.touchGateway(gatewayIdValue, {
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      lastSeenAt: options.nowIso(),
    });
    options.schedulePersist();
  };

  const handleGatewayChatHistory = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    const sessionKey = requestUrl.searchParams.get("sessionKey")?.trim() || "main";
    const requestedLimit = Number.parseInt(requestUrl.searchParams.get("limit") ?? "100", 10);
    const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 200)) : 100;

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "chat.history", {
        sessionKey,
        limit,
      });
      markGatewayHealthy(gatewayIdValue);
      const result = (payload ?? {}) as { messages?: unknown[] };
      const chatItems = Array.isArray(result.messages)
        ? result.messages.flatMap((entry, index) => {
            if (!entry || typeof entry !== "object" || Array.isArray(entry)) return [];
            const record = entry as Record<string, unknown>;
            const rawRole = typeof record.role === "string" ? record.role : "assistant";
            const createdAt =
              normalizeSessionTimestamp(record.createdAt)
              ?? normalizeSessionTimestamp(record.created_at)
              ?? normalizeSessionTimestamp(record.timestamp)
              ?? normalizeSessionTimestamp(record.ts)
              ?? normalizeSessionTimestamp(record.time);
            const contentBlocks = extractHistoryContentBlocks(record);
            const contentText = extractHistoryTextFromBlocks(contentBlocks);
            const role = hasToolContentBlocks(contentBlocks) ? "tool" : rawRole;
            const normalizedContent = normalizeHistoryMessageContent(role, contentText);
            if (!normalizedContent && contentBlocks.length === 0) return [];
            return [{
              id: typeof record.id === "string" && record.id.trim() ? record.id.trim() : `history-${index}`,
              role,
              content: normalizedContent,
              contentBlocks,
              createdAt,
            }];
          })
        : [];
      const fileItems = await options.fileStore.listFiles(gatewayIdValue, sessionKey, userId);
      const mergedItems = [
        ...chatItems,
        ...fileItems.map((record) => options.fileStore.toChatHistoryItem(record)),
      ].sort((left, right) => {
        const leftTimestamp = normalizeSessionTimestamp(left.createdAt) ? Date.parse(normalizeSessionTimestamp(left.createdAt)!) : 0;
        const rightTimestamp = normalizeSessionTimestamp(right.createdAt) ? Date.parse(normalizeSessionTimestamp(right.createdAt)!) : 0;
        return leftTimestamp - rightTimestamp;
      });
      json(res, 200, { items: mergedItems });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleGatewayChatReady = async (
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
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "system-presence", {});
      let readiness = resolveDesktopChatReadiness(payload);
      if (!readiness.ready) {
        const logsPayload = await options.dispatchHostCommand(gatewayIdValue, userId, "logs.tail", {
          limit: 200,
          maxBytes: 200_000,
        });
        readiness = resolveDesktopChatReadinessFromLogs(logsPayload);
      }
      markGatewayHealthy(gatewayIdValue);
      json(res, 200, readiness);
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleGatewayChatSessions = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
  ): Promise<void> => {
    const userId = options.requireAuthenticatedUser(req, res);
    if (!userId) return;
    const membership = options.getMembership(gatewayIdValue, userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }

    const requestedLimit = Number.parseInt(requestUrl.searchParams.get("limit") ?? "120", 10);
    const limit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(requestedLimit, 120)) : 120;
    const requestedActiveMinutes = Number.parseInt(requestUrl.searchParams.get("activeMinutes") ?? "", 10);
    const activeMinutes = Number.isFinite(requestedActiveMinutes) ? Math.max(1, requestedActiveMinutes) : undefined;
    const includeGlobal = requestUrl.searchParams.get("includeGlobal") !== "false";
    const includeUnknown = requestUrl.searchParams.get("includeUnknown") === "true";

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "sessions.list", {
        limit,
        ...(activeMinutes !== undefined ? { activeMinutes } : {}),
        includeGlobal,
        includeUnknown,
      });
      markGatewayHealthy(gatewayIdValue);
      json(res, 200, { items: buildMobileChatSessionItems(payload) });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleGatewayChatSessionDelete = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
    requestUrl: URL,
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

    const sessionKey = requestUrl.searchParams.get("sessionKey")?.trim();
    if (!sessionKey) {
      json(res, 400, { error: "session_key_required" });
      return;
    }
    const deleteTranscript = requestUrl.searchParams.get("deleteTranscript") !== "false";

    try {
      const payload = await options.dispatchHostCommand(gatewayIdValue, userId, "sessions.delete", {
        key: sessionKey,
        deleteTranscript,
      });
      markGatewayHealthy(gatewayIdValue);
      const payloadRecord = toPayloadRecord(payload);
      const deleted = payloadRecord?.deleted === true;
      json(res, 200, { ok: true, deleted });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  return {
    handleGatewayChatHistory,
    handleGatewayChatReady,
    handleGatewayChatSessions,
    handleGatewayChatSessionDelete,
  };
}
