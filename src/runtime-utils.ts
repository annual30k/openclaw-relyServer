import { nowIso } from "./security.js";
import type { GatewayRecord, GatewayRuntimeStateRecord } from "./types.js";

function toNonNegativeInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? Math.round(value) : undefined;
}

function normalizeEventTimestamp(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.round(value > 10_000_000_000 ? value : value * 1000);
  }
  if (typeof value === "string" && value.trim().length > 0) {
    const trimmed = value.trim();
    const numeric = Number(trimmed);
    if (Number.isFinite(numeric) && numeric > 0) {
      return Math.round(numeric > 10_000_000_000 ? numeric : numeric * 1000);
    }
    const parsed = Date.parse(trimmed);
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.round(parsed);
    }
  }
  return undefined;
}

export function normalizeSessionTimestamp(value: unknown): string | undefined {
  if (value instanceof Date && Number.isFinite(value.getTime())) {
    return value.toISOString();
  }
  if (typeof value === "string") {
    const trimmedValue = value.trim();
    if (!trimmedValue) return undefined;
    const parsed = Date.parse(trimmedValue);
    if (!Number.isNaN(parsed)) {
      return new Date(parsed).toISOString();
    }
    return undefined;
  }
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    const millis = value > 10_000_000_000 ? value : value * 1000;
    return new Date(millis).toISOString();
  }
  return undefined;
}

export function normalizeRealtimeChatPayload(rawPayload: unknown, fallbackTimestamp = Date.now()): unknown {
  if (!rawPayload || typeof rawPayload !== "object" || Array.isArray(rawPayload)) {
    return rawPayload;
  }

  const payload = { ...(rawPayload as Record<string, unknown>) };
  const existingMessageRecord =
    payload.message && typeof payload.message === "object" && !Array.isArray(payload.message)
      ? { ...(payload.message as Record<string, unknown>) }
      : undefined;
  const hasTopLevelMessageFields =
    typeof payload.role === "string"
    || typeof payload.text === "string"
    || typeof payload.content === "string"
    || Array.isArray(payload.content)
    || typeof payload.result === "string"
    || typeof payload.output === "string"
    || typeof payload.stopReason === "string"
    || typeof payload.errorMessage === "string";
  const messageRecord = existingMessageRecord ?? (hasTopLevelMessageFields ? {} : undefined);
  const resolvedTimestamp =
    normalizeEventTimestamp(payload.ts)
    ?? normalizeEventTimestamp(payload.timestamp)
    ?? normalizeEventTimestamp(payload.createdAt)
    ?? normalizeEventTimestamp(payload.created_at)
    ?? normalizeEventTimestamp(payload.time)
    ?? normalizeEventTimestamp(messageRecord?.timestamp)
    ?? fallbackTimestamp;

  payload.ts = resolvedTimestamp;

  if (messageRecord) {
    messageRecord.timestamp = normalizeEventTimestamp(messageRecord.timestamp) ?? resolvedTimestamp;
    if (
      (!messageRecord.role || typeof messageRecord.role !== "string" || !messageRecord.role.trim())
      && typeof payload.role === "string"
      && payload.role.trim()
    ) {
      messageRecord.role = payload.role.trim();
    }
    if (typeof payload.text === "string" && payload.text.trim()) {
      messageRecord.text = payload.text;
      if (!Array.isArray(messageRecord.content) && !messageRecord.content) {
        messageRecord.content = [{ type: "text", text: payload.text }];
      }
    }
    if (Array.isArray(payload.content) && !messageRecord.content) {
      messageRecord.content = payload.content;
    }
    payload.message = messageRecord;
  }

  return payload;
}

export function extractContextMetrics(
  payloadRecord: Record<string, unknown> | undefined,
): Pick<GatewayRuntimeStateRecord, "contextUsage" | "contextLimit"> {
  const usageRecord =
    payloadRecord?.usage && typeof payloadRecord.usage === "object" && !Array.isArray(payloadRecord.usage)
      ? (payloadRecord.usage as Record<string, unknown>)
      : undefined;

  const contextUsage =
    toNonNegativeInteger(payloadRecord?.contextUsage) ??
    toNonNegativeInteger(payloadRecord?.promptTokens) ??
    toNonNegativeInteger(payloadRecord?.prompt_tokens) ??
    toNonNegativeInteger(payloadRecord?.inputTokens) ??
    toNonNegativeInteger(payloadRecord?.input_tokens) ??
    toNonNegativeInteger(usageRecord?.promptTokens) ??
    toNonNegativeInteger(usageRecord?.prompt_tokens) ??
    toNonNegativeInteger(usageRecord?.inputTokens) ??
    toNonNegativeInteger(usageRecord?.input_tokens);
  const contextLimit =
    toNonNegativeInteger(payloadRecord?.contextLimit) ??
    toNonNegativeInteger(payloadRecord?.maxInputTokens) ??
    toNonNegativeInteger(payloadRecord?.max_input_tokens) ??
    toNonNegativeInteger(usageRecord?.contextLimit) ??
    toNonNegativeInteger(usageRecord?.maxInputTokens) ??
    toNonNegativeInteger(usageRecord?.max_input_tokens);

  return {
    contextUsage,
    contextLimit,
  };
}

export function buildGatewaySummary(gateway: GatewayRecord, runtime: GatewayRuntimeStateRecord) {
  const lastSeenAt =
    normalizeSessionTimestamp(gateway.lastSeenAt)
    ?? normalizeSessionTimestamp(gateway.createdAt)
    ?? nowIso();
  return {
    gatewayId: gateway.id,
    displayName: gateway.displayName,
    platform: gateway.platform,
    aggregateStatus: runtime.aggregateStatus,
    relayStatus: runtime.relayStatus,
    hostStatus: runtime.hostStatus,
    openclawStatus: runtime.openclawStatus,
    mobileControlStatus: runtime.mobileControlStatus,
    lastSeenAt,
    currentModel: runtime.currentModel ?? "--",
    contextUsage: runtime.contextUsage,
    contextLimit: runtime.contextLimit,
  };
}

export function resolveDesktopChatReadiness(payload: unknown): { ready: boolean; reason?: string } {
  const entries: unknown[] = Array.isArray(payload)
    ? payload
    : payload && typeof payload === "object" && !Array.isArray(payload) && Array.isArray((payload as Record<string, unknown>).presence)
      ? ((payload as Record<string, unknown>).presence as unknown[])
      : [];

  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    const mode = typeof record.mode === "string" ? record.mode.trim().toLowerCase() : "";
    const reason = typeof record.reason === "string" ? record.reason.trim().toLowerCase() : "";
    if (reason === "webchat-open") {
      return { ready: true, reason: "webchat-open" };
    }
    if (
      mode === "webchat" &&
      reason !== "disconnect" &&
      reason !== "webchat-closed"
    ) {
      return { ready: true, reason: reason || "webchat-connect" };
    }
  }

  return { ready: false };
}

function decodeGatewayLogLine(line: unknown): string {
  if (typeof line !== "string") {
    return "";
  }
  try {
    const parsed = JSON.parse(line) as Record<string, unknown>;
    const primary = typeof parsed["2"] === "string" ? parsed["2"] : "";
    if (primary) {
      return primary;
    }
    const fallback = typeof parsed["0"] === "string" ? parsed["0"] : "";
    return fallback;
  } catch {
    return line;
  }
}

export function resolveDesktopChatReadinessFromLogs(payload: unknown): { ready: boolean; reason?: string } {
  const lines =
    payload && typeof payload === "object" && !Array.isArray(payload) && Array.isArray((payload as Record<string, unknown>).lines)
      ? ((payload as Record<string, unknown>).lines as unknown[])
      : [];

  for (let index = lines.length - 1; index >= 0; index -= 1) {
    const message = decodeGatewayLogLine(lines[index]).trim().toLowerCase();
    if (!message) {
      continue;
    }
    if (message.includes("webchat connected")) {
      return { ready: true, reason: "webchat-log-connect" };
    }
    if (message.includes("webchat disconnected")) {
      return { ready: false, reason: "webchat-log-disconnect" };
    }
  }

  return { ready: false };
}

export function normalizeHistoryMessageContent(role: string, content: string): string {
  const trimmed = content.trim();
  if (!trimmed || role !== "user") {
    return trimmed;
  }

  const looksLikeSyntheticPrompt =
    /^System:\s*\[[^\]]+\]/.test(trimmed) && /\n\s*\n+\[[^\]]+\]\s*/.test(trimmed);
  if (!looksLikeSyntheticPrompt) {
    return trimmed;
  }

  const trailingBlock = trimmed
    .split(/\n\s*\n+/)
    .map((segment) => segment.trim())
    .filter(Boolean)
    .reverse()
    .find((segment) => !segment.startsWith("System:"));

  if (!trailingBlock) {
    return trimmed;
  }

  const normalized = trailingBlock.replace(/^\[[^\]]+\]\s*/, "").trim();
  return normalized || trimmed;
}

export function extractHistoryContentBlocks(record: Record<string, unknown>): Record<string, unknown>[] {
  if (!Array.isArray(record.content)) {
    return [];
  }

  return record.content.flatMap((block) => {
    if (!block || typeof block !== "object" || Array.isArray(block)) {
      return [];
    }
    return [block as Record<string, unknown>];
  });
}

export function extractHistoryTextFromBlocks(blocks: Record<string, unknown>[]): string {
  return blocks
    .filter((block) => {
      const type = typeof block.type === "string" ? block.type.trim().toLowerCase() : "";
      return type === "text" || type === "output_text" || type === "input_text";
    })
    .map((block) => (typeof block.text === "string" ? block.text : ""))
    .filter((text) => text.trim().length > 0)
    .join("\n\n")
    .trim();
}

export function hasToolContentBlocks(blocks: Record<string, unknown>[]): boolean {
  return blocks.some((block) => {
    const type = typeof block.type === "string" ? block.type.trim().toLowerCase() : "";
    return type === "toolcall"
      || type === "tool_call"
      || type === "tooluse"
      || type === "tool_use"
      || type === "toolresult"
      || type === "tool_result";
  });
}
