import assert from "node:assert/strict";
import test from "node:test";
import {
  buildGatewaySummary,
  extractContextMetrics,
  extractHistoryContentBlocks,
  extractHistoryTextFromBlocks,
  hasToolContentBlocks,
  normalizeRealtimeChatPayload,
  normalizeHistoryMessageContent,
  normalizeSessionTimestamp,
  resolveDesktopChatReadiness,
  resolveDesktopChatReadinessFromLogs,
} from "./runtime-utils.js";

test("normalizeRealtimeChatPayload fills timestamps and message objects", () => {
  const normalized = normalizeRealtimeChatPayload({
    role: "assistant",
    text: "Hello",
    timestamp: "1700000000000",
  }) as Record<string, unknown>;

  assert.equal(normalized.ts, 1_700_000_000_000);
  assert.equal((normalized.message as Record<string, unknown>).timestamp, 1_700_000_000_000);
  assert.equal((normalized.message as Record<string, unknown>).role, "assistant");
});

test("extractContextMetrics prefers the explicit values", () => {
  assert.deepEqual(
    extractContextMetrics({
      contextUsage: 42,
      contextLimit: 128,
      usage: {
        promptTokens: 99,
        maxInputTokens: 256,
      },
    }),
    { contextUsage: 42, contextLimit: 128 },
  );
});

test("buildGatewaySummary combines gateway and runtime state", () => {
  const gateway = {
    id: "gw_1",
    displayName: "Gateway 1",
    platform: "macOS",
    gatewayCode: "gw-code",
    relaySecretHash: "secret",
    agentVersion: "1.0.0",
    status: "healthy",
    createdAt: "2024-01-01T00:00:00.000Z",
    updatedAt: "2024-01-01T00:00:00.000Z",
  } as Parameters<typeof buildGatewaySummary>[0];

  const summary = buildGatewaySummary(
    gateway,
    {
      gatewayId: "gw_1",
      relayStatus: "relay_connected",
      hostStatus: "healthy",
      openclawStatus: "healthy",
      aggregateStatus: "healthy",
      mobileControlStatus: "idle",
      currentModel: "gpt-4o",
      contextUsage: 512,
      contextLimit: 4096,
    },
  );

  assert.equal(summary.gatewayId, "gw_1");
  assert.equal(summary.currentModel, "gpt-4o");
  assert.equal(summary.contextUsage, 512);
});

test("resolveDesktopChatReadiness detects state from payload and logs", () => {
  assert.deepEqual(resolveDesktopChatReadiness([{ mode: "webchat", reason: "connect" }]), {
    ready: true,
    reason: "connect",
  });
  assert.deepEqual(
    resolveDesktopChatReadinessFromLogs({ lines: ['{"0":"ignored","2":"webchat connected"}'] }),
    {
      ready: true,
      reason: "webchat-log-connect",
    },
  );
});

test("history block helpers extract visible text and detect tool blocks", () => {
  const blocks = extractHistoryContentBlocks({
    content: [
      { type: "text", text: "Hello" },
      { type: "tool_use", text: "ignored" },
    ],
  });

  assert.equal(extractHistoryTextFromBlocks(blocks), "Hello");
  assert.equal(hasToolContentBlocks(blocks), true);
});

test("normalizeHistoryMessageContent strips synthetic command prompts", () => {
  const normalized = normalizeHistoryMessageContent(
    "user",
    "System: [foo]\n\n[2024-01-01 00:00] actual prompt",
  );
  assert.equal(normalized, "actual prompt");
});

test("normalizeSessionTimestamp accepts strings and dates", () => {
  assert.equal(normalizeSessionTimestamp("2024-01-01T00:00:00.000Z"), "2024-01-01T00:00:00.000Z");
  assert.equal(normalizeSessionTimestamp(new Date("2024-01-01T00:00:00.000Z")), "2024-01-01T00:00:00.000Z");
});
