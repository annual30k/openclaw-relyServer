import test from "node:test";
import assert from "node:assert/strict";
import { buildMobileChatSessionItems } from "./chat-routes.js";

test("buildMobileChatSessionItems dedupes entries and sorts by last activity", () => {
  const items = buildMobileChatSessionItems({
    sessions: [
      { key: "older", updatedAt: "2026-03-30T00:00:00Z", displayName: " Older " },
      "main",
      { sessionKey: "newer", lastMessageAt: "2026-03-31T12:00:00Z", label: " Latest " },
      { id: "older", createdAt: "2026-03-29T00:00:00Z" },
      { session: "other", kind: " assistant " },
    ],
  });

  assert.deepEqual(items, [
    {
      sessionKey: "newer",
      lastActivityAt: "2026-03-31T12:00:00.000Z",
      displayName: undefined,
      label: "Latest",
      derivedTitle: undefined,
      kind: undefined,
    },
    {
      sessionKey: "older",
      lastActivityAt: "2026-03-30T00:00:00.000Z",
      displayName: "Older",
      label: undefined,
      derivedTitle: undefined,
      kind: undefined,
    },
    { sessionKey: "main" },
    {
      sessionKey: "other",
      lastActivityAt: undefined,
      displayName: undefined,
      label: undefined,
      derivedTitle: undefined,
      kind: "assistant",
    },
  ]);
});
