import assert from "node:assert/strict";
import test from "node:test";
import { extractSessionKeysFromPayload, isIgnorableSessionDeleteError } from "./session-utils.js";

test("extractSessionKeysFromPayload normalizes common payload shapes", () => {
  assert.deepEqual(
    extractSessionKeysFromPayload({
      sessions: [
        " main ",
        { key: "chat-1" },
        { sessionKey: "chat-2" },
        { id: "chat-3" },
        { session: "chat-4" },
        { key: "chat-1" },
        null,
      ],
    }),
    ["main", "chat-1", "chat-2", "chat-3", "chat-4"],
  );

  assert.deepEqual(extractSessionKeysFromPayload(["task-a", { key: "task-b" }]), ["main", "task-a", "task-b"]);
});

test("isIgnorableSessionDeleteError matches known cleanup failures", () => {
  assert.equal(isIgnorableSessionDeleteError(new Error("session not found")), true);
  assert.equal(isIgnorableSessionDeleteError("cannot delete the main session"), true);
  assert.equal(isIgnorableSessionDeleteError("permission denied"), false);
});
