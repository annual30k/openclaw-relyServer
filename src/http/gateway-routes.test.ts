import assert from "node:assert/strict";
import test from "node:test";
import { resolveModelSelectionSessionKey } from "./gateway-routes.js";

test("resolveModelSelectionSessionKey preserves explicit session keys", () => {
  assert.equal(resolveModelSelectionSessionKey("agent:main:ios-123"), "agent:main:ios-123");
  assert.equal(resolveModelSelectionSessionKey(" main "), "main");
});

test("resolveModelSelectionSessionKey falls back to main", () => {
  assert.equal(resolveModelSelectionSessionKey(undefined), "main");
  assert.equal(resolveModelSelectionSessionKey(null), "main");
  assert.equal(resolveModelSelectionSessionKey("   "), "main");
});
