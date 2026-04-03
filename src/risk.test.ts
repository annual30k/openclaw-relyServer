import assert from "node:assert/strict";
import test from "node:test";
import { classifyRisk, requiresApproval } from "./risk.js";

test("remote restart methods are classified as high risk and require approval", () => {
  const methods = [
    "host.gateway.remoteRestart",
    "clawpilot.gateway.remoteRestart",
    "clawconnect.gateway.remoteRestart",
    "pocketclaw.gateway.remoteRestart",
  ];

  for (const method of methods) {
    assert.equal(classifyRisk(method), "L3");
    assert.equal(requiresApproval(method), true);
  }
});
