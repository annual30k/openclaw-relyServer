import assert from "node:assert/strict";
import test from "node:test";
import { computeAggregateStatus, defaultGatewayRuntime } from "./runtime-state.js";

test("defaultGatewayRuntime starts offline", () => {
  assert.deepEqual(defaultGatewayRuntime("gw_1"), {
    gatewayId: "gw_1",
    relayStatus: "offline",
    hostStatus: "offline",
    openclawStatus: "offline",
    aggregateStatus: "offline",
    mobileControlStatus: "idle",
  });
});

test("computeAggregateStatus prefers active and degraded states over offline", () => {
  assert.equal(
    computeAggregateStatus({
      gatewayId: "gw_1",
      relayStatus: "offline",
      hostStatus: "healthy",
      openclawStatus: "offline",
      aggregateStatus: "offline",
      mobileControlStatus: "idle",
    }),
    "healthy",
  );
  assert.equal(
    computeAggregateStatus({
      gatewayId: "gw_1",
      relayStatus: "offline",
      hostStatus: "degraded",
      openclawStatus: "offline",
      aggregateStatus: "offline",
      mobileControlStatus: "idle",
    }),
    "degraded",
  );
  assert.equal(
    computeAggregateStatus({
      gatewayId: "gw_1",
      relayStatus: "relay_connected",
      hostStatus: "offline",
      openclawStatus: "offline",
      aggregateStatus: "offline",
      mobileControlStatus: "idle",
    }),
    "degraded",
  );
});
