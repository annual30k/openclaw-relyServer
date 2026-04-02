import test from "node:test";
import assert from "node:assert/strict";
import { metricsText } from "./metrics.js";
import type { HostSession, Metrics } from "../ws/runtime-types.js";

test("metricsText renders gateway and connection gauges", () => {
  const metrics: Metrics = {
    hostConnections: 3,
    mobileConnections: 5,
    commandRequests: 8,
    commandFailures: 2,
    wsReconnectKicks: 1,
    highRiskCommands: 4,
  };
  const hostSessions = new Map<string, HostSession>([
    ["gw-1", { gatewayId: "gw-1", socket: {} as HostSession["socket"], lastSeenAt: "2026-03-31T00:00:00.000Z" }],
    ["gw-2", { gatewayId: "gw-2", socket: {} as HostSession["socket"], lastSeenAt: "2026-03-31T00:00:00.000Z" }],
  ]);

  assert.equal(
    metricsText(metrics, hostSessions),
    [
      "# HELP relay_online_gateways Number of gateways with an online host session",
      "# TYPE relay_online_gateways gauge",
      "relay_online_gateways 2",
      "# HELP relay_host_connections Total active host websocket connections",
      "# TYPE relay_host_connections gauge",
      "relay_host_connections 3",
      "# HELP relay_mobile_connections Total active mobile websocket connections",
      "# TYPE relay_mobile_connections gauge",
      "relay_mobile_connections 5",
      "# HELP relay_command_requests_total Total command requests",
      "# TYPE relay_command_requests_total counter",
      "relay_command_requests_total 8",
      "# HELP relay_command_failures_total Total command failures",
      "# TYPE relay_command_failures_total counter",
      "relay_command_failures_total 2",
      "# HELP relay_high_risk_commands_total Total high risk commands",
      "# TYPE relay_high_risk_commands_total counter",
      "relay_high_risk_commands_total 4",
      "",
    ].join("\n"),
  );
});
