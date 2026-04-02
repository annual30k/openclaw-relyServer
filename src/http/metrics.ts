import type { HostSession, Metrics } from "../ws/runtime-types.js";

export function metricsText(metrics: Metrics, hostSessions: Map<string, HostSession>): string {
  const onlineGateways = Array.from(hostSessions.keys()).length;
  return [
    "# HELP relay_online_gateways Number of gateways with an online host session",
    "# TYPE relay_online_gateways gauge",
    `relay_online_gateways ${onlineGateways}`,
    "# HELP relay_host_connections Total active host websocket connections",
    "# TYPE relay_host_connections gauge",
    `relay_host_connections ${metrics.hostConnections}`,
    "# HELP relay_mobile_connections Total active mobile websocket connections",
    "# TYPE relay_mobile_connections gauge",
    `relay_mobile_connections ${metrics.mobileConnections}`,
    "# HELP relay_command_requests_total Total command requests",
    "# TYPE relay_command_requests_total counter",
    `relay_command_requests_total ${metrics.commandRequests}`,
    "# HELP relay_command_failures_total Total command failures",
    "# TYPE relay_command_failures_total counter",
    `relay_command_failures_total ${metrics.commandFailures}`,
    "# HELP relay_high_risk_commands_total Total high risk commands",
    "# TYPE relay_high_risk_commands_total counter",
    `relay_high_risk_commands_total ${metrics.highRiskCommands}`,
    "",
  ].join("\n");
}
