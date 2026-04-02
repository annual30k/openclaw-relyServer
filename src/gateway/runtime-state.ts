import type { GatewayRuntimeStateRecord } from "../types.js";

export function defaultGatewayRuntime(gatewayIdValue: string): GatewayRuntimeStateRecord {
  return {
    gatewayId: gatewayIdValue,
    relayStatus: "offline",
    hostStatus: "offline",
    openclawStatus: "offline",
    aggregateStatus: "offline",
    mobileControlStatus: "idle",
  };
}

export function computeAggregateStatus(
  runtime: GatewayRuntimeStateRecord,
): GatewayRuntimeStateRecord["aggregateStatus"] {
  if (runtime.hostStatus === "healthy" || runtime.openclawStatus === "healthy") return "healthy";
  if (runtime.hostStatus === "degraded" || runtime.openclawStatus === "degraded") return "degraded";
  if (runtime.hostStatus === "connecting_openclaw") return "connecting";
  if (runtime.relayStatus === "relay_connected") return "degraded";
  return "offline";
}
