import type { RiskLevel } from "./types.js";

const HIGH_RISK_METHODS = new Set([
  "host.restore.config",
  "host.gateway.restart",
  "host.update.openclaw",
  "provider.add",
  "provider.delete",
]);

const READ_ONLY_PREFIXES = [
  "chat.history",
  "chat.list",
  "logs.get",
  "logs.list",
  "status.",
  "relay.",
];

export function classifyRisk(method: string): RiskLevel {
  if (HIGH_RISK_METHODS.has(method)) return "L3";
  if (READ_ONLY_PREFIXES.some((prefix) => method.startsWith(prefix))) return "L1";
  return "L2";
}

export function requiresApproval(method: string): boolean {
  return classifyRisk(method) === "L3";
}

export function isReadOnly(method: string): boolean {
  return classifyRisk(method) === "L1";
}
