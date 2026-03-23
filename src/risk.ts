import type { RiskLevel } from "./types.js";

const HIGH_RISK_METHODS = new Set([
  "host.restore.config",
  "host.gateway.restart",
  "clawpilot.gateway.restart",
  "clawconnect.gateway.restart",
  "pocketclaw.gateway.restart",
  "host.update.openclaw",
  "provider.add",
  "provider.delete",
]);

const BACKUP_METHOD_PATTERN = /^(clawconnect|pocketclaw|clawpilot)\.backup\.(list|create|update|delete|restore)$/;
const RESTORE_CONFIG_METHOD_PATTERN = /^(host|clawconnect|pocketclaw|clawpilot)\.restore\.config$/;

const READ_ONLY_METHODS = new Set([
  "chat.history",
  "chat.list",
  "cron.list",
  "cron.runs",
  "cron.status",
  "logs.get",
  "logs.list",
  "pocketclaw.model.list",
  "skills.status",
]);

const READ_ONLY_PREFIXES = [
  "status.",
  "relay.",
];

export function classifyRisk(method: string): RiskLevel {
  if (HIGH_RISK_METHODS.has(method)) return "L3";
  if (RESTORE_CONFIG_METHOD_PATTERN.test(method)) return "L3";
  if (BACKUP_METHOD_PATTERN.test(method)) {
    return method.endsWith(".list") ? "L1" : "L3";
  }
  if (READ_ONLY_METHODS.has(method)) return "L1";
  if (READ_ONLY_PREFIXES.some((prefix) => method.startsWith(prefix))) return "L1";
  return "L2";
}

export function requiresApproval(method: string): boolean {
  return classifyRisk(method) === "L3";
}

export function isReadOnly(method: string): boolean {
  return classifyRisk(method) === "L1";
}
