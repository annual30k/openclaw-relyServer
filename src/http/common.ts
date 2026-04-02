import type { IncomingMessage, ServerResponse } from "http";

export function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

export function text(res: ServerResponse, status: number, body: string, contentType = "text/plain; charset=utf-8"): void {
  res.writeHead(status, { "Content-Type": contentType });
  res.end(body);
}

export async function readJson<T>(req: IncomingMessage): Promise<T | null> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  if (chunks.length === 0) {
    return null;
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function decodePathSegment(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function parseStringRecord(value: unknown): Record<string, string> | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object" || Array.isArray(value)) return undefined;

  const record: Record<string, string> = {};
  for (const [key, rawValue] of Object.entries(value as Record<string, unknown>)) {
    if (typeof rawValue !== "string") {
      return undefined;
    }
    record[key] = rawValue;
  }
  return record;
}

export function hostCommandErrorResponse(error: unknown): { status: number; body: { error: string } } {
  const message = error instanceof Error ? error.message : String(error);
  const separatorIndex = message.indexOf(":");
  const rawCode = separatorIndex > 0 ? message.slice(0, separatorIndex).trim() : message.trim();
  const detail = separatorIndex > 0 ? message.slice(separatorIndex + 1).trim() : "";
  const normalizedCode = rawCode.replace(/[\s-]+/g, "_").toUpperCase();
  const errorCode = rawCode.replace(/[\s-]+/g, "_").toLowerCase() || "host_error";
  const invalidRequestBody = { error: "invalid_request" };
  const timeoutBody = { error: "timeout" };
  const gatewayOfflineBody = { error: "gateway_offline" };

  switch (normalizedCode) {
    case "GATEWAY_OFFLINE":
      return { status: 503, body: gatewayOfflineBody };
    case "TIMEOUT":
    case "AGENT_TIMEOUT":
      return { status: 504, body: timeoutBody };
    case "INVALID_REQUEST":
      return { status: 400, body: invalidRequestBody };
    case "UNAVAILABLE":
      return { status: 503, body: { error: errorCode } };
    case "NOT_LINKED":
    case "NOT_PAIRED":
      return { status: 403, body: { error: errorCode } };
    case "BACKUP_NOT_FOUND":
    case "OPENCLAW_CONFIG_NOT_FOUND":
    case "OPENCLAW_CONFIG_DIR_NOT_FOUND":
    case "SKILL_NOT_FOUND":
      return { status: 404, body: { error: errorCode } };
  }

  if (normalizedCode.endsWith("NOT_FOUND") || detail.toLowerCase().includes("not found")) {
    return { status: 404, body: { error: normalizedCode === "INVALID_REQUEST" ? "task_not_found" : errorCode } };
  }
  if (normalizedCode.endsWith("REQUIRED") || normalizedCode.endsWith("INVALID")) {
    return { status: 400, body: { error: errorCode } };
  }

  switch (errorCode) {
    case "gateway_offline":
      return { status: 503, body: gatewayOfflineBody };
    case "timeout":
      return { status: 504, body: timeoutBody };
    case "backup_not_found":
      return { status: 404, body: { error: "backup_not_found" } };
    case "backup_id_required":
    case "backup_filename_invalid":
    case "backup_title_too_long":
    case "backup_detail_too_long":
      return { status: 400, body: { error: errorCode } };
    case "backup_limit_reached":
      return { status: 409, body: { error: errorCode } };
    case "openclaw_config_not_found":
    case "openclaw_config_dir_not_found":
      return { status: 404, body: { error: errorCode } };
    case "skill_not_found":
      return { status: 404, body: { error: errorCode } };
    case "skill_blocked":
      return { status: 403, body: { error: errorCode } };
    default:
      return { status: 502, body: { error: errorCode } };
  }
}
