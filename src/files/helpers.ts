import { extname } from "path";

export function normalizeTimestamp(value: string): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? new Date(parsed).toISOString() : new Date().toISOString();
}

export function normalizeText(value?: string | null): string | undefined {
  const trimmed = value?.trim() ?? "";
  return trimmed ? trimmed : undefined;
}

export function normalizeSessionKey(value: string): string {
  const trimmed = value.trim().toLowerCase();
  return trimmed ? trimmed : "main";
}

export function safeStoredFileName(fileName: string): { extension: string } {
  const extension = extname(fileName).toLowerCase();
  if (!extension || extension.length > 10 || /[^.\w-]/.test(extension)) {
    return { extension: "" };
  }
  return { extension };
}

export function toSqlDate(value?: string): string | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) {
    return parsed.toISOString().slice(0, 19).replace("T", " ");
  }
  return value.slice(0, 19).replace("T", " ");
}

export function toIso(value: unknown): string | undefined {
  if (value == null) return undefined;
  const stringValue = String(value);
  if (!stringValue) return undefined;
  return stringValue.includes("T") ? stringValue : `${stringValue.replace(" ", "T")}Z`;
}

export function buildStorageUri(bucket: string | undefined, objectKey: string | undefined): string {
  const normalizedBucket = normalizeText(bucket);
  const normalizedKey = normalizeText(objectKey);
  if (!normalizedBucket || !normalizedKey) {
    return "";
  }
  return `minio://${normalizedBucket}/${normalizedKey}`;
}

export function buildStoredObjectKey(gatewayId: string, sessionKey: string, fileId: string, fileName: string): string {
  const { extension } = safeStoredFileName(fileName);
  const yearMonth = new Date().toISOString().slice(0, 7).replace("-", "/");
  return [
    "gateways",
    encodeURIComponent(gatewayId),
    "sessions",
    encodeURIComponent(sessionKey),
    yearMonth,
    `${fileId}${extension}`,
  ].join("/");
}
