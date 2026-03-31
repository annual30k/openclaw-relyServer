import { mkdirSync } from "fs";
import { resolve } from "path";

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function boolEnv(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (!raw) return fallback;
  const normalized = raw.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return fallback;
}

function fileStorageDriverEnv(): "disk" | "minio" {
  return process.env.FILE_STORAGE_DRIVER?.trim().toLowerCase() === "minio" ? "minio" : "disk";
}

export interface AppConfig {
  nodeEnv: string;
  host: string;
  port: number;
  jwtSecret: string;
  databaseUrl: string;
  dataDir: string;
  dataFile: string;
  accessCodeTtlSeconds: number;
  heartbeatIntervalMs: number;
  wsIdleTimeoutMs: number;
  approvalTtlSeconds: number;
  rateLimitWindowMs: number;
  rateLimitMax: number;
  authTokenTtlSeconds: number;
  fileStorageDriver: "disk" | "minio";
  fileChunkSizeBytes: number;
  fileUploadTtlSeconds: number;
  fileTtlSeconds: number;
  minio?: {
    endPoint: string;
    port: number;
    useSSL: boolean;
    accessKey: string;
    secretKey: string;
    bucket: string;
    region?: string;
  };
}

export function loadConfig(): AppConfig {
  const dataDir = resolve(process.cwd(), process.env.DATA_DIR ?? ".data");
  const fileStorageDriver = fileStorageDriverEnv();
  mkdirSync(dataDir, { recursive: true });
  return {
    nodeEnv: process.env.NODE_ENV ?? "development",
    host: process.env.HOST ?? "0.0.0.0",
    port: intEnv("PORT", 8080),
    jwtSecret: process.env.JWT_SECRET ?? "change-me",
    databaseUrl: process.env.DATABASE_URL ?? "mysql://pocketclaw:pocketclaw123@127.0.0.1:3306/pocketclaw_relay",
    dataDir,
    dataFile: resolve(dataDir, "relay-state.json"),
    accessCodeTtlSeconds: intEnv("ACCESS_CODE_TTL_SECONDS", 300),
    heartbeatIntervalMs: intEnv("HEARTBEAT_INTERVAL_MS", 30000),
    wsIdleTimeoutMs: intEnv("WS_IDLE_TIMEOUT_MS", 70000),
    approvalTtlSeconds: intEnv("APPROVAL_TTL_SECONDS", 300),
    rateLimitWindowMs: intEnv("RATE_LIMIT_WINDOW_MS", 60000),
    rateLimitMax: intEnv("RATE_LIMIT_MAX", 120),
    authTokenTtlSeconds: intEnv("AUTH_TOKEN_TTL_SECONDS", 60 * 60 * 24 * 30),
    fileStorageDriver,
    fileChunkSizeBytes: intEnv("FILE_CHUNK_SIZE_BYTES", 5 * 1024 * 1024),
    fileUploadTtlSeconds: intEnv("FILE_UPLOAD_TTL_SECONDS", 30 * 60),
    fileTtlSeconds: intEnv("FILE_TTL_SECONDS", 7 * 24 * 60 * 60),
    minio: fileStorageDriver === "minio" ? {
      endPoint: process.env.MINIO_ENDPOINT ?? "127.0.0.1",
      port: intEnv("MINIO_PORT", 9000),
      useSSL: boolEnv("MINIO_USE_SSL", false),
      accessKey: process.env.MINIO_ACCESS_KEY ?? "",
      secretKey: process.env.MINIO_SECRET_KEY ?? "",
      bucket: process.env.MINIO_BUCKET ?? "pocketclaw-files",
      region: process.env.MINIO_REGION?.trim() || undefined,
    } : undefined,
  };
}
