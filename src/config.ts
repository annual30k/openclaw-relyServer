import { mkdirSync } from "fs";
import { resolve } from "path";

function intEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
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
}

export function loadConfig(): AppConfig {
  const dataDir = resolve(process.cwd(), process.env.DATA_DIR ?? ".data");
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
  };
}
