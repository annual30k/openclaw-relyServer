import { createServer, type IncomingMessage, type Server, type ServerResponse } from "http";
import { decodePathSegment, json, text } from "./common.js";

type RouteHandler = (req: IncomingMessage, res: ServerResponse) => Promise<void>;
type GatewayRouteHandler = (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
type GatewayUrlRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  gatewayIdValue: string,
  requestUrl: URL,
) => Promise<void>;
type GatewayItemRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  gatewayIdValue: string,
  itemId: string,
) => Promise<void>;
type SkillUpdateRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  gatewayIdValue: string,
  skillId: string,
) => Promise<void>;
type FileChunkRouteHandler = (
  req: IncomingMessage,
  res: ServerResponse,
  uploadId: string,
  chunkIndexRaw: string,
) => Promise<void>;

export interface RelayHttpServerOptions {
  ensureRateLimit: (scope: string, key: string) => boolean;
  metricsText: () => string;
  nowIso: () => string;
  handleRegister: RouteHandler;
  handleAuthRegister: RouteHandler;
  handleAuthLogin: RouteHandler;
  handleAuthDeleteAccount: RouteHandler;
  handleAccessCode: RouteHandler;
  handleMobilePair: RouteHandler;
  handleGatewayList: RouteHandler;
  handleGatewayDetail: GatewayRouteHandler;
  handleGatewayUpdate: GatewayRouteHandler;
  handleGatewayDelete: GatewayRouteHandler;
  handleGatewayModels: GatewayRouteHandler;
  handleGatewaySkills: GatewayRouteHandler;
  handleGatewayBackups: GatewayRouteHandler;
  handleGatewayBackupRestore: GatewayItemRouteHandler;
  handleGatewayBackup: GatewayItemRouteHandler;
  handleGatewayTasks: GatewayRouteHandler;
  handleGatewayTask: GatewayItemRouteHandler;
  handleGatewaySkillUpdate: SkillUpdateRouteHandler;
  handleGatewayChatHistory: GatewayUrlRouteHandler;
  handleGatewayChatReady: GatewayRouteHandler;
  handleGatewayChatSessions: GatewayUrlRouteHandler;
  handleGatewayChatSessionDelete: GatewayUrlRouteHandler;
  handleMobileFileUploadInit: GatewayRouteHandler;
  handleHostFileUploadInit: GatewayRouteHandler;
  handleMobileFileUploadChunk: FileChunkRouteHandler;
  handleHostFileUploadChunk: FileChunkRouteHandler;
  handleMobileFileUploadComplete: (req: IncomingMessage, res: ServerResponse, uploadId: string) => Promise<void>;
  handleHostFileUploadComplete: (req: IncomingMessage, res: ServerResponse, uploadId: string) => Promise<void>;
  handleMobileFileDownload: (req: IncomingMessage, res: ServerResponse, fileId: string) => Promise<void>;
  handleGatewayModelSelect: GatewayRouteHandler;
  handleGatewayDefaultModelSelect: GatewayRouteHandler;
  handleApproveSensitiveAction: GatewayRouteHandler;
}

export function createRelayHttpServer(options: RelayHttpServerOptions): Server {
  return createServer((req, res) => {
    void handleRelayHttpRequest(req, res, options);
  });
}

async function handleRelayHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  options: RelayHttpServerOptions,
): Promise<void> {
  try {
    const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const clientIp =
      (req.headers["x-forwarded-for"] as string | undefined)?.split(",")[0]?.trim()
      ?? req.socket.remoteAddress
      ?? "unknown";

    if (!options.ensureRateLimit("http", clientIp)) {
      json(res, 429, { error: "rate_limited" });
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/healthz") {
      json(res, 200, { ok: true, status: "healthy", now: options.nowIso() });
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/metrics") {
      text(res, 200, options.metricsText(), "text/plain; version=0.0.4; charset=utf-8");
      return;
    }

    if (req.method === "POST" && requestUrl.pathname === "/api/relay/register") {
      await options.handleRegister(req, res);
      return;
    }

    if (req.method === "POST" && requestUrl.pathname === "/api/auth/register") {
      await options.handleAuthRegister(req, res);
      return;
    }

    if (req.method === "POST" && requestUrl.pathname === "/api/auth/login") {
      await options.handleAuthLogin(req, res);
      return;
    }

    if (req.method === "DELETE" && requestUrl.pathname === "/api/auth/account") {
      await options.handleAuthDeleteAccount(req, res);
      return;
    }

    if (
      req.method === "POST"
      && (requestUrl.pathname === "/api/relay/access-code" || requestUrl.pathname === "/api/relay/accesscode")
    ) {
      await options.handleAccessCode(req, res);
      return;
    }

    if (req.method === "POST" && requestUrl.pathname === "/api/mobile/pair") {
      await options.handleMobilePair(req, res);
      return;
    }

    if (req.method === "GET" && requestUrl.pathname === "/api/mobile/gateways") {
      await options.handleGatewayList(req, res);
      return;
    }

    const detailMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)$/);
    if (detailMatch && req.method === "GET") {
      await options.handleGatewayDetail(req, res, detailMatch[1]);
      return;
    }
    if (detailMatch && req.method === "PATCH") {
      await options.handleGatewayUpdate(req, res, detailMatch[1]);
      return;
    }
    if (detailMatch && req.method === "DELETE") {
      await options.handleGatewayDelete(req, res, detailMatch[1]);
      return;
    }

    const modelsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models$/);
    if (modelsMatch && req.method === "GET") {
      await options.handleGatewayModels(req, res, modelsMatch[1]);
      return;
    }

    const skillsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/skills$/);
    if (skillsMatch && req.method === "GET") {
      await options.handleGatewaySkills(req, res, skillsMatch[1]);
      return;
    }

    const backupsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/backups$/);
    if (backupsMatch && (req.method === "GET" || req.method === "POST")) {
      await options.handleGatewayBackups(req, res, decodePathSegment(backupsMatch[1]));
      return;
    }

    const backupRestoreMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/backups\/([^/]+)\/restore$/);
    if (backupRestoreMatch && req.method === "POST") {
      await options.handleGatewayBackupRestore(
        req,
        res,
        decodePathSegment(backupRestoreMatch[1]),
        decodePathSegment(backupRestoreMatch[2]),
      );
      return;
    }

    const backupDetailMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/backups\/([^/]+)$/);
    if (backupDetailMatch && (req.method === "PATCH" || req.method === "DELETE")) {
      await options.handleGatewayBackup(
        req,
        res,
        decodePathSegment(backupDetailMatch[1]),
        decodePathSegment(backupDetailMatch[2]),
      );
      return;
    }

    const tasksMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/tasks$/);
    if (tasksMatch && (req.method === "GET" || req.method === "POST")) {
      await options.handleGatewayTasks(req, res, decodePathSegment(tasksMatch[1]));
      return;
    }

    const taskDetailMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/tasks\/([^/]+)$/);
    if (taskDetailMatch && (req.method === "PATCH" || req.method === "DELETE")) {
      await options.handleGatewayTask(
        req,
        res,
        decodePathSegment(taskDetailMatch[1]),
        decodePathSegment(taskDetailMatch[2]),
      );
      return;
    }

    const skillUpdateMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/skills\/([^/]+)$/);
    if (skillUpdateMatch && req.method === "PATCH") {
      await options.handleGatewaySkillUpdate(
        req,
        res,
        decodePathSegment(skillUpdateMatch[1]),
        decodePathSegment(skillUpdateMatch[2]),
      );
      return;
    }

    const chatHistoryMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/history$/);
    if (chatHistoryMatch && req.method === "GET") {
      await options.handleGatewayChatHistory(req, res, chatHistoryMatch[1], requestUrl);
      return;
    }

    const chatReadyMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/ready$/);
    if (chatReadyMatch && req.method === "GET") {
      await options.handleGatewayChatReady(req, res, chatReadyMatch[1]);
      return;
    }

    const chatSessionsMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/chat\/sessions$/);
    if (chatSessionsMatch && req.method === "GET") {
      await options.handleGatewayChatSessions(req, res, chatSessionsMatch[1], requestUrl);
      return;
    }
    if (chatSessionsMatch && req.method === "DELETE") {
      await options.handleGatewayChatSessionDelete(req, res, chatSessionsMatch[1], requestUrl);
      return;
    }

    const mobileFileInitMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/files\/init$/);
    if (mobileFileInitMatch && req.method === "POST") {
      await options.handleMobileFileUploadInit(req, res, mobileFileInitMatch[1]);
      return;
    }

    const hostFileInitMatch = requestUrl.pathname.match(/^\/api\/host\/gateways\/([^/]+)\/files\/init$/);
    if (hostFileInitMatch && req.method === "POST") {
      await options.handleHostFileUploadInit(req, res, hostFileInitMatch[1]);
      return;
    }

    const mobileFileChunkMatch = requestUrl.pathname.match(/^\/api\/mobile\/files\/([^/]+)\/chunks\/(\d+)$/);
    if (mobileFileChunkMatch && req.method === "PUT") {
      await options.handleMobileFileUploadChunk(req, res, mobileFileChunkMatch[1], mobileFileChunkMatch[2]);
      return;
    }

    const hostFileChunkMatch = requestUrl.pathname.match(/^\/api\/host\/files\/([^/]+)\/chunks\/(\d+)$/);
    if (hostFileChunkMatch && req.method === "PUT") {
      await options.handleHostFileUploadChunk(req, res, hostFileChunkMatch[1], hostFileChunkMatch[2]);
      return;
    }

    const mobileFileCompleteMatch = requestUrl.pathname.match(/^\/api\/mobile\/files\/([^/]+)\/complete$/);
    if (mobileFileCompleteMatch && req.method === "POST") {
      await options.handleMobileFileUploadComplete(req, res, mobileFileCompleteMatch[1]);
      return;
    }

    const hostFileCompleteMatch = requestUrl.pathname.match(/^\/api\/host\/files\/([^/]+)\/complete$/);
    if (hostFileCompleteMatch && req.method === "POST") {
      await options.handleHostFileUploadComplete(req, res, hostFileCompleteMatch[1]);
      return;
    }

    const mobileFileDownloadMatch = requestUrl.pathname.match(/^\/api\/mobile\/files\/([^/]+)$/);
    if (mobileFileDownloadMatch && req.method === "GET") {
      await options.handleMobileFileDownload(req, res, mobileFileDownloadMatch[1]);
      return;
    }

    const modelSelectMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models\/select$/);
    if (modelSelectMatch && req.method === "POST") {
      await options.handleGatewayModelSelect(req, res, modelSelectMatch[1]);
      return;
    }

    const defaultModelSelectMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/models\/default$/);
    if (defaultModelSelectMatch && req.method === "POST") {
      await options.handleGatewayDefaultModelSelect(req, res, defaultModelSelectMatch[1]);
      return;
    }

    const approvalMatch = requestUrl.pathname.match(/^\/api\/mobile\/gateways\/([^/]+)\/approve-sensitive-action$/);
    if (approvalMatch && req.method === "POST") {
      await options.handleApproveSensitiveAction(req, res, approvalMatch[1]);
      return;
    }

    json(res, 404, { error: "not_found" });
  } catch (error) {
    console.error("[relay] http handler failed", error);
    if (!res.headersSent) {
      json(res, 500, { error: "internal_error" });
      return;
    }
    res.end();
  }
}
