import type { IncomingMessage, ServerResponse } from "http";
import { pipeline } from "stream/promises";
import type { FileTransferRecord, FileTransferStore } from "../files/file-transfer-store.js";
import { canAccessFileTransfer } from "../files/file-formatters.js";
import { json, readJson } from "./common.js";
import type { TokenClaims } from "../ws/runtime-types.js";
import type { GatewayMembershipRecord } from "../types.js";

export interface FileRouteHandlers {
  handleMobileFileUploadInit: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleHostFileUploadInit: (req: IncomingMessage, res: ServerResponse, gatewayIdValue: string) => Promise<void>;
  handleMobileFileUploadChunk: (req: IncomingMessage, res: ServerResponse, uploadId: string, chunkIndexRaw: string) => Promise<void>;
  handleHostFileUploadChunk: (req: IncomingMessage, res: ServerResponse, uploadId: string, chunkIndexRaw: string) => Promise<void>;
  handleMobileFileUploadComplete: (req: IncomingMessage, res: ServerResponse, uploadId: string) => Promise<void>;
  handleHostFileUploadComplete: (req: IncomingMessage, res: ServerResponse, uploadId: string) => Promise<void>;
  handleMobileFileDownload: (req: IncomingMessage, res: ServerResponse, fileId: string) => Promise<void>;
}

interface FileRouteOptions {
  fileStore: FileTransferStore;
  sha256: (value: string) => string;
  store: {
    snapshot(): {
      gateways: Record<string, { relaySecretHash: string; displayName: string; ownerUserId?: string }>;
    };
  };
  requireAuthenticatedClaims: (req: IncomingMessage, res: ServerResponse) => TokenClaims | null;
  getMembership: (gatewayIdValue: string, userId: string) => GatewayMembershipRecord | undefined;
  touchHostSessionActivity: (gatewayIdValue: string) => void;
  touchMobileSessionActivity: (userId: string, deviceId: string) => void;
  broadcastFileTransfer: (gatewayIdValue: string, record: FileTransferRecord) => void;
}

export function buildAttachmentContentDisposition(fileName: string): string {
  const trimmed = fileName.trim();
  const fallbackName = sanitizeAsciiFilename(trimmed || "download");
  const encodedName = encodeRFC5987ValueChars(trimmed || "download");
  return `attachment; filename="${fallbackName}"; filename*=UTF-8''${encodedName}`;
}

export function createFileRouteHandlers(options: FileRouteOptions): FileRouteHandlers {
  const handleFileUploadInit = async (
    res: ServerResponse,
    gatewayIdValue: string,
    origin: "host" | "mobile",
    body: Record<string, unknown>,
    senderIdentity: string,
    uploaderUserId?: string,
    uploaderDeviceId?: string,
  ): Promise<void> => {
    const sessionKeyRaw = typeof body.sessionKey === "string" ? body.sessionKey : "main";
    const fileName = typeof body.fileName === "string" ? body.fileName.trim() : "";
    const mimeType = typeof body.mimeType === "string" ? body.mimeType.trim() : "application/octet-stream";
    const sizeBytes =
      typeof body.sizeBytes === "number" && Number.isFinite(body.sizeBytes) ? Math.max(0, Math.floor(body.sizeBytes)) : 0;
    const sha = typeof body.sha256 === "string" ? body.sha256.trim() : "";
    const senderDisplayName = typeof body.senderDisplayName === "string" ? body.senderDisplayName.trim() : undefined;
    const clientCreatedAt =
      typeof body.clientCreatedAt === "string" ? body.clientCreatedAt.trim()
        : typeof body.createdAt === "string" ? body.createdAt.trim()
          : undefined;

    if (!fileName || !sha) {
      json(res, 400, { error: "file_name_and_sha256_required" });
      return;
    }

    try {
      const response = await options.fileStore.initUpload({
        gatewayId: gatewayIdValue,
        sessionKey: sessionKeyRaw,
        fileName,
        mimeType,
        sizeBytes,
        sha256: sha,
        origin,
        uploaderUserId,
        uploaderDeviceId,
        senderDisplayName: senderDisplayName || (origin === "host" ? "ClawLink Host" : senderIdentity),
        clientCreatedAt: clientCreatedAt || undefined,
      });
      json(res, 200, response);
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleFileUploadChunk = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
    chunkIndex: number,
  ): Promise<void> => {
    try {
      const uploadSession = await options.fileStore.peekUpload(uploadId);
      if (uploadSession) {
        options.touchHostSessionActivity(uploadSession.gatewayId);
      }
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      await options.fileStore.writeChunk(uploadId, chunkIndex, Buffer.concat(chunks));
      json(res, 200, { ok: true });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleFileUploadComplete = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const totalChunks = typeof body.totalChunks === "number" && Number.isFinite(body.totalChunks) ? Math.floor(body.totalChunks) : 0;
    try {
      const uploadSession = await options.fileStore.peekUpload(uploadId);
      if (uploadSession) {
        options.touchHostSessionActivity(uploadSession.gatewayId);
      }
      const record = await options.fileStore.completeUpload(uploadId, totalChunks);
      options.broadcastFileTransfer(record.gatewayId, record);
      json(res, 200, {
        ok: true,
        payload: {
          ...record,
          downloadUrl: record.downloadPath,
        },
      });
    } catch (error) {
      json(res, 502, { error: String(error) });
    }
  };

  const handleMobileFileUploadInit = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const claims = options.requireAuthenticatedClaims(req, res);
    if (!claims) {
      return;
    }
    options.touchMobileSessionActivity(claims.userId, claims.deviceId);
    options.touchHostSessionActivity(gatewayIdValue);
    const membership = options.getMembership(gatewayIdValue, claims.userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    await handleFileUploadInit(res, gatewayIdValue, "mobile", body, claims.userId, claims.userId, claims.deviceId);
  };

  const handleHostFileUploadInit = async (
    req: IncomingMessage,
    res: ServerResponse,
    gatewayIdValue: string,
  ): Promise<void> => {
    const body = (await readJson<Record<string, unknown>>(req)) ?? {};
    const gateway = options.store.snapshot().gateways[gatewayIdValue];
    const secret = typeof body.secret === "string" ? body.secret : "";
    if (!gateway || options.sha256(secret) !== gateway.relaySecretHash) {
      json(res, 401, { error: "unauthorized" });
      return;
    }
    options.touchHostSessionActivity(gatewayIdValue);
    await handleFileUploadInit(res, gatewayIdValue, "host", body, gateway.displayName, gateway.ownerUserId ?? undefined);
  };

  const handleMobileFileUploadChunk = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
    chunkIndexRaw: string,
  ): Promise<void> => {
    const claims = options.requireAuthenticatedClaims(req, res);
    if (!claims) {
      return;
    }
    const chunkIndex = Number.parseInt(chunkIndexRaw, 10);
    if (!Number.isFinite(chunkIndex) || chunkIndex < 0) {
      json(res, 400, { error: "invalid_chunk_index" });
      return;
    }
    const uploadSession = await options.fileStore.peekUpload(uploadId);
    if (uploadSession) {
      options.touchHostSessionActivity(uploadSession.gatewayId);
    }
    options.touchMobileSessionActivity(claims.userId, claims.deviceId);
    await handleFileUploadChunk(req, res, uploadId, chunkIndex);
  };

  const handleHostFileUploadChunk = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
    chunkIndexRaw: string,
  ): Promise<void> => {
    const chunkIndex = Number.parseInt(chunkIndexRaw, 10);
    if (!Number.isFinite(chunkIndex) || chunkIndex < 0) {
      json(res, 400, { error: "invalid_chunk_index" });
      return;
    }
    const uploadSession = await options.fileStore.peekUpload(uploadId);
    if (uploadSession) {
      options.touchHostSessionActivity(uploadSession.gatewayId);
    }
    await handleFileUploadChunk(req, res, uploadId, chunkIndex);
  };

  const handleMobileFileUploadComplete = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
  ): Promise<void> => {
    const claims = options.requireAuthenticatedClaims(req, res);
    if (!claims) {
      return;
    }
    const uploadSession = await options.fileStore.peekUpload(uploadId);
    if (uploadSession) {
      options.touchHostSessionActivity(uploadSession.gatewayId);
    }
    options.touchMobileSessionActivity(claims.userId, claims.deviceId);
    await handleFileUploadComplete(req, res, uploadId);
  };

  const handleHostFileUploadComplete = async (
    req: IncomingMessage,
    res: ServerResponse,
    uploadId: string,
  ): Promise<void> => {
    const uploadSession = await options.fileStore.peekUpload(uploadId);
    if (uploadSession) {
      options.touchHostSessionActivity(uploadSession.gatewayId);
    }
    await handleFileUploadComplete(req, res, uploadId);
  };

  const handleMobileFileDownload = async (
    req: IncomingMessage,
    res: ServerResponse,
    fileId: string,
  ): Promise<void> => {
    const claims = options.requireAuthenticatedClaims(req, res);
    if (!claims) {
      return;
    }

    const record = await options.fileStore.downloadFile(fileId);
    if (!record) {
      json(res, 404, { error: "file_not_found" });
      return;
    }

    options.touchHostSessionActivity(record.gatewayId);
    options.touchMobileSessionActivity(claims.userId, claims.deviceId);
    const membership = options.getMembership(record.gatewayId, claims.userId);
    if (!membership) {
      json(res, 404, { error: "gateway_not_found" });
      return;
    }
    if (!canAccessFileTransfer(record, claims.userId)) {
      json(res, 403, { error: "file_not_owned" });
      return;
    }

    try {
      const source = await options.fileStore.openDownload(record);
      res.writeHead(200, {
        "Content-Type": record.mimeType || "application/octet-stream",
        "Content-Length": String(source.contentLength),
        "Content-Disposition": buildAttachmentContentDisposition(record.fileName),
        "Cache-Control": "private, max-age=0, no-cache",
      });
      await pipeline(source.stream, res);
    } catch (error) {
      if (!res.headersSent) {
        json(res, 502, { error: String(error) });
        return;
      }
      res.destroy(error instanceof Error ? error : undefined);
    }
  };

  return {
    handleMobileFileUploadInit,
    handleHostFileUploadInit,
    handleMobileFileUploadChunk,
    handleHostFileUploadChunk,
    handleMobileFileUploadComplete,
    handleHostFileUploadComplete,
    handleMobileFileDownload,
  };
}

function sanitizeAsciiFilename(fileName: string): string {
  const asciiOnly = fileName
    .replace(/[\r\n]/g, "")
    .replace(/[\\/]/g, "_")
    .replace(/[^\x20-\x7E]/g, "_")
    .replace(/["\\]/g, "\\$&")
    .trim();
  return asciiOnly || "download";
}

function encodeRFC5987ValueChars(value: string): string {
  return encodeURIComponent(value)
    .replace(/['()]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/\*/g, "%2A");
}
