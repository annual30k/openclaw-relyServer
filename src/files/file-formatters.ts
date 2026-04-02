import type { FileTransferRecord } from "./types.js";

export function buildFileContentBlock(record: FileTransferRecord): Record<string, unknown> {
  return {
    type: "file",
    text: record.fileName,
    name: record.fileName,
    gatewayId: record.gatewayId,
    sessionKey: record.sessionKey,
    fileId: record.fileId,
    fileName: record.fileName,
    mimeType: record.mimeType,
    sizeBytes: record.sizeBytes,
    downloadUrl: record.downloadPath,
    expiresAt: record.expiresAt,
    senderDisplayName: record.senderDisplayName,
    origin: record.origin,
    storageBackend: record.storageBackend,
    storageKey: record.storageKey,
  };
}

export function canAccessFileTransfer(record: FileTransferRecord, userId: string): boolean {
  if (!record.uploaderUserId) {
    return true;
  }
  return record.uploaderUserId === userId;
}
