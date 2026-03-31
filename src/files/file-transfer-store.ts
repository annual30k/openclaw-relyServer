import { createHash, randomUUID } from "crypto";
import { access, mkdir, open, readFile, rm } from "fs/promises";
import { join } from "path";
import { buildStoredObjectKey, normalizeSessionKey, safeStoredFileName } from "./helpers.js";
import { MySqlFileTransferMetadataStore } from "./metadata-store.js";
import { createFileObjectStorage, type FileObjectStorage } from "./object-storage.js";
import type {
  FileDownloadSource,
  FileTransferInitInput,
  FileTransferInitResult,
  FileTransferMetadataStore,
  FileTransferRecord,
  FileTransferStoreOptions,
  FileUploadSessionInfo,
} from "./types.js";

export type { FileTransferOrigin, FileTransferRecord, FileTransferStatus } from "./types.js";

export class FileTransferStore {
  private readonly uploadsDir: string;

  constructor(
    private readonly metadataStore: FileTransferMetadataStore,
    private readonly objectStorage: FileObjectStorage,
    private readonly options: Pick<FileTransferStoreOptions, "chunkSizeBytes" | "uploadTtlMs" | "fileTtlMs">,
    dataDir: string,
  ) {
    this.uploadsDir = join(dataDir, "uploads");
  }

  static async create(options: FileTransferStoreOptions): Promise<FileTransferStore> {
    await mkdir(join(options.dataDir, "uploads"), { recursive: true });
    const [metadataStore, objectStorage] = await Promise.all([
      MySqlFileTransferMetadataStore.create(options.databaseUrl),
      createFileObjectStorage(options),
    ]);
    return new FileTransferStore(metadataStore, objectStorage, options, options.dataDir);
  }

  async initUpload(input: FileTransferInitInput): Promise<FileTransferInitResult> {
    const now = new Date();
    const fileId = `file_${randomUUID().replace(/-/g, "")}`;
    const uploadId = `up_${randomUUID().replace(/-/g, "")}`;
    const chunkSize = Math.max(1, Math.floor(this.options.chunkSizeBytes));
    const expiresAt = new Date(now.getTime() + this.options.uploadTtlMs).toISOString();
    await mkdir(this.chunkDir(uploadId), { recursive: true });

    await this.metadataStore.createUpload({
      ...input,
      sessionKey: normalizeSessionKey(input.sessionKey),
      fileId,
      uploadId,
      chunkSize,
      expiresAt,
      downloadPath: `/api/mobile/files/${fileId}`,
      storageBackend: this.objectStorage.backend,
    });

    return {
      fileId,
      uploadId,
      chunkSize,
      expiresAt,
      uploadUrl: `/api/${input.origin}/files/${uploadId}/chunks`,
    };
  }

  async writeChunk(uploadId: string, index: number, data: Buffer): Promise<void> {
    await this.requireUpload(uploadId);
    await mkdir(this.chunkDir(uploadId), { recursive: true });
    await this.metadataStore.touchUpload(uploadId);
    const chunkPath = this.chunkPath(uploadId, index);
    await rm(chunkPath, { force: true });
    const handle = await open(chunkPath, "w");
    try {
      await handle.writeFile(data);
    } finally {
      await handle.close();
    }
  }

  async completeUpload(uploadId: string, totalChunks: number): Promise<FileTransferRecord> {
    const upload = await this.requireUpload(uploadId);
    const normalizedTotalChunks = Math.max(0, Math.floor(totalChunks));
    if (normalizedTotalChunks <= 0) {
      throw new Error("total_chunks_required");
    }

    const assembledPath = this.assembledPath(uploadId, upload.fileId, upload.fileName);
    await rm(assembledPath, { force: true });

    const hasher = createHash("sha256");
    const output = await open(assembledPath, "w");
    let totalBytes = 0;

    try {
      for (let index = 0; index < normalizedTotalChunks; index += 1) {
        const chunkPath = this.chunkPath(uploadId, index);
        await access(chunkPath);
        const chunk = await readFile(chunkPath);
        totalBytes += chunk.length;
        hasher.update(chunk);
        await output.write(chunk);
      }
    } finally {
      await output.close();
    }

    if (totalBytes !== upload.sizeBytes) {
      await rm(assembledPath, { force: true });
      throw new Error("size_mismatch");
    }

    const computedSha = hasher.digest("hex");
    if (computedSha.toLowerCase() !== upload.sha256.toLowerCase()) {
      await rm(assembledPath, { force: true });
      throw new Error("checksum_mismatch");
    }

    const stored = await this.objectStorage.storeFile(
      assembledPath,
      buildStoredObjectKey(upload.gatewayId, upload.sessionKey, upload.fileId, upload.fileName),
      upload,
    );

    const record = await this.metadataStore.completeUpload({
      uploadId,
      storage: stored,
      totalChunks: normalizedTotalChunks,
      expiresAt: new Date(Date.now() + this.options.fileTtlMs).toISOString(),
    });

    await rm(this.uploadDir(uploadId), { recursive: true, force: true });
    return record;
  }

  async listFiles(gatewayId: string, sessionKey: string | undefined, viewerUserId: string): Promise<FileTransferRecord[]> {
    await this.cleanupExpired();
    return this.metadataStore.listVisibleCompletedFiles(gatewayId.trim(), sessionKey, viewerUserId);
  }

  async getFile(fileId: string): Promise<FileTransferRecord | undefined> {
    return this.metadataStore.getFile(fileId);
  }

  async downloadFile(fileId: string): Promise<FileTransferRecord | undefined> {
    await this.cleanupExpired();
    const record = await this.metadataStore.getFile(fileId);
    if (!record || record.status !== "completed") {
      return undefined;
    }
    return record;
  }

  async openDownload(record: FileTransferRecord): Promise<FileDownloadSource> {
    return this.objectStorage.openDownload(record);
  }

  async peekUpload(uploadId: string): Promise<FileUploadSessionInfo | undefined> {
    const upload = await this.metadataStore.getUpload(uploadId);
    if (!upload || (upload.status !== "initiated" && upload.status !== "uploading")) {
      return undefined;
    }
    return {
      gatewayId: upload.gatewayId,
      sessionKey: upload.sessionKey,
      origin: upload.origin,
    };
  }

  async deleteFile(fileId: string): Promise<boolean> {
    const record = await this.metadataStore.getFile(fileId);
    if (!record) {
      return false;
    }
    if (record.status === "completed") {
      await this.objectStorage.deleteObject(record);
    }
    if (record.uploadId) {
      await rm(this.uploadDir(record.uploadId), { recursive: true, force: true });
    }
    return this.metadataStore.markDeleted(fileId);
  }

  async deleteFilesForGateway(gatewayId: string): Promise<number> {
    const records = await this.metadataStore.listFilesForGatewayCleanup(gatewayId.trim());
    let deletedCount = 0;
    for (const record of records) {
      if (await this.deleteFile(record.fileId)) {
        deletedCount += 1;
      }
    }
    return deletedCount;
  }

  async cleanupExpired(now = new Date()): Promise<void> {
    const expiredRecords = await this.metadataStore.listExpiredActiveFiles(now);
    for (const record of expiredRecords) {
      try {
        if ((record.status === "initiated" || record.status === "uploading") && record.uploadId) {
          await rm(this.uploadDir(record.uploadId), { recursive: true, force: true });
        }
        if (record.status === "completed") {
          await this.objectStorage.deleteObject(record);
        }
        await this.metadataStore.markExpired(record.fileId);
      } catch (error) {
        if (!(error instanceof Error) || !error.message.includes("NoSuch")) {
          throw error;
        }
        await this.metadataStore.markExpired(record.fileId);
      }
    }
  }

  toChatHistoryItem(record: FileTransferRecord): {
    id: string;
    role: string;
    content: string;
    contentBlocks: Array<Record<string, unknown>>;
    createdAt: string;
  } {
    const block = buildFileContentBlock(record);
    return {
      id: `file-${record.fileId}`,
      role: record.origin === "mobile" ? "user" : "assistant",
      content: record.fileName,
      contentBlocks: [block],
      createdAt: record.createdAt,
    };
  }

  toChatEventPayload(record: FileTransferRecord): Record<string, unknown> {
    const historyItem = this.toChatHistoryItem(record);
    return {
      state: "final",
      role: historyItem.role,
      sessionKey: record.sessionKey,
      runId: historyItem.id,
      ts: Date.parse(historyItem.createdAt),
      text: historyItem.content,
      message: {
        role: historyItem.role,
        timestamp: Date.parse(historyItem.createdAt),
        content: historyItem.contentBlocks,
      },
    };
  }

  private async requireUpload(uploadId: string): Promise<FileTransferRecord> {
    const upload = await this.metadataStore.getUpload(uploadId);
    if (!upload || (upload.status !== "initiated" && upload.status !== "uploading")) {
      throw new Error("upload_not_found");
    }
    return upload;
  }

  private uploadDir(uploadId: string): string {
    return join(this.uploadsDir, uploadId);
  }

  private chunkDir(uploadId: string): string {
    return join(this.uploadDir(uploadId), "chunks");
  }

  private chunkPath(uploadId: string, index: number): string {
    return join(this.chunkDir(uploadId), `${index}.part`);
  }

  private assembledPath(uploadId: string, fileId: string, fileName: string): string {
    const { extension } = safeStoredFileName(fileName);
    return join(this.uploadDir(uploadId), `${fileId}.assembled${extension}`);
  }
}

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
