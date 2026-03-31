import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";
import test from "node:test";
import { FileTransferStore, buildFileContentBlock } from "./file-transfer-store.js";
import type {
  CompleteUploadRecordInput,
  CreateUploadRecordInput,
  FileDownloadSource,
  FileTransferMetadataStore,
  FileTransferRecord,
} from "./types.js";

class InMemoryMetadataStore implements FileTransferMetadataStore {
  private readonly records = new Map<string, FileTransferRecord>();
  private readonly uploadIds = new Map<string, string>();

  async createUpload(input: CreateUploadRecordInput): Promise<FileTransferRecord> {
    const record: FileTransferRecord = {
      fileId: input.fileId,
      uploadId: input.uploadId,
      gatewayId: input.gatewayId,
      sessionKey: input.sessionKey,
      fileName: input.fileName,
      mimeType: input.mimeType,
      sizeBytes: input.sizeBytes,
      sha256: input.sha256,
      origin: input.origin,
      uploaderUserId: input.uploaderUserId,
      uploaderDeviceId: input.uploaderDeviceId,
      senderDisplayName: input.senderDisplayName,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      expiresAt: input.expiresAt,
      status: "initiated",
      storageBackend: input.storageBackend,
      storagePath: "",
      downloadPath: input.downloadPath,
      chunkSize: input.chunkSize,
      totalChunks: 0,
    };
    this.records.set(record.fileId, record);
    this.uploadIds.set(record.uploadId!, record.fileId);
    return record;
  }

  async getUpload(uploadId: string): Promise<FileTransferRecord | undefined> {
    const fileId = this.uploadIds.get(uploadId);
    return fileId ? this.records.get(fileId) : undefined;
  }

  async getFile(fileId: string): Promise<FileTransferRecord | undefined> {
    return this.records.get(fileId);
  }

  async touchUpload(uploadId: string): Promise<void> {
    const record = await this.getUpload(uploadId);
    if (!record) return;
    record.status = record.status === "initiated" ? "uploading" : record.status;
    record.updatedAt = new Date().toISOString();
  }

  async completeUpload(input: CompleteUploadRecordInput): Promise<FileTransferRecord> {
    const record = await this.getUpload(input.uploadId);
    assert.ok(record);
    record.status = "completed";
    record.storageBackend = input.storage.storageBackend;
    record.storageBucket = input.storage.storageBucket;
    record.storageKey = input.storage.storageKey;
    record.storagePath = input.storage.storagePath;
    record.totalChunks = input.totalChunks;
    record.expiresAt = input.expiresAt;
    record.updatedAt = new Date().toISOString();
    return record;
  }

  async listVisibleCompletedFiles(gatewayId: string, sessionKey: string | undefined, viewerUserId: string): Promise<FileTransferRecord[]> {
    return Array.from(this.records.values()).filter((record) => (
      record.gatewayId === gatewayId
      && record.status === "completed"
      && (!sessionKey || record.sessionKey === sessionKey)
      && (!record.uploaderUserId || record.uploaderUserId === viewerUserId)
    ));
  }

  async listFilesForGatewayCleanup(gatewayId: string): Promise<FileTransferRecord[]> {
    return Array.from(this.records.values()).filter((record) => (
      record.gatewayId === gatewayId && record.status !== "deleted"
    ));
  }

  async listExpiredActiveFiles(now: Date): Promise<FileTransferRecord[]> {
    return Array.from(this.records.values()).filter((record) => (
      ["initiated", "uploading", "completed"].includes(record.status)
      && Date.parse(record.expiresAt) <= now.getTime()
    ));
  }

  async markExpired(fileId: string): Promise<void> {
    const record = this.records.get(fileId);
    if (record) {
      record.status = "expired";
    }
  }

  async markDeleted(fileId: string): Promise<boolean> {
    const record = this.records.get(fileId);
    if (!record) {
      return false;
    }
    this.records.delete(fileId);
    if (record.uploadId) {
      this.uploadIds.delete(record.uploadId);
    }
    return true;
  }
}

class InMemoryObjectStorage {
  readonly backend = "disk" as const;
  readonly deletedFileIds: string[] = [];
  private readonly contents = new Map<string, Buffer>();

  async storeFile(sourcePath: string, targetObjectKey: string, record: FileTransferRecord) {
    const data = await readFile(sourcePath);
    this.contents.set(record.fileId, data);
    return {
      storageBackend: this.backend,
      storageKey: targetObjectKey,
      storagePath: `/virtual/${targetObjectKey}`,
    };
  }

  async openDownload(record: FileTransferRecord): Promise<FileDownloadSource> {
    const data = this.contents.get(record.fileId) ?? Buffer.alloc(0);
    return {
      stream: Readable.from(data),
      contentLength: data.length,
    };
  }

  async deleteObject(record: FileTransferRecord): Promise<void> {
    this.deletedFileIds.push(record.fileId);
    this.contents.delete(record.fileId);
  }
}

test("file transfer store completes upload and builds file block", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "relay-file-store-"));
  const metadataStore = new InMemoryMetadataStore();
  const objectStorage = new InMemoryObjectStorage();
  const store = new FileTransferStore(
    metadataStore,
    objectStorage,
    {
      chunkSizeBytes: 4,
      uploadTtlMs: 60_000,
      fileTtlMs: 600_000,
    },
    rootDir,
  );

  try {
    const buffer = Buffer.from("hello relay");
    const sha256 = "d6d73b3e899f235e4c4540a978ac34c5bcd2dea1437991da046282f41844692b";
    const init = await store.initUpload({
      gatewayId: "gw_1",
      sessionKey: "main",
      fileName: "hello.txt",
      mimeType: "text/plain",
      sizeBytes: buffer.length,
      sha256,
      origin: "host",
      uploaderUserId: "user_1",
      senderDisplayName: "ClawLink Host",
    });

    await store.writeChunk(init.uploadId, 0, buffer.subarray(0, 4));
    await store.writeChunk(init.uploadId, 1, buffer.subarray(4, 8));
    await store.writeChunk(init.uploadId, 2, buffer.subarray(8));

    const record = await store.completeUpload(init.uploadId, 3);
    assert.equal(record.status, "completed");
    assert.equal(record.storageKey?.includes(record.fileId), true);

    const items = await store.listFiles("gw_1", "main", "user_1");
    assert.equal(items.length, 1);
    const block = buildFileContentBlock(record);
    assert.equal(block.fileId, record.fileId);
    assert.equal(block.downloadUrl, record.downloadPath);

    const downloadable = await store.downloadFile(record.fileId);
    assert.ok(downloadable);
    const source = await store.openDownload(downloadable);
    assert.equal(source.contentLength, buffer.length);
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("file transfer store rejects completion when a chunk is missing", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "relay-file-store-missing-"));
  const metadataStore = new InMemoryMetadataStore();
  const objectStorage = new InMemoryObjectStorage();
  const store = new FileTransferStore(
    metadataStore,
    objectStorage,
    {
      chunkSizeBytes: 4,
      uploadTtlMs: 60_000,
      fileTtlMs: 600_000,
    },
    rootDir,
  );

  try {
    const init = await store.initUpload({
      gatewayId: "gw_1",
      sessionKey: "main",
      fileName: "oops.txt",
      mimeType: "text/plain",
      sizeBytes: 8,
      sha256: "86d8e9d8ef6d11b44f0e6d0295d515de68660fafa3fd7a215e5a0008279ec0ae",
      origin: "host",
    });
    await store.writeChunk(init.uploadId, 0, Buffer.from("test"));
    await assert.rejects(() => store.completeUpload(init.uploadId, 2), /ENOENT|no such file or directory/);
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});

test("cleanupExpired deletes expired completed objects and marks metadata", async () => {
  const rootDir = await mkdtemp(join(tmpdir(), "relay-file-store-expired-"));
  const metadataStore = new InMemoryMetadataStore();
  const objectStorage = new InMemoryObjectStorage();
  const store = new FileTransferStore(
    metadataStore,
    objectStorage,
    {
      chunkSizeBytes: 4,
      uploadTtlMs: 60_000,
      fileTtlMs: 600_000,
    },
    rootDir,
  );

  try {
    const init = await store.initUpload({
      gatewayId: "gw_1",
      sessionKey: "main",
      fileName: "expired.txt",
      mimeType: "text/plain",
      sizeBytes: 4,
      sha256: "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
      origin: "host",
      uploaderUserId: "user_1",
    });
    await store.writeChunk(init.uploadId, 0, Buffer.from("data"));
    const record = await store.completeUpload(init.uploadId, 1);
    record.expiresAt = new Date(Date.now() - 1_000).toISOString();

    await store.cleanupExpired(new Date());

    const expired = await metadataStore.getFile(record.fileId);
    assert.equal(expired?.status, "expired");
    assert.deepEqual(objectStorage.deletedFileIds, [record.fileId]);
  } finally {
    await rm(rootDir, { recursive: true, force: true });
  }
});
