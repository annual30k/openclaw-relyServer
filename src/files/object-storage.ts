import { Client as MinioClient } from "minio";
import { createReadStream } from "fs";
import { mkdir, rename, rm } from "fs/promises";
import { dirname, join, resolve } from "path";
import type { FileDownloadSource, FileTransferRecord, FileTransferStoreOptions, StoredFileDescriptor } from "./types.js";
import { buildStorageUri, normalizeText } from "./helpers.js";

export interface FileObjectStorage {
  readonly backend: "disk" | "minio";
  storeFile(sourcePath: string, targetObjectKey: string, record: FileTransferRecord): Promise<StoredFileDescriptor>;
  openDownload(record: FileTransferRecord): Promise<FileDownloadSource>;
  deleteObject(record: FileTransferRecord): Promise<void>;
}

export async function createFileObjectStorage(options: FileTransferStoreOptions): Promise<FileObjectStorage> {
  if (options.storageBackend === "minio") {
    if (!options.minio) {
      throw new Error("minio_config_required");
    }
    if (!normalizeText(options.minio.endPoint) || !normalizeText(options.minio.accessKey) || !normalizeText(options.minio.secretKey) || !normalizeText(options.minio.bucket)) {
      throw new Error("minio_config_invalid");
    }
    return MinioFileObjectStorage.create(options.minio);
  }
  return DiskFileObjectStorage.create(options.dataDir);
}

class DiskFileObjectStorage implements FileObjectStorage {
  readonly backend = "disk" as const;
  private readonly filesDir: string;

  private constructor(rootDir: string) {
    this.filesDir = join(resolve(rootDir), "files");
  }

  static async create(rootDir: string): Promise<DiskFileObjectStorage> {
    const storage = new DiskFileObjectStorage(rootDir);
    await mkdir(storage.filesDir, { recursive: true });
    return storage;
  }

  async storeFile(sourcePath: string, targetObjectKey: string): Promise<StoredFileDescriptor> {
    const normalizedKey = targetObjectKey.replace(/^\/+/, "");
    const finalPath = join(this.filesDir, normalizedKey);
    await mkdir(dirname(finalPath), { recursive: true });
    await rename(sourcePath, finalPath);
    return {
      storageBackend: this.backend,
      storageKey: normalizedKey,
      storagePath: finalPath,
    };
  }

  async openDownload(record: FileTransferRecord): Promise<FileDownloadSource> {
    return {
      stream: createReadStream(record.storagePath),
      contentLength: record.sizeBytes,
    };
  }

  async deleteObject(record: FileTransferRecord): Promise<void> {
    if (!record.storagePath) {
      return;
    }
    await rm(record.storagePath, { force: true });
  }
}

class MinioFileObjectStorage implements FileObjectStorage {
  readonly backend = "minio" as const;
  private readonly client: MinioClient;

  private constructor(
    client: MinioClient,
    private readonly bucket: string,
    private readonly region?: string,
  ) {
    this.client = client;
  }

  static async create(config: NonNullable<FileTransferStoreOptions["minio"]>): Promise<MinioFileObjectStorage> {
    const client = new MinioClient({
      endPoint: config.endPoint,
      port: config.port,
      useSSL: config.useSSL,
      accessKey: config.accessKey,
      secretKey: config.secretKey,
      region: config.region,
    });

    const storage = new MinioFileObjectStorage(client, config.bucket, config.region);
    await storage.ensureBucket();
    return storage;
  }

  async storeFile(sourcePath: string, targetObjectKey: string, record: FileTransferRecord): Promise<StoredFileDescriptor> {
    const metaData: Record<string, string> = {
      "Content-Type": record.mimeType || "application/octet-stream",
      "X-Amz-Meta-File-Id": record.fileId,
      "X-Amz-Meta-Gateway-Id": record.gatewayId,
      "X-Amz-Meta-Session-Key": record.sessionKey,
    };
    await this.client.fPutObject(this.bucket, targetObjectKey, sourcePath, metaData);
    await rm(sourcePath, { force: true });
    return {
      storageBackend: this.backend,
      storageBucket: this.bucket,
      storageKey: targetObjectKey,
      storagePath: buildStorageUri(this.bucket, targetObjectKey),
    };
  }

  async openDownload(record: FileTransferRecord): Promise<FileDownloadSource> {
    if (!record.storageKey) {
      throw new Error("storage_key_missing");
    }
    const bucket = record.storageBucket ?? this.bucket;
    const stream = await this.client.getObject(bucket, record.storageKey);
    return {
      stream,
      contentLength: record.sizeBytes,
    };
  }

  async deleteObject(record: FileTransferRecord): Promise<void> {
    if (!record.storageKey) {
      return;
    }
    const bucket = record.storageBucket ?? this.bucket;
    try {
      await this.client.removeObject(bucket, record.storageKey);
    } catch (error) {
      if (!isMissingObjectError(error)) {
        throw error;
      }
    }
  }

  private async ensureBucket(): Promise<void> {
    const exists = await this.client.bucketExists(this.bucket);
    if (!exists) {
      await this.client.makeBucket(this.bucket, this.region);
    }
  }
}

function isMissingObjectError(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }
  const code = "code" in error ? String((error as { code?: unknown }).code ?? "") : "";
  return code === "NoSuchKey" || code === "NoSuchObject" || code === "NotFound";
}
