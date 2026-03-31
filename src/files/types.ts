import type { Readable } from "stream";

export type FileTransferOrigin = "host" | "mobile";
export type FileTransferStatus = "initiated" | "uploading" | "completed" | "failed" | "canceled" | "expired" | "deleted";
export type FileStorageBackend = "disk" | "minio";

export interface FileUploadSessionInfo {
  gatewayId: string;
  sessionKey: string;
  origin: FileTransferOrigin;
}

export interface FileTransferInitInput {
  gatewayId: string;
  sessionKey: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  origin: FileTransferOrigin;
  uploaderUserId?: string;
  uploaderDeviceId?: string;
  senderDisplayName?: string;
}

export interface FileTransferInitResult {
  fileId: string;
  uploadId: string;
  chunkSize: number;
  expiresAt: string;
  uploadUrl: string;
}

export interface FileTransferRecord {
  fileId: string;
  uploadId?: string;
  gatewayId: string;
  sessionKey: string;
  fileName: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  origin: FileTransferOrigin;
  uploaderUserId?: string;
  uploaderDeviceId?: string;
  senderDisplayName?: string;
  createdAt: string;
  updatedAt: string;
  expiresAt: string;
  status: FileTransferStatus;
  storageBackend: FileStorageBackend;
  storageBucket?: string;
  storageKey?: string;
  storagePath: string;
  downloadPath: string;
  chunkSize: number;
  totalChunks: number;
}

export interface FileTransferStoreOptions {
  dataDir: string;
  databaseUrl: string;
  chunkSizeBytes: number;
  uploadTtlMs: number;
  fileTtlMs: number;
  storageBackend: FileStorageBackend;
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

export interface StoredFileDescriptor {
  storageBackend: FileStorageBackend;
  storageBucket?: string;
  storageKey?: string;
  storagePath: string;
}

export interface FileDownloadSource {
  stream: Readable;
  contentLength: number;
}

export interface CreateUploadRecordInput extends FileTransferInitInput {
  fileId: string;
  uploadId: string;
  chunkSize: number;
  expiresAt: string;
  downloadPath: string;
  storageBackend: FileStorageBackend;
}

export interface CompleteUploadRecordInput {
  uploadId: string;
  storage: StoredFileDescriptor;
  totalChunks: number;
  expiresAt: string;
}

export interface FileTransferMetadataStore {
  createUpload(input: CreateUploadRecordInput): Promise<FileTransferRecord>;
  getUpload(uploadId: string): Promise<FileTransferRecord | undefined>;
  getFile(fileId: string): Promise<FileTransferRecord | undefined>;
  touchUpload(uploadId: string): Promise<void>;
  completeUpload(input: CompleteUploadRecordInput): Promise<FileTransferRecord>;
  listVisibleCompletedFiles(gatewayId: string, sessionKey: string | undefined, viewerUserId: string): Promise<FileTransferRecord[]>;
  listFilesForGatewayCleanup(gatewayId: string): Promise<FileTransferRecord[]>;
  listExpiredActiveFiles(now: Date): Promise<FileTransferRecord[]>;
  markExpired(fileId: string): Promise<void>;
  markDeleted(fileId: string): Promise<boolean>;
}
