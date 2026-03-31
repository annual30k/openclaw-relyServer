import mysql, { type Pool, type RowDataPacket } from "mysql2/promise";
import type {
  CompleteUploadRecordInput,
  CreateUploadRecordInput,
  FileTransferMetadataStore,
  FileTransferRecord,
  FileTransferStatus,
} from "./types.js";
import { buildStorageUri, normalizeSessionKey, normalizeText, normalizeTimestamp, toIso, toSqlDate } from "./helpers.js";

type FileTransferRow = RowDataPacket & {
  file_id: string;
  upload_id: string | null;
  gateway_id: string;
  session_key: string;
  origin: string;
  uploader_user_id: string | null;
  uploader_device_id: string | null;
  sender_display_name: string | null;
  file_name: string;
  mime_type: string;
  size_bytes: number | string;
  sha256: string;
  status: string;
  storage_backend: string;
  storage_bucket: string | null;
  storage_key: string | null;
  storage_path: string | null;
  download_path: string;
  chunk_size: number;
  total_chunks: number;
  expires_at: string;
  created_at: string;
  updated_at: string;
};

const ACTIVE_STATUSES: FileTransferStatus[] = ["initiated", "uploading", "completed"];

export class MySqlFileTransferMetadataStore implements FileTransferMetadataStore {
  private constructor(private readonly pool: Pool) {}

  static async create(databaseUrl: string): Promise<MySqlFileTransferMetadataStore> {
    const pool = mysql.createPool(databaseUrl);
    return new MySqlFileTransferMetadataStore(pool);
  }

  async createUpload(input: CreateUploadRecordInput): Promise<FileTransferRecord> {
    const createdAt = new Date().toISOString();
    await this.pool.query(
      `
        INSERT INTO file_transfers (
          file_id, upload_id, gateway_id, session_key, origin,
          uploader_user_id, uploader_device_id, sender_display_name,
          file_name, mime_type, size_bytes, sha256, status,
          storage_backend, storage_bucket, storage_key, storage_path,
          download_path, chunk_size, total_chunks, expires_at, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'initiated', ?, NULL, NULL, '', ?, ?, 0, ?, ?, ?)
      `,
      [
        input.fileId,
        input.uploadId,
        input.gatewayId,
        normalizeSessionKey(input.sessionKey),
        input.origin,
        normalizeText(input.uploaderUserId) ?? null,
        normalizeText(input.uploaderDeviceId) ?? null,
        normalizeText(input.senderDisplayName) ?? null,
        input.fileName,
        input.mimeType,
        Math.max(0, Math.floor(input.sizeBytes)),
        input.sha256.toLowerCase(),
        input.storageBackend,
        input.downloadPath,
        Math.max(1, Math.floor(input.chunkSize)),
        toSqlDate(input.expiresAt),
        toSqlDate(createdAt),
        toSqlDate(createdAt),
      ],
    );

    const created = await this.getUpload(input.uploadId);
    if (!created) {
      throw new Error("upload_record_not_created");
    }
    return created;
  }

  async getUpload(uploadId: string): Promise<FileTransferRecord | undefined> {
    const [rows] = await this.pool.query<FileTransferRow[]>(
      "SELECT * FROM file_transfers WHERE upload_id = ? LIMIT 1",
      [uploadId],
    );
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async getFile(fileId: string): Promise<FileTransferRecord | undefined> {
    const [rows] = await this.pool.query<FileTransferRow[]>(
      "SELECT * FROM file_transfers WHERE file_id = ? LIMIT 1",
      [fileId],
    );
    return rows[0] ? mapRow(rows[0]) : undefined;
  }

  async touchUpload(uploadId: string): Promise<void> {
    await this.pool.query(
      `
        UPDATE file_transfers
        SET status = CASE WHEN status = 'initiated' THEN 'uploading' ELSE status END,
            updated_at = ?
        WHERE upload_id = ? AND status IN ('initiated', 'uploading')
      `,
      [toSqlDate(new Date().toISOString()), uploadId],
    );
  }

  async completeUpload(input: CompleteUploadRecordInput): Promise<FileTransferRecord> {
    const completedAt = new Date().toISOString();
    await this.pool.query(
      `
        UPDATE file_transfers
        SET status = 'completed',
            storage_bucket = ?,
            storage_key = ?,
            storage_path = ?,
            total_chunks = ?,
            expires_at = ?,
            updated_at = ?
        WHERE upload_id = ? AND status IN ('initiated', 'uploading')
      `,
      [
        normalizeText(input.storage.storageBucket) ?? null,
        normalizeText(input.storage.storageKey) ?? null,
        input.storage.storagePath,
        Math.max(1, Math.floor(input.totalChunks)),
        toSqlDate(input.expiresAt),
        toSqlDate(completedAt),
        input.uploadId,
      ],
    );

    const updated = await this.getUpload(input.uploadId);
    if (!updated) {
      throw new Error("upload_record_not_found");
    }
    return updated;
  }

  async listVisibleCompletedFiles(gatewayId: string, sessionKey: string | undefined, viewerUserId: string): Promise<FileTransferRecord[]> {
    const params: Array<string> = [gatewayId];
    const clauses = ["gateway_id = ?", "status = 'completed'", "(uploader_user_id IS NULL OR uploader_user_id = ?)"];
    params.push(viewerUserId);
    if (sessionKey) {
      clauses.splice(1, 0, "session_key = ?");
      params.splice(1, 0, normalizeSessionKey(sessionKey));
    }
    const [rows] = await this.pool.query<FileTransferRow[]>(
      `SELECT * FROM file_transfers WHERE ${clauses.join(" AND ")} ORDER BY created_at ASC`,
      params,
    );
    return rows.map(mapRow);
  }

  async listExpiredActiveFiles(now: Date): Promise<FileTransferRecord[]> {
    const [rows] = await this.pool.query<FileTransferRow[]>(
      `
        SELECT *
        FROM file_transfers
        WHERE status IN (${ACTIVE_STATUSES.map(() => "?").join(", ")})
          AND expires_at <= ?
        ORDER BY expires_at ASC
      `,
      [...ACTIVE_STATUSES, toSqlDate(now.toISOString())],
    );
    return rows.map(mapRow);
  }

  async markExpired(fileId: string): Promise<void> {
    await this.updateStatus(fileId, "expired");
  }

  async markDeleted(fileId: string): Promise<boolean> {
    const [result] = await this.pool.query(
      `
        UPDATE file_transfers
        SET status = 'deleted', updated_at = ?
        WHERE file_id = ? AND status <> 'deleted'
      `,
      [toSqlDate(new Date().toISOString()), fileId],
    );
    const affectedRows = "affectedRows" in result ? Number(result.affectedRows ?? 0) : 0;
    return affectedRows > 0;
  }

  private async updateStatus(fileId: string, status: Extract<FileTransferStatus, "expired" | "deleted" | "failed" | "canceled">): Promise<void> {
    await this.pool.query(
      "UPDATE file_transfers SET status = ?, updated_at = ? WHERE file_id = ?",
      [status, toSqlDate(new Date().toISOString()), fileId],
    );
  }
}

function mapRow(row: FileTransferRow): FileTransferRecord {
  const storageKey = normalizeText(row.storage_key);
  const storageBucket = normalizeText(row.storage_bucket);
  const storagePath = normalizeText(row.storage_path) ?? buildStorageUri(storageBucket, storageKey);

  return {
    fileId: row.file_id,
    uploadId: normalizeText(row.upload_id),
    gatewayId: row.gateway_id,
    sessionKey: normalizeSessionKey(row.session_key),
    fileName: row.file_name,
    mimeType: row.mime_type,
    sizeBytes: Math.max(0, Math.floor(Number(row.size_bytes) || 0)),
    sha256: row.sha256.toLowerCase(),
    origin: row.origin === "mobile" ? "mobile" : "host",
    uploaderUserId: normalizeText(row.uploader_user_id),
    uploaderDeviceId: normalizeText(row.uploader_device_id),
    senderDisplayName: normalizeText(row.sender_display_name),
    createdAt: normalizeTimestamp(toIso(row.created_at) ?? new Date().toISOString()),
    updatedAt: normalizeTimestamp(toIso(row.updated_at) ?? new Date().toISOString()),
    expiresAt: normalizeTimestamp(toIso(row.expires_at) ?? new Date().toISOString()),
    status: normalizeStatus(row.status),
    storageBackend: row.storage_backend === "minio" ? "minio" : "disk",
    storageBucket,
    storageKey,
    storagePath,
    downloadPath: row.download_path,
    chunkSize: Math.max(1, Math.floor(Number(row.chunk_size) || 1)),
    totalChunks: Math.max(0, Math.floor(Number(row.total_chunks) || 0)),
  };
}

function normalizeStatus(value: string): FileTransferStatus {
  switch (value) {
    case "initiated":
    case "uploading":
    case "completed":
    case "failed":
    case "canceled":
    case "expired":
    case "deleted":
      return value;
    default:
      return "failed";
  }
}
