import assert from "node:assert/strict";
import test from "node:test";
import { buildFileContentBlock, canAccessFileTransfer } from "./file-formatters.js";
import type { FileTransferRecord } from "./types.js";

test("file formatters build chat payloads and enforce ownership", () => {
  const record: FileTransferRecord = {
    fileId: "file_1",
    gatewayId: "gw_1",
    sessionKey: "main",
    fileName: "hello.txt",
    mimeType: "text/plain",
    sizeBytes: 1,
    sha256: "abc",
    origin: "host",
    createdAt: "2024-01-01T00:00:00.000Z",
    sortTimestampMs: Date.parse("2024-01-01T00:00:00.000Z"),
    updatedAt: "2024-01-01T00:00:00.000Z",
    expiresAt: "2024-01-02T00:00:00.000Z",
    status: "completed",
    storageBackend: "disk",
    storagePath: "/tmp/hello.txt",
    downloadPath: "/api/mobile/files/file_1",
    chunkSize: 1,
    totalChunks: 1,
    uploaderUserId: "user_1",
  };

  const block = buildFileContentBlock(record);
  assert.equal(block.fileId, "file_1");
  assert.equal(canAccessFileTransfer(record, "user_1"), true);
  assert.equal(canAccessFileTransfer(record, "user_2"), false);
});
