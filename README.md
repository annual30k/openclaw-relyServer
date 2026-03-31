# PocketClaw Relay Server

MVP relay server that implements the development contract in `docs/relay-development-deployment.md`.

## Features

- Host registration and access code refresh
- Mobile pairing and gateway membership
- Host and mobile WebSocket entrypoints
- Command routing, event fan-out, and response relay
- Skills status lookup and write-back to the host gateway
- Presence aggregation, sensitive-action approval, and audit logging
- MySQL-backed relay state and file transfer metadata
- Pluggable file transfer storage with local disk or MinIO object storage
- Docker and Docker Compose support

## Run

```bash
npm install
npm run dev
```

File transfer defaults to local disk unless `FILE_STORAGE_DRIVER=minio` is configured.

## Docker Compose

```bash
docker compose up -d --build
```

`docker-compose.yml` now starts:

- `relay-api`
- `mysql:8.4.8`
- `minio`

If you are switching a test environment from MySQL 5.7 to 8.4, rebuild the MySQL container with a fresh database volume instead of reusing the old 5.7 data directory.

MySQL init SQL lives in `mysql/init/001_schema.sql` and automatically creates the database and these tables:

- `users`
- `mobile_devices`
- `gateways`
- `gateway_pairing_codes`
- `gateway_memberships`
- `relay_sessions`
- `gateway_runtime_state`
- `command_audit_logs`
- `api_tokens`
- `approvals`
- `file_transfers`

`DATA_DIR` is still required for temporary chunk staging. Completed file bodies are stored either on local disk or in MinIO, while metadata lives in MySQL.

## Storage Configuration

- `FILE_STORAGE_DRIVER=disk|minio`
- `FILE_CHUNK_SIZE_BYTES`
- `FILE_UPLOAD_TTL_SECONDS`
- `FILE_TTL_SECONDS`
- `MINIO_ENDPOINT`
- `MINIO_PORT`
- `MINIO_USE_SSL`
- `MINIO_ACCESS_KEY`
- `MINIO_SECRET_KEY`
- `MINIO_BUCKET`
- `MINIO_REGION`

## Endpoints

- `POST /api/relay/register`
- `POST /api/relay/access-code`
- `POST /api/relay/accesscode` (compat)
- `POST /api/mobile/pair`
- `GET /api/mobile/gateways`
- `GET /api/mobile/gateways/:gatewayId`
- `DELETE /api/mobile/gateways/:gatewayId`
- `GET /api/mobile/gateways/:gatewayId/skills`
- `PATCH /api/mobile/gateways/:gatewayId/skills/:skillKey`
- `POST /api/mobile/gateways/:gatewayId/approve-sensitive-action`
- `POST /api/host/gateways/:gatewayId/files/init`
- `PUT /api/host/files/:uploadId/chunks/:index`
- `POST /api/host/files/:uploadId/complete`
- `POST /api/mobile/gateways/:gatewayId/files/init`
- `PUT /api/mobile/files/:uploadId/chunks/:index`
- `POST /api/mobile/files/:uploadId/complete`
- `GET /api/mobile/files/:fileId`
- `GET /healthz`
- `GET /metrics`

## WebSocket

- Host: `/relay/ws?gatewayId=...&secret=...`
- Host compat: `/relay/:gatewayId?secret=...`
- Mobile: `/mobile/ws?accessToken=...`
