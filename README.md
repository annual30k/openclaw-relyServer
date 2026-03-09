# PocketClaw Relay Server

MVP relay server that implements the development contract in `docs/relay-development-deployment.md`.

## Features

- Host registration and access code refresh
- Mobile pairing and gateway membership
- Host and mobile WebSocket entrypoints
- Command routing, event fan-out, and response relay
- Presence aggregation, sensitive-action approval, and audit logging
- File-backed persistence for local development
- Docker and Docker Compose support
- MySQL 5.7 service and schema bootstrap for deployment

## Run

```bash
npm install
npm run dev
```

## Docker Compose

```bash
docker compose up -d --build
```

`docker-compose.yml` now starts:

- `relay-api`
- `mysql:5.7`

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

Current status: the application persistence layer uses MySQL 5.7 through `DATABASE_URL`. `DATA_DIR` remains only as an optional local artifact directory.

## Endpoints

- `POST /api/relay/register`
- `POST /api/relay/access-code`
- `POST /api/relay/accesscode` (compat)
- `POST /api/mobile/pair`
- `GET /api/mobile/gateways`
- `GET /api/mobile/gateways/:gatewayId`
- `DELETE /api/mobile/gateways/:gatewayId`
- `POST /api/mobile/gateways/:gatewayId/approve-sensitive-action`
- `GET /healthz`
- `GET /metrics`

## WebSocket

- Host: `/relay/ws?gatewayId=...&secret=...`
- Host compat: `/relay/:gatewayId?secret=...`
- Mobile: `/mobile/ws?accessToken=...`
