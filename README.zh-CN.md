# PocketClaw 中继站

这是 PocketClaw Relay Server 的中文说明文档，对应实现位于 `relay-server/`。

## 当前能力

- 主机注册
- 配对码刷新
- 移动端配对
- 主机端与移动端 WebSocket 接入
- 命令转发、事件回传、在线态聚合
- 技能状态查询与写回主机端
- 高危命令审批
- 审计日志
- MySQL 8.4 LTS 持久化
- 文件互传元数据持久化
- 本地磁盘或 MinIO 对象存储文件本体
- Docker / Docker Compose 部署

## 目录说明

- 服务入口：`src/index.ts`
- 存储层：`src/store.ts`
- 风险分级：`src/risk.ts`
- 安全工具：`src/security.ts`
- 配置：`src/config.ts`
- Docker 编排：`docker-compose.yml`
- MySQL 初始化脚本：`mysql/init/001_schema.sql`

## 本地开发

先安装依赖：

```bash
npm install
```

本地直接运行：

```bash
npm run dev
```

构建：

```bash
npm run build
```

## Docker 启动

在 `relay-server/` 目录下执行：

```bash
docker compose up -d --build
```

启动后会包含三个服务：

- `relay-api`
- `mysql:8.4.8`
- `minio`

如果测试环境是从 MySQL 5.7 切到 8.4，请直接重建 MySQL 容器和数据库 volume，不要复用旧的 5.7 数据目录。

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

## MySQL 配置

默认连接信息：

- Host: `127.0.0.1`
- Port: `3306`
- Database: `pocketclaw_relay`
- User: `pocketclaw`
- Password: `pocketclaw123`

环境变量示例见：`.env.example`

关键变量：

- `DATABASE_URL`
- `JWT_SECRET`
- `PORT`
- `HOST`
- `ACCESS_CODE_TTL_SECONDS`
- `HEARTBEAT_INTERVAL_MS`
- `WS_IDLE_TIMEOUT_MS`
- `APPROVAL_TTL_SECONDS`
- `RATE_LIMIT_WINDOW_MS`
- `RATE_LIMIT_MAX`
- `AUTH_TOKEN_TTL_SECONDS`
- `FILE_STORAGE_DRIVER`
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

## 自动创建的表

`mysql/init/001_schema.sql` 会自动创建：

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

`DATA_DIR` 仍然用于上传分块的临时目录。完成上传后的文件本体可落本地磁盘，也可落到 MinIO；文件元数据统一存 MySQL。

## HTTP 接口

- `POST /api/relay/register`
- `POST /api/relay/access-code`
- `POST /api/relay/accesscode`
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

## WebSocket 地址

Host Agent：

- `/relay/ws?gatewayId=...&secret=...`
- 兼容旧路径：`/relay/:gatewayId?secret=...`

Mobile：

- `/mobile/ws?accessToken=...`

## 当前实现说明

当前版本已经正式使用 MySQL 8.4 LTS 做持久化，不再依赖本地 JSON 文件作为主存储。文件互传的完成态元数据也落 MySQL，文件本体可走本地磁盘或 MinIO。

已经验证通过的流程：

- 注册主机后写入 `gateways`、`gateway_pairing_codes`
- 移动端配对后写入 `users`、`mobile_devices`、`gateway_memberships`
- 服务容器启动时可正常连接 MySQL

## 适用场景

当前版本适合：

- 本地开发
- 局域网联调
- 单机测试环境

如果要用于正式生产，建议继续补：

- 真正的用户认证体系
- 更细粒度的 `relay_sessions` 持久化
- Redis 在线态 / 控制权协调
- Prometheus / Grafana / Loki
- Nginx / TLS / 反向代理
- 多实例部署支持
