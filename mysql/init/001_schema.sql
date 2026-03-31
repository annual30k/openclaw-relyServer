CREATE DATABASE IF NOT EXISTS pocketclaw_relay
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE pocketclaw_relay;

CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(64) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password_hash TEXT NOT NULL,
  name VARCHAR(191) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mobile_devices (
  id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  platform VARCHAR(32) NOT NULL,
  app_version VARCHAR(64) DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_mobile_devices_user_id (user_id),
  CONSTRAINT fk_mobile_devices_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gateways (
  id VARCHAR(64) NOT NULL,
  owner_user_id VARCHAR(64) DEFAULT NULL,
  gateway_code VARCHAR(64) NOT NULL,
  relay_secret_hash VARCHAR(128) NOT NULL,
  display_name VARCHAR(191) NOT NULL,
  platform VARCHAR(32) NOT NULL,
  agent_version VARCHAR(64) NOT NULL,
  openclaw_version VARCHAR(64) DEFAULT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'offline',
  last_seen_at DATETIME DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_gateways_gateway_code (gateway_code),
  KEY idx_gateways_owner_user_id (owner_user_id),
  CONSTRAINT fk_gateways_owner
    FOREIGN KEY (owner_user_id) REFERENCES users (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gateway_pairing_codes (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gateway_id VARCHAR(64) NOT NULL,
  access_code_hash VARCHAR(128) NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_gateway_pairing_codes_gateway_id (gateway_id),
  KEY idx_gateway_pairing_codes_expires_at (expires_at),
  CONSTRAINT fk_gateway_pairing_codes_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gateway_memberships (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gateway_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  role VARCHAR(16) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_gateway_memberships_gateway_user (gateway_id, user_id),
  KEY idx_gateway_memberships_user_id (user_id),
  CONSTRAINT fk_gateway_memberships_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_gateway_memberships_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS relay_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id VARCHAR(128) NOT NULL,
  gateway_id VARCHAR(64) DEFAULT NULL,
  user_id VARCHAR(64) DEFAULT NULL,
  device_id VARCHAR(64) DEFAULT NULL,
  session_type VARCHAR(16) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'connected',
  remote_addr VARCHAR(128) DEFAULT NULL,
  connected_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  disconnected_at DATETIME DEFAULT NULL,
  last_seen_at DATETIME DEFAULT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_relay_sessions_session_id (session_id),
  KEY idx_relay_sessions_gateway_id (gateway_id),
  KEY idx_relay_sessions_user_id (user_id),
  CONSTRAINT fk_relay_sessions_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE SET NULL,
  CONSTRAINT fk_relay_sessions_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gateway_runtime_state (
  gateway_id VARCHAR(64) NOT NULL,
  relay_status VARCHAR(32) NOT NULL DEFAULT 'offline',
  host_status VARCHAR(32) NOT NULL DEFAULT 'offline',
  openclaw_status VARCHAR(32) NOT NULL DEFAULT 'offline',
  aggregate_status VARCHAR(32) NOT NULL DEFAULT 'offline',
  current_model VARCHAR(128) DEFAULT NULL,
  context_usage INT DEFAULT NULL,
  context_limit INT DEFAULT NULL,
  controller_user_id VARCHAR(64) DEFAULT NULL,
  controller_device_id VARCHAR(64) DEFAULT NULL,
  mobile_control_status VARCHAR(32) NOT NULL DEFAULT 'idle',
  last_seen_at DATETIME DEFAULT NULL,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (gateway_id),
  KEY idx_gateway_runtime_state_controller_user_id (controller_user_id),
  CONSTRAINT fk_gateway_runtime_state_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_gateway_runtime_state_controller_user
    FOREIGN KEY (controller_user_id) REFERENCES users (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS gateway_tasks (
  id VARCHAR(64) NOT NULL,
  gateway_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  title VARCHAR(191) NOT NULL,
  prompt LONGTEXT NOT NULL,
  schedule_kind VARCHAR(16) NOT NULL,
  schedule_at DATETIME DEFAULT NULL,
  repeat_amount INT DEFAULT NULL,
  repeat_unit VARCHAR(16) DEFAULT NULL,
  enabled TINYINT(1) NOT NULL DEFAULT 1,
  last_result LONGTEXT NOT NULL,
  next_run_at DATETIME DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_gateway_tasks_gateway_id (gateway_id),
  KEY idx_gateway_tasks_user_id (user_id),
  KEY idx_gateway_tasks_next_run_at (next_run_at),
  KEY idx_gateway_tasks_enabled_next_run_at (enabled, next_run_at),
  CONSTRAINT fk_gateway_tasks_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_gateway_tasks_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS command_audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gateway_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  method VARCHAR(128) NOT NULL,
  risk_level VARCHAR(8) NOT NULL,
  params_masked LONGTEXT NOT NULL,
  result_ok TINYINT(1) NOT NULL DEFAULT 0,
  error_code VARCHAR(64) DEFAULT NULL,
  duration_ms INT NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_command_audit_logs_gateway_id (gateway_id),
  KEY idx_command_audit_logs_user_id (user_id),
  KEY idx_command_audit_logs_created_at (created_at),
  CONSTRAINT fk_command_audit_logs_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_command_audit_logs_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS api_tokens (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id VARCHAR(64) NOT NULL,
  device_id VARCHAR(64) DEFAULT NULL,
  token_hash VARCHAR(128) NOT NULL,
  token_type VARCHAR(32) NOT NULL DEFAULT 'access',
  expires_at DATETIME DEFAULT NULL,
  revoked_at DATETIME DEFAULT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_api_tokens_token_hash (token_hash),
  KEY idx_api_tokens_user_id (user_id),
  CONSTRAINT fk_api_tokens_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS approvals (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  gateway_id VARCHAR(64) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  method VARCHAR(128) NOT NULL,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_approvals_gateway_user_method (gateway_id, user_id, method),
  KEY idx_approvals_expires_at (expires_at),
  CONSTRAINT fk_approvals_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_approvals_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS file_transfers (
  file_id VARCHAR(64) NOT NULL,
  upload_id VARCHAR(64) DEFAULT NULL,
  gateway_id VARCHAR(64) NOT NULL,
  session_key VARCHAR(128) NOT NULL,
  origin VARCHAR(16) NOT NULL,
  uploader_user_id VARCHAR(64) DEFAULT NULL,
  uploader_device_id VARCHAR(64) DEFAULT NULL,
  sender_display_name VARCHAR(191) DEFAULT NULL,
  file_name VARCHAR(255) NOT NULL,
  mime_type VARCHAR(255) NOT NULL,
  size_bytes BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  storage_backend VARCHAR(16) NOT NULL DEFAULT 'disk',
  storage_bucket VARCHAR(191) DEFAULT NULL,
  storage_key VARCHAR(512) DEFAULT NULL,
  storage_path VARCHAR(1024) DEFAULT NULL,
  download_path VARCHAR(255) NOT NULL,
  chunk_size INT UNSIGNED NOT NULL DEFAULT 0,
  total_chunks INT UNSIGNED NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (file_id),
  UNIQUE KEY uk_file_transfers_upload_id (upload_id),
  KEY idx_file_transfers_gateway_session (gateway_id, session_key),
  KEY idx_file_transfers_gateway_status_created_at (gateway_id, status, created_at),
  KEY idx_file_transfers_gateway_session_status_created_at (gateway_id, session_key, status, created_at),
  KEY idx_file_transfers_uploader_user_id (uploader_user_id),
  KEY idx_file_transfers_status_expires_at (status, expires_at),
  CONSTRAINT fk_file_transfers_gateway
    FOREIGN KEY (gateway_id) REFERENCES gateways (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_file_transfers_uploader_user
    FOREIGN KEY (uploader_user_id) REFERENCES users (id)
    ON DELETE SET NULL,
  CONSTRAINT fk_file_transfers_uploader_device
    FOREIGN KEY (uploader_device_id) REFERENCES mobile_devices (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
