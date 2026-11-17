-- 000001_init.up.sql
-- Tools BPBJ — initial schema (7 tables).
-- Conventions: InnoDB; utf8mb4/utf8mb4_unicode_ci; BIGINT UNSIGNED PK;
-- DATETIME(3) UTC; enums stored as VARCHAR; soft delete only on `tools`.
-- See docs/database-design.md.

-- ---------------------------------------------------------------------------
-- admins
-- ---------------------------------------------------------------------------
CREATE TABLE `admins` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username`      VARCHAR(64)     NOT NULL,
    `password_hash` VARCHAR(255)    NOT NULL,
    `role`          VARCHAR(32)     NOT NULL DEFAULT 'superadmin',
    `is_active`     TINYINT(1)      NOT NULL DEFAULT 1,
    `last_login_at` DATETIME(3)     NULL,
    `created_at`    DATETIME(3)     NOT NULL,
    `updated_at`    DATETIME(3)     NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_admins_username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- admin_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE `admin_sessions` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `admin_id`           BIGINT UNSIGNED NOT NULL,
    `session_token_hash` VARCHAR(255)    NOT NULL,
    `csrf_token`         VARCHAR(255)    NOT NULL,
    `ip_address`         VARCHAR(45)     NULL,
    `user_agent`         VARCHAR(512)    NULL,
    `expires_at`         DATETIME(3)     NOT NULL,
    `created_at`         DATETIME(3)     NOT NULL,
    `revoked_at`         DATETIME(3)     NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_admin_sessions_session_token_hash` (`session_token_hash`),
    KEY `idx_admin_sessions_admin_id` (`admin_id`),
    KEY `idx_admin_sessions_expires_at` (`expires_at`),
    CONSTRAINT `fk_admin_sessions_admin`
        FOREIGN KEY (`admin_id`) REFERENCES `admins` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- tools
-- ---------------------------------------------------------------------------
CREATE TABLE `tools` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `slug`                VARCHAR(64)     NOT NULL,
    `name`                VARCHAR(128)    NOT NULL,
    `description`         VARCHAR(512)    NULL,
    `category`            VARCHAR(64)     NULL,
    `version`             VARCHAR(32)     NULL,
    `runtime`             VARCHAR(32)     NULL,
    `access_type`         VARCHAR(16)     NOT NULL DEFAULT 'public',
    `upstream_url`        VARCHAR(255)    NOT NULL,
    `healthcheck_path`    VARCHAR(128)    NOT NULL DEFAULT '/health',
    `status`              VARCHAR(16)     NOT NULL DEFAULT 'draft',
    `maintenance_message` VARCHAR(512)    NULL,
    `manifest_json`       JSON            NULL,
    `display_order`       INT             NOT NULL DEFAULT 0,
    `created_at`          DATETIME(3)     NOT NULL,
    `updated_at`          DATETIME(3)     NOT NULL,
    `deleted_at`          DATETIME(3)     NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_tools_slug` (`slug`),
    KEY `idx_tools_status` (`status`),
    KEY `idx_tools_category` (`category`),
    KEY `idx_tools_deleted_at` (`deleted_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- access_tokens  (expires_at is MANDATORY / NOT NULL)
-- ---------------------------------------------------------------------------
CREATE TABLE `access_tokens` (
    `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `tool_id`             BIGINT UNSIGNED NOT NULL,
    `token_hash`          VARCHAR(255)    NOT NULL,
    `token_prefix`        VARCHAR(16)     NOT NULL,
    `recipient_label`     VARCHAR(128)    NULL,
    `expires_at`          DATETIME(3)     NOT NULL,
    `revoked_at`          DATETIME(3)     NULL,
    `created_by_admin_id` BIGINT UNSIGNED NOT NULL,
    `last_used_at`        DATETIME(3)     NULL,
    `created_at`          DATETIME(3)     NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_access_tokens_token_hash` (`token_hash`),
    KEY `idx_access_tokens_tool_id` (`tool_id`),
    KEY `idx_access_tokens_expires_at` (`expires_at`),
    KEY `idx_access_tokens_revoked_at` (`revoked_at`),
    CONSTRAINT `fk_access_tokens_tool`
        FOREIGN KEY (`tool_id`) REFERENCES `tools` (`id`) ON DELETE RESTRICT,
    CONSTRAINT `fk_access_tokens_created_by_admin`
        FOREIGN KEY (`created_by_admin_id`) REFERENCES `admins` (`id`) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- tool_access_sessions
-- ---------------------------------------------------------------------------
CREATE TABLE `tool_access_sessions` (
    `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `tool_id`            BIGINT UNSIGNED NOT NULL,
    `access_token_id`    BIGINT UNSIGNED NOT NULL,
    `session_token_hash` VARCHAR(255)    NOT NULL,
    `ip_address`         VARCHAR(45)     NULL,
    `user_agent`         VARCHAR(512)    NULL,
    `expires_at`         DATETIME(3)     NOT NULL,
    `created_at`         DATETIME(3)     NOT NULL,
    `revoked_at`         DATETIME(3)     NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_tool_access_sessions_session_token_hash` (`session_token_hash`),
    KEY `idx_tool_access_sessions_tool_id` (`tool_id`),
    KEY `idx_tool_access_sessions_access_token_id` (`access_token_id`),
    KEY `idx_tool_access_sessions_expires_at` (`expires_at`),
    CONSTRAINT `fk_tool_access_sessions_tool`
        FOREIGN KEY (`tool_id`) REFERENCES `tools` (`id`) ON DELETE CASCADE,
    CONSTRAINT `fk_tool_access_sessions_access_token`
        FOREIGN KEY (`access_token_id`) REFERENCES `access_tokens` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- activity_logs
-- ---------------------------------------------------------------------------
CREATE TABLE `activity_logs` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `actor_type`    VARCHAR(16)     NOT NULL,
    `actor_id`      BIGINT UNSIGNED NULL,
    `action`        VARCHAR(64)     NOT NULL,
    `entity_type`   VARCHAR(32)     NULL,
    `entity_id`     BIGINT UNSIGNED NULL,
    `tool_id`       BIGINT UNSIGNED NULL,
    `ip_address`    VARCHAR(45)     NULL,
    `user_agent`    VARCHAR(512)    NULL,
    `metadata_json` JSON            NULL,
    `created_at`    DATETIME(3)     NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_activity_logs_created_at` (`created_at`),
    KEY `idx_activity_logs_tool_id` (`tool_id`),
    KEY `idx_activity_logs_actor` (`actor_type`, `actor_id`),
    CONSTRAINT `fk_activity_logs_tool`
        FOREIGN KEY (`tool_id`) REFERENCES `tools` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- tool_health_checks
-- ---------------------------------------------------------------------------
CREATE TABLE `tool_health_checks` (
    `id`               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `tool_id`          BIGINT UNSIGNED NOT NULL,
    `status`           VARCHAR(16)     NOT NULL,
    `http_status_code` INT             NULL,
    `latency_ms`       INT             NULL,
    `checked_at`       DATETIME(3)     NOT NULL,
    `error_message`    VARCHAR(512)    NULL,
    PRIMARY KEY (`id`),
    KEY `idx_tool_health_checks_tool_checked` (`tool_id`, `checked_at`),
    KEY `idx_tool_health_checks_checked_at` (`checked_at`),
    CONSTRAINT `fk_tool_health_checks_tool`
        FOREIGN KEY (`tool_id`) REFERENCES `tools` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
