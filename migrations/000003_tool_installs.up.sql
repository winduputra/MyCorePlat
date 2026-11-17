-- 000003_tool_installs
-- Installation history / lifecycle state for tools deployed by the Dynamic
-- Tool Installer.
--
-- Why a table: the installer builds an image, starts a container and registers
-- the tool. Each of those steps needs a durable record so that a failed install
-- can be rolled back, an update can be traced, and an uninstall can find the
-- image/container it must tear down. The `tools` table stays the runtime
-- source of truth for status/access/upstream; this table is the deployment
-- bookkeeping.
--
-- No secret material is ever stored here: HMAC secrets live in the per-tool
-- key file on disk and are never persisted in the database.

CREATE TABLE tool_installs (
    id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tool_id              BIGINT UNSIGNED NULL,
    slug                 VARCHAR(64)     NOT NULL,
    status               VARCHAR(32)     NOT NULL,
    version              VARCHAR(32)     NULL,
    image_tag            VARCHAR(255)    NULL,
    container_name       VARCHAR(128)    NULL,
    package_sha256       CHAR(64)        NULL,
    error_code           VARCHAR(64)     NULL,
    error_message        VARCHAR(512)    NULL,
    installed_by_admin_id BIGINT UNSIGNED NULL,
    created_at           DATETIME(3)     NOT NULL,
    updated_at           DATETIME(3)     NOT NULL,
    PRIMARY KEY (id),
    KEY idx_tool_installs_slug (slug),
    KEY idx_tool_installs_status (status),
    KEY idx_tool_installs_tool_id (tool_id),
    CONSTRAINT fk_tool_installs_tool FOREIGN KEY (tool_id) REFERENCES tools (id) ON DELETE SET NULL,
    CONSTRAINT fk_tool_installs_admin FOREIGN KEY (installed_by_admin_id) REFERENCES admins (id) ON DELETE RESTRICT
) ENGINE = InnoDB
  DEFAULT CHARSET = utf8mb4
  COLLATE = utf8mb4_unicode_ci;
