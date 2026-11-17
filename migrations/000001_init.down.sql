-- 000001_init.down.sql
-- Reverses 000001_init.up.sql. Drops tables in dependency-safe order:
-- children before parents (reverse of creation order).

DROP TABLE IF EXISTS `tool_health_checks`;
DROP TABLE IF EXISTS `activity_logs`;
DROP TABLE IF EXISTS `tool_access_sessions`;
DROP TABLE IF EXISTS `access_tokens`;
DROP TABLE IF EXISTS `tools`;
DROP TABLE IF EXISTS `admin_sessions`;
DROP TABLE IF EXISTS `admins`;
