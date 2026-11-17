package model

import "time"

// Actor types recorded in activity_logs.actor_type.
const (
	ActorTypeAdmin  = "admin"
	ActorTypeSystem = "system"
)

// ActivityLog maps the append-only activity_logs audit table.
//
// Rows are never updated or deleted by the application. The table deliberately
// stores metadata only: no tokens, session identifiers, cookies, passwords,
// authorization headers, request bodies or file contents ever belong here
// (see docs/security-design.md §12).
type ActivityLog struct {
	ID           uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ActorType    string    `gorm:"column:actor_type"`
	ActorID      *uint64   `gorm:"column:actor_id"`
	Action       string    `gorm:"column:action"`
	EntityType   *string   `gorm:"column:entity_type"`
	EntityID     *uint64   `gorm:"column:entity_id"`
	ToolID       *uint64   `gorm:"column:tool_id"`
	IPAddress    *string   `gorm:"column:ip_address"`
	UserAgent    *string   `gorm:"column:user_agent"`
	MetadataJSON *string   `gorm:"column:metadata_json"`
	CreatedAt    time.Time `gorm:"column:created_at"`
}

// TableName pins the model to the migrated table name.
func (ActivityLog) TableName() string { return "activity_logs" }

// Tool health check statuses recorded in tool_health_checks.status.
const (
	HealthStatusHealthy   = "healthy"
	HealthStatusUnhealthy = "unhealthy"
)

// ToolHealthCheck maps tool_health_checks: one row per completed probe.
type ToolHealthCheck struct {
	ID             uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ToolID         uint64    `gorm:"column:tool_id"`
	Status         string    `gorm:"column:status"`
	HTTPStatusCode *int      `gorm:"column:http_status_code"`
	LatencyMS      *int      `gorm:"column:latency_ms"`
	CheckedAt      time.Time `gorm:"column:checked_at"`
	ErrorMessage   *string   `gorm:"column:error_message"`
}

// TableName pins the model to the migrated table name.
func (ToolHealthCheck) TableName() string { return "tool_health_checks" }
