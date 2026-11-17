package model

import "time"

// Tool is an entry in the authoritative tool registry (table: tools).
//
// The database row is the source of truth for operational state: Status and
// AccessType are enforced server-side and are never derived from a manifest or
// trusted from client input. ManifestJSON is a stored snapshot for reference.
type Tool struct {
	ID                 uint64     `gorm:"column:id;primaryKey"`
	Slug               string     `gorm:"column:slug"`
	Name               string     `gorm:"column:name"`
	Description        *string    `gorm:"column:description"`
	Category           *string    `gorm:"column:category"`
	Version            *string    `gorm:"column:version"`
	Runtime            *string    `gorm:"column:runtime"`
	AccessType         string     `gorm:"column:access_type"`
	UpstreamURL        string     `gorm:"column:upstream_url"`
	HealthcheckPath    string     `gorm:"column:healthcheck_path"`
	Status             string     `gorm:"column:status"`
	MaintenanceMessage *string    `gorm:"column:maintenance_message"`
	ManifestJSON       *string    `gorm:"column:manifest_json"`
	DisplayOrder       int        `gorm:"column:display_order"`
	CreatedAt          time.Time  `gorm:"column:created_at"`
	UpdatedAt          time.Time  `gorm:"column:updated_at"`
	DeletedAt          *time.Time `gorm:"column:deleted_at"`
}

// TableName pins the model to the migrated table name.
func (Tool) TableName() string { return "tools" }

// Tool status values. These are the only valid values for Status.
const (
	ToolStatusDraft       = "draft"
	ToolStatusActive      = "active"
	ToolStatusMaintenance = "maintenance"
	ToolStatusDisabled    = "disabled"
)

// Tool access-type values. These are the only valid values for AccessType.
const (
	ToolAccessPublic = "public"
	ToolAccessToken  = "token"
)

// IsValidToolStatus reports whether s is a recognized tool status.
func IsValidToolStatus(s string) bool {
	switch s {
	case ToolStatusDraft, ToolStatusActive, ToolStatusMaintenance, ToolStatusDisabled:
		return true
	default:
		return false
	}
}

// IsValidToolAccess reports whether s is a recognized access type.
func IsValidToolAccess(s string) bool {
	switch s {
	case ToolAccessPublic, ToolAccessToken:
		return true
	default:
		return false
	}
}
