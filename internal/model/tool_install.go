package model

import "time"

// Tool installation lifecycle states (table: tool_installs).
//
// A row is created when an admin uploads a package and moves through these
// states. Terminal states are Installed, Failed and Removed. A Failed install
// never leaves a container or image behind (the installer rolls back), and the
// registry row that a failed install created is soft-deleted.
const (
	ToolInstallPending   = "pending"
	ToolInstallBuilding  = "building"
	ToolInstallStarting  = "starting"
	ToolInstallInstalled = "installed"
	ToolInstallFailed    = "failed"
	ToolInstallUpdating  = "updating"
	ToolInstallRemoving  = "removing"
	ToolInstallRemoved   = "removed"
)

// ToolInstall is the deployment bookkeeping record for a tool that was
// installed from an uploaded ZIP package.
//
// The tools table remains the runtime source of truth for status, access type
// and upstream URL. This table only records how the container got there, so an
// update or uninstall can find the image and container it must act on.
type ToolInstall struct {
	ID                 uint64    `gorm:"column:id;primaryKey;autoIncrement"`
	ToolID             *uint64   `gorm:"column:tool_id"`
	Slug               string    `gorm:"column:slug"`
	Status             string    `gorm:"column:status"`
	Version            *string   `gorm:"column:version"`
	ImageTag           *string   `gorm:"column:image_tag"`
	ContainerName      *string   `gorm:"column:container_name"`
	PackageSHA256      *string   `gorm:"column:package_sha256"`
	ErrorCode          *string   `gorm:"column:error_code"`
	ErrorMessage       *string   `gorm:"column:error_message"`
	InstalledByAdminID *uint64   `gorm:"column:installed_by_admin_id"`
	CreatedAt          time.Time `gorm:"column:created_at"`
	UpdatedAt          time.Time `gorm:"column:updated_at"`
}

// TableName pins the model to the migrated table name.
func (ToolInstall) TableName() string { return "tool_installs" }

// IsTerminal reports whether the install reached a state that needs no further
// polling. The admin UI stops refreshing when this is true.
func (i *ToolInstall) IsTerminal() bool {
	switch i.Status {
	case ToolInstallInstalled, ToolInstallFailed, ToolInstallRemoved:
		return true
	default:
		return false
	}
}

// IsValidToolInstallStatus reports whether s is a recognized install state.
func IsValidToolInstallStatus(s string) bool {
	switch s {
	case ToolInstallPending, ToolInstallBuilding, ToolInstallStarting,
		ToolInstallInstalled, ToolInstallFailed, ToolInstallUpdating,
		ToolInstallRemoving, ToolInstallRemoved:
		return true
	default:
		return false
	}
}
