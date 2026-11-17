package service

import (
	"context"
	"errors"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// ErrToolNotFound is returned when a tool does not exist (or is soft-deleted).
var ErrToolNotFound = errors.New("tool not found")

// ErrDuplicateSlug is returned when a tool slug already exists.
var ErrDuplicateSlug = errors.New("slug already in use")

// ToolRepository is the persistence contract the tool service depends on. It is
// satisfied by internal/repository and lets the service be unit-tested without
// a database.
type ToolRepository interface {
	List(ctx context.Context) ([]model.Tool, error)
	GetByID(ctx context.Context, id uint64) (*model.Tool, error)
	GetBySlug(ctx context.Context, slug string) (*model.Tool, error)
	Create(ctx context.Context, tool *model.Tool) error
	Update(ctx context.Context, tool *model.Tool) error
	SoftDelete(ctx context.Context, id uint64) error
}
