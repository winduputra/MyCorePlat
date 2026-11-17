package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/winduputra/MyCorePlat/internal/model"
)

// Recorded activity actions. Keep them stable: admin UI filters on them.
const (
	ActionAdminLogin           = "admin.login"
	ActionAdminLoginFailed     = "admin.login_failed"
	ActionAdminLogout          = "admin.logout"
	ActionToolCreated          = "tool.create"
	ActionToolUpdated          = "tool.update"
	ActionToolDeleted          = "tool.delete"
	ActionToolAccessChanged    = "tool.access_changed"
	ActionToolStatusChanged    = "tool.status_changed"
	ActionTokenCreated         = "token.create"
	ActionTokenRevoked         = "token.revoke"
	ActionHealthCheckFailed    = "health.check_failed"
	ActionHealthCheckRecovered = "health.check_recovered"
)

// Entity types referenced by activity_logs.entity_type.
const (
	EntityTypeAdmin = "admin"
	EntityTypeTool  = "tool"
	EntityTypeToken = "token"
)

// Sensitive metadata keys that are stripped before persisting. Matching is
// case-insensitive and substring based so that variants like "X-Signature"
// or "access_token_hash" are caught too (docs/security-design.md §12).
var sensitiveMetadataKeys = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"hash",
	"cookie",
	"csrf",
	"authorization",
	"signature",
	"dsn",
	"session",
	"credential",
	"api_key",
	"apikey",
	"private_key",
}

// ActivityLogRepository is the narrow persistence interface this service needs.
type ActivityLogRepository interface {
	Insert(ctx context.Context, entry *model.ActivityLog) error
	List(ctx context.Context, filter ActivityFilter) ([]model.ActivityLog, int64, error)
}

// ActivityFilter narrows an activity log listing.
type ActivityFilter struct {
	Action     string
	EntityType string
	ToolID     *uint64
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

// ActivityEntry is the sanitized input for recording one activity row. Values
// here are treated as untrusted: Metadata is filtered against the deny-list,
// bounded in size, and every free-text field is truncated.
type ActivityEntry struct {
	ActorType  string
	ActorID    *uint64
	Action     string
	EntityType string
	EntityID   *uint64
	ToolID     *uint64
	IPAddress  string
	UserAgent  string
	Metadata   map[string]any
}

// ActivityService records administrative activity and serves the audit listing.
type ActivityService struct {
	repo          ActivityLogRepository
	metadataLimit int
}

// NewActivityService builds the audit service. A non-positive metadataLimit
// falls back to a conservative default rather than allowing unbounded rows.
func NewActivityService(repo ActivityLogRepository, metadataLimit int) *ActivityService {
	if metadataLimit <= 0 {
		metadataLimit = DefaultActivityMetadataLimit
	}
	return &ActivityService{repo: repo, metadataLimit: metadataLimit}
}

// Default bounds applied inside the sanitizer.
const (
	DefaultActivityMetadataLimit = 2048
	maxIPAddressLen              = 45
	maxUserAgentLen              = 512
	maxActionLen                 = 64
	maxEntityTypeLen             = 32
	maxMetadataStringLen         = 256
)

// Record persists one sanitized activity row.
//
// The boolean reports whether the row was written. Errors are deliberately
// swallowed: an audit-write failure must never change the security response of
// the caller, and it must never itself be logged in a way that could echo
// sensitive data. Callers ignoring the result get a safe, non-recursive path.
func (s *ActivityService) Record(ctx context.Context, entry ActivityEntry) bool {
	if s == nil || s.repo == nil {
		return false
	}
	row := s.build(entry)
	if row.Action == "" {
		return false
	}
	if err := s.repo.Insert(ctx, row); err != nil {
		// Intentionally not logged: the error may embed connection details or
		// values from the row, and recursive logging is forbidden.
		return false
	}
	return true
}

// List returns a page of activity rows plus the total count for pagination.
func (s *ActivityService) List(ctx context.Context, filter ActivityFilter) ([]model.ActivityLog, int64, error) {
	if s == nil || s.repo == nil {
		return nil, 0, nil
	}
	if filter.Limit <= 0 {
		filter.Limit = DefaultActivityPageSize
	}
	if filter.Limit > MaxActivityPageSize {
		filter.Limit = MaxActivityPageSize
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	return s.repo.List(ctx, filter)
}

// Pagination bounds for the admin listing.
const (
	DefaultActivityPageSize = 50
	MaxActivityPageSize     = 200
)

// build converts an entry into a persistable row, applying every safety rule.
func (s *ActivityService) build(entry ActivityEntry) *model.ActivityLog {
	row := &model.ActivityLog{
		ActorType: sanitizeActorType(entry.ActorType),
		Action:    truncate(strings.TrimSpace(entry.Action), maxActionLen),
		CreatedAt: time.Now().UTC(),
	}
	row.ActorID = entry.ActorID
	row.EntityID = entry.EntityID
	row.ToolID = entry.ToolID
	row.EntityType = optionalTruncated(entry.EntityType, maxEntityTypeLen)
	row.IPAddress = optionalTruncated(entry.IPAddress, maxIPAddressLen)
	row.UserAgent = optionalTruncated(entry.UserAgent, maxUserAgentLen)

	if meta := s.sanitizeMetadata(entry.Metadata); meta != "" {
		row.MetadataJSON = &meta
	}
	return row
}

// sanitizeMetadata drops sensitive keys, truncates strings, and enforces the
// configured byte budget. It returns "" when nothing survives.
func (s *ActivityService) sanitizeMetadata(in map[string]any) string {
	if len(in) == 0 {
		return ""
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		if isSensitiveKey(key) {
			continue
		}
		cleaned, ok := cleanMetadataValue(value)
		if !ok {
			continue
		}
		out[key] = cleaned
	}
	if len(out) == 0 {
		return ""
	}

	encoded, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	if len(encoded) <= s.metadataLimit {
		return string(encoded)
	}

	// Over budget: fall back to a marker rather than truncating mid-JSON, which
	// would produce an invalid document.
	trimmed, err := json.Marshal(map[string]string{"truncated": "metadata exceeded size limit"})
	if err != nil {
		return ""
	}
	return string(trimmed)
}

// cleanMetadataValue keeps only scalar values and length-bounded strings;
// nested objects/arrays are stringified and truncated.
func cleanMetadataValue(value any) (any, bool) {
	switch v := value.(type) {
	case nil:
		return nil, false
	case string:
		return truncate(v, maxMetadataStringLen), true
	case bool, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return v, true
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil, false
		}
		return truncate(string(encoded), maxMetadataStringLen), true
	}
}

// isSensitiveKey reports whether a metadata key must never be persisted.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	if lower == "" {
		return true
	}
	for _, needle := range sensitiveMetadataKeys {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

func sanitizeActorType(actorType string) string {
	switch strings.TrimSpace(actorType) {
	case model.ActorTypeAdmin:
		return model.ActorTypeAdmin
	case model.ActorTypeSystem:
		return model.ActorTypeSystem
	default:
		return model.ActorTypeSystem
	}
}

func optionalTruncated(value string, max int) *string {
	trimmed := truncate(strings.TrimSpace(value), max)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

// truncate caps a string to at most max bytes without splitting a rune.
func truncate(value string, max int) string {
	if max <= 0 || len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && !isUTF8Start(value[cut]) {
		cut--
	}
	return value[:cut]
}

// isUTF8Start reports whether b begins a UTF-8 sequence.
func isUTF8Start(b byte) bool { return b&0xC0 != 0x80 }
