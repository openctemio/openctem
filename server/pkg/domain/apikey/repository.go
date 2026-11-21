package apikey

import (
	"context"
	"time"
)

// Filter represents filtering options for listing API keys.
type Filter struct {
	TenantID *ID
	UserID   *ID
	Status   *Status
	// OwnerKind limits the list to keys owned by that kind of identity:
	// OwnerService (service accounts) or OwnerPerson (people). Empty: any.
	OwnerKind string
	Search    string
	Page      int
	PerPage   int
	SortBy    string
	SortOrder string
}

// Owner kinds of Filter.OwnerKind and Owner.Kind.
const (
	OwnerPerson  = "person"
	OwnerService = "service"
)

// Owner is the display data of the identity a key belongs to.
type Owner struct {
	// Name is the owner's name, or the e-mail when the owner has none.
	Name string
	// Kind is OwnerPerson or OwnerService.
	Kind string
}

// ListResult represents a paginated list of API keys.
type ListResult struct {
	// Owners maps a key id to its owner, loaded by the same query as the
	// page. A key without an owner has no entry.
	Owners     map[ID]Owner
	Data       []*APIKey
	Total      int64
	Page       int
	PerPage    int
	TotalPages int
}

// Repository defines the interface for API key persistence.
type Repository interface {
	Create(ctx context.Context, key *APIKey) error
	GetByID(ctx context.Context, id, tenantID ID) (*APIKey, error)
	GetByHash(ctx context.Context, hash string) (*APIKey, error)
	List(ctx context.Context, filter Filter) (ListResult, error)
	Update(ctx context.Context, key *APIKey) error
	Delete(ctx context.Context, id, tenantID ID) error
	// TouchLastUsed records that the key was just used (last_used_at/ip +
	// use_count). Best-effort — callers ignore its error so telemetry never
	// blocks authentication.
	TouchLastUsed(ctx context.Context, tenantID, id ID, ip string) error
	// RevokeByUser revokes every active key owned by userID in EVERY
	// organization (keys without an owner are untouched) and returns how
	// many. CountActiveByUser counts them. Both filter on the owner only.
	RevokeByUser(ctx context.Context, userID, revokedBy ID, now time.Time) (int, error)
	CountActiveByUser(ctx context.Context, userID ID, now time.Time) (int, error)
}

// ExpiringKey is an active key that expires soon and whose holder was not
// told yet (the expiry notice sweep).
type ExpiringKey struct {
	ID        ID
	TenantID  ID
	Name      string
	Prefix    string
	ExpiresAt time.Time
	UserID    *ID
	CreatedBy *ID
}

// ExpiryNoticeRepository finds keys that expire soon and records the notice.
type ExpiryNoticeRepository interface {
	// ListExpiringUnnoticed reads across organizations (a system sweep).
	ListExpiringUnnoticed(ctx context.Context, before time.Time, limit int) ([]ExpiringKey, error)
	// MarkExpiryNoticed is tenant-scoped and reports false when the notice
	// was already recorded.
	MarkExpiryNoticed(ctx context.Context, tenantID, id ID) (bool, error)
}
