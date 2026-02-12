package apikey

import (
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ID is a type alias for shared.ID.
type ID = shared.ID

// Status represents the API key status.
type Status string

const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// IsValid returns true if the status is valid.
func (s Status) IsValid() bool {
	switch s {
	case StatusActive, StatusExpired, StatusRevoked:
		return true
	}
	return false
}

// APIKey represents a tenant API key for programmatic access.
type APIKey struct {
	id          ID
	tenantID    ID
	userID      *ID // nil = tenant-level key
	name        string
	description string
	keyHash     string
	keyPrefix   string // first 8 chars for identification
	scopes      []string
	rateLimit   int
	status      Status
	expiresAt   *time.Time
	lastUsedAt  *time.Time
	lastUsedIP  string
	useCount    int64
	createdBy   *ID
	createdAt   time.Time
	updatedAt   time.Time
	revokedAt   *time.Time
	revokedBy   *ID
}

// NewAPIKey creates a new API key entity.
func NewAPIKey(id, tenantID ID, name, keyHash, keyPrefix string) *APIKey {
	now := time.Now()
	return &APIKey{
		id:        id,
		tenantID:  tenantID,
		name:      name,
		keyHash:   keyHash,
		keyPrefix: keyPrefix,
		scopes:    []string{},
		rateLimit: 1000,
		status:    StatusActive,
		createdAt: now,
		updatedAt: now,
	}
}

// Reconstruct creates an APIKey from stored data (database reconstruction).
func Reconstruct(
	id, tenantID ID,
	userID *ID,
	name, description, keyHash, keyPrefix string,
	scopes []string,
	rateLimit int,
	status Status,
	expiresAt, lastUsedAt *time.Time,
	lastUsedIP string,
	useCount int64,
	createdBy *ID,
	createdAt, updatedAt time.Time,
	revokedAt *time.Time,
	revokedBy *ID,
) *APIKey {
	return &APIKey{
		id:          id,
		tenantID:    tenantID,
		userID:      userID,
		name:        name,
		description: description,
		keyHash:     keyHash,
		keyPrefix:   keyPrefix,
		scopes:      scopes,
		rateLimit:   rateLimit,
		status:      status,
		expiresAt:   expiresAt,
		lastUsedAt:  lastUsedAt,
		lastUsedIP:  lastUsedIP,
		useCount:    useCount,
		createdBy:   createdBy,
		createdAt:   createdAt,
		updatedAt:   updatedAt,
		revokedAt:   revokedAt,
		revokedBy:   revokedBy,
	}
}

// --- Getters ---

func (k *APIKey) ID() ID                 { return k.id }
func (k *APIKey) TenantID() ID           { return k.tenantID }
func (k *APIKey) UserID() *ID            { return k.userID }
func (k *APIKey) Name() string           { return k.name }
func (k *APIKey) Description() string    { return k.description }
func (k *APIKey) KeyHash() string        { return k.keyHash }
func (k *APIKey) KeyPrefix() string      { return k.keyPrefix }
func (k *APIKey) Scopes() []string       { return k.scopes }
func (k *APIKey) RateLimit() int         { return k.rateLimit }
func (k *APIKey) Status() Status         { return k.status }
func (k *APIKey) ExpiresAt() *time.Time  { return k.expiresAt }
func (k *APIKey) LastUsedAt() *time.Time { return k.lastUsedAt }
func (k *APIKey) LastUsedIP() string     { return k.lastUsedIP }
func (k *APIKey) UseCount() int64        { return k.useCount }
func (k *APIKey) CreatedBy() *ID         { return k.createdBy }
func (k *APIKey) CreatedAt() time.Time   { return k.createdAt }
func (k *APIKey) UpdatedAt() time.Time   { return k.updatedAt }
func (k *APIKey) RevokedAt() *time.Time  { return k.revokedAt }
func (k *APIKey) RevokedBy() *ID         { return k.revokedBy }

// --- Setters ---

func (k *APIKey) SetDescription(desc string) {
	k.description = desc
	k.updatedAt = time.Now()
}

func (k *APIKey) SetScopes(scopes []string) {
	k.scopes = scopes
	k.updatedAt = time.Now()
}

func (k *APIKey) SetRateLimit(limit int) {
	k.rateLimit = limit
	k.updatedAt = time.Now()
}

func (k *APIKey) SetExpiresAt(t *time.Time) {
	k.expiresAt = t
	k.updatedAt = time.Now()
}

func (k *APIKey) SetUserID(id *ID) {
	k.userID = id
	k.updatedAt = time.Now()
}

func (k *APIKey) SetCreatedBy(id ID) {
	k.createdBy = &id
}

// Revoke marks the key as revoked.
func (k *APIKey) Revoke(revokedBy ID) error {
	if k.status == StatusRevoked {
		return fmt.Errorf("%w: key is already revoked", shared.ErrValidation)
	}
	now := time.Now()
	k.status = StatusRevoked
	k.revokedAt = &now
	k.revokedBy = &revokedBy
	k.updatedAt = now
	return nil
}

// IsActive returns true if the key is active and not expired.
func (k *APIKey) IsActive() bool {
	if k.status != StatusActive {
		return false
	}
	if k.expiresAt != nil && k.expiresAt.Before(time.Now()) {
		return false
	}
	return true
}

// --- Errors ---

var (
	ErrAPIKeyNotFound   = fmt.Errorf("%w: api key not found", shared.ErrNotFound)
	ErrAPIKeyNameExists = fmt.Errorf("%w: api key name already exists", shared.ErrAlreadyExists)
)
