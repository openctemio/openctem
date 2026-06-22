// Package scimtoken is the domain model for per-tenant SCIM 2.0 provisioning
// bearer tokens (RFC-009). Only the peppered hash is persisted; the plaintext
// is shown once at creation.
package scimtoken

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ErrNotFound is returned when no token matches the lookup.
var ErrNotFound = errors.New("scim token not found")

// Status is the token lifecycle state.
type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
)

// ScimToken is a per-tenant SCIM bearer token.
type ScimToken struct {
	id         shared.ID
	tenantID   shared.ID
	name       string
	tokenHash  string // peppered HMAC-SHA256 of the plaintext
	prefix     string // first chars of the plaintext, for identification
	status     Status
	createdBy  *shared.ID
	createdAt  time.Time
	lastUsedAt *time.Time
}

// New creates an active SCIM token.
func New(id, tenantID shared.ID, name, tokenHash, prefix string) *ScimToken {
	return &ScimToken{
		id:        id,
		tenantID:  tenantID,
		name:      name,
		tokenHash: tokenHash,
		prefix:    prefix,
		status:    StatusActive,
		createdAt: time.Now().UTC(),
	}
}

// Reconstruct rebuilds a token from persistence.
func Reconstruct(id, tenantID shared.ID, name, tokenHash, prefix string, status Status, createdBy *shared.ID, createdAt time.Time, lastUsedAt *time.Time) *ScimToken {
	return &ScimToken{
		id:         id,
		tenantID:   tenantID,
		name:       name,
		tokenHash:  tokenHash,
		prefix:     prefix,
		status:     status,
		createdBy:  createdBy,
		createdAt:  createdAt,
		lastUsedAt: lastUsedAt,
	}
}

func (t *ScimToken) ID() shared.ID          { return t.id }
func (t *ScimToken) TenantID() shared.ID    { return t.tenantID }
func (t *ScimToken) Name() string           { return t.name }
func (t *ScimToken) TokenHash() string      { return t.tokenHash }
func (t *ScimToken) Prefix() string         { return t.prefix }
func (t *ScimToken) Status() Status         { return t.status }
func (t *ScimToken) CreatedBy() *shared.ID  { return t.createdBy }
func (t *ScimToken) CreatedAt() time.Time   { return t.createdAt }
func (t *ScimToken) LastUsedAt() *time.Time { return t.lastUsedAt }

// IsActive reports whether the token may authenticate.
func (t *ScimToken) IsActive() bool { return t.status == StatusActive }

// Revoke marks the token unusable.
func (t *ScimToken) Revoke() { t.status = StatusRevoked }

// SetCreatedBy records the admin who minted the token.
func (t *ScimToken) SetCreatedBy(id shared.ID) { t.createdBy = &id }

// TouchLastUsed records a successful authentication time.
func (t *ScimToken) TouchLastUsed(at time.Time) { t.lastUsedAt = &at }

// Repository persists SCIM tokens.
type Repository interface {
	Create(ctx context.Context, token *ScimToken) error
	// GetByHash returns the token with the given peppered hash (used on the
	// authentication path). Returns ErrNotFound when absent.
	GetByHash(ctx context.Context, tokenHash string) (*ScimToken, error)
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ScimToken, error)
	ListByTenant(ctx context.Context, tenantID shared.ID) ([]*ScimToken, error)
	Update(ctx context.Context, token *ScimToken) error
	// TouchLastUsed records a use time WITHOUT touching status, and only for a
	// still-active token. This avoids a last-used write on the auth path
	// clobbering a concurrent revoke (which would resurrect the token).
	TouchLastUsed(ctx context.Context, id shared.ID, at time.Time) error
}
