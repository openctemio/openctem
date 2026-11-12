package toolsource

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Key is an organization's stored key of one source. KeyEnc is ciphertext
// only; the value never leaves the platform except to the sensor holding a
// task of the organization's job.
type Key struct {
	TenantID      shared.ID
	Source        string
	KeyEnc        string
	Last4         string
	Enabled       bool
	CreatedBy     *shared.ID
	CreatedAt     time.Time
	UpdatedBy     *shared.ID
	UpdatedByName string
	UpdatedAt     time.Time
	LastUsedAt    *time.Time
}

// Repository stores the keys. Every method is scoped by the tenant.
type Repository interface {
	// List returns the tenant's keys.
	List(ctx context.Context, tenantID shared.ID) ([]Key, error)
	// Get returns one key (shared.ErrNotFound when the tenant has none).
	Get(ctx context.Context, tenantID shared.ID, source string) (*Key, error)
	// Upsert stores or replaces the key of k.Source; a replaced key keeps
	// its creation facts and its enabled switch.
	Upsert(ctx context.Context, k *Key) error
	// SetEnabled switches a key on or off (shared.ErrNotFound when none).
	SetEnabled(ctx context.Context, tenantID shared.ID, source string, enabled bool, by *shared.ID) error
	// Delete removes a key (shared.ErrNotFound when none).
	Delete(ctx context.Context, tenantID shared.ID, source string) error
	// Enabled returns the tenant's enabled keys among sources.
	Enabled(ctx context.Context, tenantID shared.ID, sources []string) ([]Key, error)
	// MarkUsed records that the tenant's keys of sources were delivered.
	MarkUsed(ctx context.Context, tenantID shared.ID, sources []string, at time.Time) error
}
