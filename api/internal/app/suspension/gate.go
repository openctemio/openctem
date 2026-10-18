// Package suspension holds the platform administrator's kill switches
// (docs/architecture/organization-suspension.md): suspending an organization
// and the access gate every credential path asks before it reaches one.
//
// The gate is the single decision; the credential paths (the token-tenant
// and URL-tenant middleware chains, MCP, sensor keys, SCIM tokens, CI run
// tokens, inbound webhooks and token issuance) each call it once they know
// the organization. It fails closed: an unreadable status refuses the
// request.
package suspension

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// StatusReader reads an organization's platform status; shared.ErrNotFound
// when the organization does not exist.
type StatusReader interface {
	OrganizationStatus(ctx context.Context, tenantID shared.ID) (tenantdom.OrganizationStatus, error)
}

// CachedStatus is the cached value of one organization's status.
type CachedStatus struct {
	Status string `json:"status"`
}

// StatusCache is the shared cache in front of the store (Redis, so every API
// replica sees a change at once). Satisfied by *redis.Cache[CachedStatus].
type StatusCache interface {
	Get(ctx context.Context, key string) (*CachedStatus, error)
	Set(ctx context.Context, key string, value CachedStatus) error
}

// CacheTTL bounds how long a cached status lives. A change overwrites the
// cached value at once (Gate.Remember), so the TTL only matters when that
// write failed.
const CacheTTL = 60 * time.Second

// CachePrefix is the Redis key prefix of the cache.
const CachePrefix = "org_status"

// Gate is the tenantdom.AccessGate production wires.
type Gate struct {
	store StatusReader
	cache StatusCache
	log   *logger.Logger
}

var _ tenantdom.AccessGate = (*Gate)(nil)

// NewGate creates the gate. cache may be nil (every check reads the store).
func NewGate(store StatusReader, cache StatusCache, log *logger.Logger) *Gate {
	if log == nil {
		log = logger.NewNop()
	}
	return &Gate{store: store, cache: cache, log: log.With("component", "organization-access-gate")}
}

// CheckAccess returns nil when the organization is active,
// tenantdom.ErrOrganizationSuspended when it is not, shared.ErrNotFound when
// it does not exist, and any other error when its status cannot be read. Only
// nil admits the request.
func (g *Gate) CheckAccess(ctx context.Context, tenantID shared.ID) error {
	if g == nil || g.store == nil {
		return errors.New("organization access gate is not configured")
	}
	if tenantID.IsZero() {
		return fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	status, err := g.status(ctx, tenantID)
	if err != nil {
		return err
	}
	if !status.IsActive() {
		return tenantdom.ErrOrganizationSuspended
	}
	return nil
}

func (g *Gate) status(ctx context.Context, tenantID shared.ID) (tenantdom.OrganizationStatus, error) {
	key := tenantID.String()
	if g.cache != nil {
		if c, err := g.cache.Get(ctx, key); err == nil && c != nil && c.Status != "" {
			return tenantdom.OrganizationStatus(c.Status), nil
		}
	}
	status, err := g.store.OrganizationStatus(ctx, tenantID)
	if err != nil {
		return "", err
	}
	g.Remember(ctx, tenantID, status)
	return status, nil
}

// Remember writes an organization's status to the shared cache. The
// suspension service calls it right after a change, so the next request on
// any replica sees the new status; a failed write is logged and the TTL
// bounds the stale window.
func (g *Gate) Remember(ctx context.Context, tenantID shared.ID, status tenantdom.OrganizationStatus) {
	if g == nil || g.cache == nil {
		return
	}
	if err := g.cache.Set(ctx, tenantID.String(), CachedStatus{Status: string(status)}); err != nil {
		g.log.Warn("organization status cache write failed", "tenant_id", tenantID.String(), "error", err)
	}
}
