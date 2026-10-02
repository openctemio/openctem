package sensor

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// StoredContentPolicy is a tenant's saved scanner content policy (RFC-031).
type StoredContentPolicy struct {
	TenantID  shared.ID
	Policy    ContentPolicy
	UpdatedBy *shared.ID
	UpdatedAt time.Time
}

// ContentPolicyRepository persists tenant content policies
// (sensor_content_policies, migration 000251).
type ContentPolicyRepository interface {
	// GetContentPolicy returns the tenant's policy, or nil (and no error)
	// when the tenant has not set one.
	GetContentPolicy(ctx context.Context, tenantID shared.ID) (*StoredContentPolicy, error)
	// SaveContentPolicy creates or replaces the tenant's policy.
	SaveContentPolicy(ctx context.Context, p *StoredContentPolicy) error
}
