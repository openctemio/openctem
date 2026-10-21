package proxypool

import (
	"context"
	"math"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Repository persists pools, endpoints and sensor assignments. Every method
// is tenant-scoped in SQL; ids of another tenant behave as not found.
type Repository interface {
	CreatePool(ctx context.Context, p *Pool) error
	// UpdatePool stores the pool's own fields (not its endpoints).
	UpdatePool(ctx context.Context, p *Pool) error
	// DeletePool removes a pool and its endpoints; ErrPoolInUse while a
	// sensor is assigned to it.
	DeletePool(ctx context.Context, tenantID, id shared.ID) error
	// GetPool returns a pool with its endpoints (priority order) and the
	// number of sensors assigned to it.
	GetPool(ctx context.Context, tenantID, id shared.ID) (*Pool, error)
	// DefaultPool returns the tenant's default pool, nil when it has none.
	DefaultPool(ctx context.Context, tenantID shared.ID) (*Pool, error)
	ListPools(ctx context.Context, tenantID shared.ID) ([]*Pool, error)
	CountPools(ctx context.Context, tenantID shared.ID) (int, error)

	// ReplaceEndpoints makes endpoints the pool's whole list in one
	// transaction: rows whose id is not in it are deleted, the others
	// inserted or updated (address, label, priority, credentials, health),
	// and the pool's revision is stored.
	ReplaceEndpoints(ctx context.Context, p *Pool, endpoints []*Endpoint) error
	// UpdateEndpoint stores an endpoint's enabled flag and health, and the
	// pool's revision.
	UpdateEndpoint(ctx context.Context, p *Pool, e *Endpoint) error
	// UpdateHealth locks the pool's endpoints, lets apply change their
	// health, and stores it, in one transaction.
	UpdateHealth(ctx context.Context, tenantID, poolID shared.ID, apply func([]*Endpoint)) error

	// GetAssignment returns a sensor's assignment, nil when it inherits.
	GetAssignment(ctx context.Context, tenantID, sensorID shared.ID) (*Assignment, error)
	ListAssignments(ctx context.Context, tenantID shared.ID) ([]Assignment, error)
	// SetAssignment stores a sensor's assignment (insert or replace). A
	// sensor or pool of another tenant, or a shared sensor, is refused by
	// the schema and reported as ErrSensorNotFound / ErrPoolNotFound.
	SetAssignment(ctx context.Context, tenantID shared.ID, a Assignment, by *shared.ID) error
	DeleteAssignment(ctx context.Context, tenantID, sensorID shared.ID) error
}

// JobEgress is the "egress" member of a scan command a sensor receives: the
// pool and the endpoints it may use, never credentials. It is part of the
// signed payload.
type JobEgress struct {
	Mode      string        `json:"mode"`
	PoolID    string        `json:"pool_id"`
	Revision  int           `json:"revision"`
	Strategy  string        `json:"strategy"`
	AppliesTo string        `json:"applies_to"`
	Endpoints []JobEndpoint `json:"endpoints"`
}

// JobEndpoint is one endpoint of a JobEgress.
type JobEndpoint struct {
	ID     string  `json:"id"`
	Scheme string  `json:"scheme"`
	Host   string  `json:"host"`
	Port   int     `json:"port"`
	Weight float64 `json:"weight"`
	Auth   bool    `json:"auth"`
}

// BuildJobEgress is the egress of a job on pool p: its enabled endpoints that
// may carry traffic now, in priority order, with their weights. No endpoint
// left (all quarantined) still yields the pool, with an empty list: the
// sensor fails the job rather than going direct.
func BuildJobEgress(p *Pool, appliesTo string, now time.Time) JobEgress {
	out := JobEgress{Mode: ModePool, PoolID: p.ID.String(), Revision: p.Revision, Strategy: p.Strategy,
		AppliesTo: appliesTo, Endpoints: []JobEndpoint{}}
	for _, e := range p.Endpoints {
		if !e.Enabled {
			continue
		}
		w := e.Health.Weight(now)
		if w <= 0 {
			continue
		}
		out.Endpoints = append(out.Endpoints, JobEndpoint{ID: e.ID.String(), Scheme: e.Scheme, Host: e.Host, Port: e.Port,
			Weight: math.Round(w*10000) / 10000, Auth: e.HasCredentials()})
	}
	return out
}
