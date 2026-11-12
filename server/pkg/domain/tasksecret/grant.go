// Package tasksecret holds the record of the secrets a claimed job may use:
// the refs the platform listed in the job's signed payload (contract
// secretref.Set) for one command, lease epoch and sensor, and the bounded
// count of fetches made under it. A grant names secrets, never holds one.
//
// Design: docs/architecture/task-secrets.md.
package tasksecret

import (
	"context"
	"time"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Fetch bounds: a job may fetch once per task it can produce, plus
// MaxFetchesSlack (the forwarder's fetch of the pool credentials and one
// retry), never fewer than MinMaxFetches and never more than
// MaxMaxFetches.
const (
	MaxFetchesSlack = 2
	MinMaxFetches   = 3
	MaxMaxFetches   = 256
)

// MaxFetches is the fetch bound of a job that can produce tasks tasks.
func MaxFetches(tasks int) int {
	return min(max(tasks+MaxFetchesSlack, MinMaxFetches), MaxMaxFetches)
}

// Grant is the secrets of one claim: command CommandID of TenantID, held by
// SensorID under LeaseEpoch.
type Grant struct {
	TenantID   shared.ID
	CommandID  shared.ID
	SensorID   shared.ID
	LeaseEpoch int
	Set        secretref.Set
	// EgressEndpoints are the ids of the endpoints of the egress block the
	// job was signed with: the only pool endpoints whose credentials the
	// job may fetch.
	EgressEndpoints []string
	Fetches         int
	MaxFetches      int
	CreatedAt       time.Time
}

// Repository stores grants. Every method is scoped by the tenant.
type Repository interface {
	// Record stores the grant of a claim. A repeat of the same claim (same
	// command, epoch and sensor) replaces the refs and keeps the count;
	// a row of the same command and epoch held by another sensor or tenant
	// is never changed (shared.ErrConflict).
	Record(ctx context.Context, g *Grant) error
	// Get returns the grant of (command, epoch) in tenantID
	// (shared.ErrNotFound when none).
	Get(ctx context.Context, tenantID, commandID shared.ID, leaseEpoch int) (*Grant, error)
	// Consume counts one fetch of the grant of (command, epoch) held by
	// sensorID, atomically, only while the count is below the bound; false
	// when the bound is reached or there is no such grant.
	Consume(ctx context.Context, tenantID, commandID shared.ID, leaseEpoch int, sensorID shared.ID) (bool, error)
}
