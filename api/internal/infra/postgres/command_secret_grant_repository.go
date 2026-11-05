package postgres

// The secrets a claimed job may use (docs/architecture/task-secrets.md).
// Every statement is tenant-scoped; a grant is written only for a command of
// the tenant held by the named sensor, and a fetch counts only against the
// grant of that command, epoch and sensor.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tasksecret"
)

// CommandSecretGrantRepository implements tasksecret.Repository on the
// command_secret_grants table.
type CommandSecretGrantRepository struct {
	db *DB
}

// NewCommandSecretGrantRepository creates the repository.
func NewCommandSecretGrantRepository(db *DB) *CommandSecretGrantRepository {
	return &CommandSecretGrantRepository{db: db}
}

var _ tasksecret.Repository = (*CommandSecretGrantRepository)(nil)

// Record stores the grant of a claim. The command must be the tenant's and
// held by the sensor under the epoch; a repeat of the same claim replaces
// the refs and keeps the count.
func (r *CommandSecretGrantRepository) Record(ctx context.Context, g *tasksecret.Grant) error {
	refs, err := json.Marshal(g.Set)
	if err != nil {
		return fmt.Errorf("record secret grant: %w", err)
	}
	var one int
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO command_secret_grants (command_id, lease_epoch, tenant_id, sensor_id, refs, max_fetches, egress_endpoints)
		SELECT c.id, $2, c.tenant_id, $4, $5::jsonb, $6, $7::text[]
		  FROM commands c
		 WHERE c.id = $1 AND c.tenant_id = $3 AND c.sensor_id = $4 AND c.lease_epoch = $2
		ON CONFLICT (command_id, lease_epoch) DO UPDATE
		   SET refs = EXCLUDED.refs, egress_endpoints = EXCLUDED.egress_endpoints, max_fetches = GREATEST(EXCLUDED.max_fetches, command_secret_grants.fetches)
		 WHERE command_secret_grants.tenant_id = EXCLUDED.tenant_id
		   AND command_secret_grants.sensor_id = EXCLUDED.sensor_id
		RETURNING 1`,
		g.CommandID.String(), g.LeaseEpoch, g.TenantID.String(), g.SensorID.String(), string(refs), g.MaxFetches, pq.Array(nonNil(g.EgressEndpoints))).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: the command is not held by the sensor under this lease", shared.ErrConflict)
	}
	if err != nil {
		return fmt.Errorf("record secret grant: %w", err)
	}
	return nil
}

// Get returns the grant of (command, epoch) in tenantID.
func (r *CommandSecretGrantRepository) Get(ctx context.Context, tenantID, commandID shared.ID, leaseEpoch int) (*tasksecret.Grant, error) {
	var (
		g            tasksecret.Grant
		sensor, refs string
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT sensor_id::text, refs::text, egress_endpoints, fetches, max_fetches, created_at
		  FROM command_secret_grants
		 WHERE tenant_id = $1 AND command_id = $2 AND lease_epoch = $3`,
		tenantID.String(), commandID.String(), leaseEpoch).Scan(&sensor, &refs, pq.Array(&g.EgressEndpoints), &g.Fetches, &g.MaxFetches, &g.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get secret grant: %w", err)
	}
	sid, err := shared.IDFromString(sensor)
	if err != nil {
		return nil, fmt.Errorf("secret grant sensor: %w", err)
	}
	if err := json.Unmarshal([]byte(refs), &g.Set); err != nil {
		return nil, fmt.Errorf("secret grant refs: %w", err)
	}
	g.TenantID, g.CommandID, g.SensorID, g.LeaseEpoch = tenantID, commandID, sid, leaseEpoch
	return &g, nil
}

// Consume counts one fetch while the count is below the bound.
func (r *CommandSecretGrantRepository) Consume(ctx context.Context, tenantID, commandID shared.ID, leaseEpoch int, sensorID shared.ID) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE command_secret_grants SET fetches = fetches + 1
		 WHERE tenant_id = $1 AND command_id = $2 AND lease_epoch = $3 AND sensor_id = $4 AND fetches < max_fetches`,
		tenantID.String(), commandID.String(), leaseEpoch, sensorID.String())
	if err != nil {
		return false, fmt.Errorf("count secret fetch: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("count secret fetch: %w", err)
	}
	return n == 1, nil
}
