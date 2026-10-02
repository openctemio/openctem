package postgres

// Tenant scanner content policies (docs/rfcs/RFC-031-managed-sensor-updates.md,
// migration 000253).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
)

// SensorContentPolicyRepository implements sensor.ContentPolicyRepository.
type SensorContentPolicyRepository struct {
	db *DB
}

// NewSensorContentPolicyRepository creates the repository.
func NewSensorContentPolicyRepository(db *DB) *SensorContentPolicyRepository {
	return &SensorContentPolicyRepository{db: db}
}

var _ sensor.ContentPolicyRepository = (*SensorContentPolicyRepository)(nil)

// GetContentPolicy returns the tenant's policy, nil when none is stored.
func (r *SensorContentPolicyRepository) GetContentPolicy(ctx context.Context, tenantID shared.ID) (*sensor.StoredContentPolicy, error) {
	var (
		raw       []byte
		updatedBy sql.NullString
		out       = sensor.StoredContentPolicy{TenantID: tenantID}
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT policy, updated_by, updated_at
		FROM sensor_content_policies
		WHERE tenant_id = $1`, tenantID.String()).Scan(&raw, &updatedBy, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get sensor content policy: %w", err)
	}
	if err := json.Unmarshal(raw, &out.Policy); err != nil {
		return nil, fmt.Errorf("failed to decode sensor content policy: %w", err)
	}
	if updatedBy.Valid {
		if id, err := shared.IDFromString(updatedBy.String); err == nil {
			out.UpdatedBy = &id
		}
	}
	return &out, nil
}

// SaveContentPolicy upserts the tenant's policy and stamps updated_at.
func (r *SensorContentPolicyRepository) SaveContentPolicy(ctx context.Context, p *sensor.StoredContentPolicy) error {
	raw, err := json.Marshal(p.Policy)
	if err != nil {
		return fmt.Errorf("failed to encode sensor content policy: %w", err)
	}
	var updatedBy sql.NullString
	if p.UpdatedBy != nil {
		updatedBy = sql.NullString{String: p.UpdatedBy.String(), Valid: true}
	}
	err = r.db.QueryRowContext(ctx, `
		INSERT INTO sensor_content_policies (tenant_id, policy, updated_by, updated_at)
		VALUES ($1, $2::jsonb, $3::uuid, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		SET policy = EXCLUDED.policy, updated_by = EXCLUDED.updated_by, updated_at = NOW()
		RETURNING updated_at`, p.TenantID.String(), string(raw), updatedBy).Scan(&p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to save sensor content policy: %w", err)
	}
	return nil
}

// OpenCommandsOfType maps each sensor of the tenant to its oldest open
// (pending, acknowledged or running) command of the given type: the
// refresh_content dedup (index idx_commands_open_refresh_content).
func (r *CommandRepository) OpenCommandsOfType(ctx context.Context, tenantID shared.ID, cmdType string) (map[string]string, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT ON (sensor_id) sensor_id, id
		FROM commands
		WHERE tenant_id = $1 AND type = $2 AND sensor_id IS NOT NULL
		  AND status IN ('pending', 'acknowledged', 'running')
		ORDER BY sensor_id, created_at`, tenantID.String(), cmdType)
	if err != nil {
		return nil, fmt.Errorf("failed to list open commands: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var sensorID, id string
		if err := rows.Scan(&sensorID, &id); err != nil {
			return nil, fmt.Errorf("failed to scan open command: %w", err)
		}
		out[sensorID] = id
	}
	return out, rows.Err()
}
