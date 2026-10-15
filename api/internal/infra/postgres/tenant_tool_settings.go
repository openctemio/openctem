package postgres

// Organization tool defaults (docs/architecture/sensors.md, "Tool settings";
// table tenant_tool_settings). Every query carries the tenant.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ sensor.TenantToolSettingsStore = (*SensorRepository)(nil)

const tenantToolSettingsColumns = `tenant_id, tool, "values", schema_digest, updated_by, updated_at`

// ListTenantToolSettings implements sensor.TenantToolSettingsStore.
func (r *SensorRepository) ListTenantToolSettings(ctx context.Context, tenantID shared.ID) ([]sensor.TenantToolSettings, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+tenantToolSettingsColumns+`
		FROM tenant_tool_settings
		WHERE tenant_id = $1
		ORDER BY tool`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list organization tool settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sensor.TenantToolSettings
	for rows.Next() {
		ts, err := scanTenantToolSettings(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ts)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list organization tool settings: %w", err)
	}
	return out, nil
}

// GetTenantToolSettings implements sensor.TenantToolSettingsStore.
func (r *SensorRepository) GetTenantToolSettings(ctx context.Context, tenantID shared.ID, tool string) (*sensor.TenantToolSettings, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+tenantToolSettingsColumns+`
		FROM tenant_tool_settings
		WHERE tenant_id = $1 AND tool = $2`, tenantID.String(), tool)
	ts, err := scanTenantToolSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return ts, err
}

// SaveTenantToolSettings implements sensor.TenantToolSettingsStore.
func (r *SensorRepository) SaveTenantToolSettings(ctx context.Context, ts sensor.TenantToolSettings) error {
	vals := ts.Values
	if vals == nil {
		vals = map[string]any{}
	}
	doc, err := json.Marshal(vals)
	if err != nil {
		return fmt.Errorf("failed to marshal organization tool settings: %w", err)
	}
	at := ts.UpdatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if _, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_tool_settings (`+tenantToolSettingsColumns+`)
		VALUES ($1, $2, $3::jsonb, $4, $5, $6)
		ON CONFLICT (tenant_id, tool) DO UPDATE
		SET "values" = EXCLUDED."values", schema_digest = EXCLUDED.schema_digest,
		    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		ts.TenantID.String(), ts.Tool, string(doc), ts.SchemaDigest, nullID(ts.UpdatedBy), at); err != nil {
		return fmt.Errorf("failed to save organization tool settings: %w", err)
	}
	return nil
}

// DeleteTenantToolSettings implements sensor.TenantToolSettingsStore.
func (r *SensorRepository) DeleteTenantToolSettings(ctx context.Context, tenantID shared.ID, tool string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM tenant_tool_settings
		WHERE tenant_id = $1 AND tool = $2`, tenantID.String(), tool)
	if err != nil {
		return false, fmt.Errorf("failed to delete organization tool settings: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to delete organization tool settings: %w", err)
	}
	return n > 0, nil
}

func scanTenantToolSettings(row interface{ Scan(dest ...any) error }) (*sensor.TenantToolSettings, error) {
	var (
		tenantID  string
		ts        sensor.TenantToolSettings
		doc       []byte
		updatedBy sql.NullString
	)
	if err := row.Scan(&tenantID, &ts.Tool, &doc, &ts.SchemaDigest, &updatedBy, &ts.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan organization tool settings: %w", err)
	}
	var err error
	if ts.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("organization tool settings tenant: %w", err)
	}
	if updatedBy.Valid {
		if id, err := shared.IDFromString(updatedBy.String); err == nil {
			ts.UpdatedBy = &id
		}
	}
	if ts.Values, err = sensor.DecodeToolSettingsValues(doc); err != nil {
		return nil, fmt.Errorf("organization tool settings values: %w", err)
	}
	return &ts, nil
}
