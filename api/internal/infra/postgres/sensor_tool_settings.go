package postgres

// Per-sensor tool settings (docs/architecture/sensors.md, "Tool settings";
// table sensor_tool_settings). Every query carries the tenant; the foreign
// key on (tenant_id, sensor_id) keeps a row on a sensor of its own tenant.

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

var _ sensor.ToolSettingsStore = (*SensorRepository)(nil)

const sensorToolSettingsColumns = `tenant_id, sensor_id, tool, "values", schema_digest, updated_by, updated_at`

// ListToolSettings implements sensor.ToolSettingsStore.
func (r *SensorRepository) ListToolSettings(ctx context.Context, tenantID, sensorID shared.ID) ([]sensor.ToolSettings, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sensorToolSettingsColumns+`
		FROM sensor_tool_settings
		WHERE tenant_id = $1 AND sensor_id = $2
		ORDER BY tool`, tenantID.String(), sensorID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list sensor tool settings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sensor.ToolSettings
	for rows.Next() {
		ts, err := scanToolSettings(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ts)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list sensor tool settings: %w", err)
	}
	return out, nil
}

// GetToolSettings implements sensor.ToolSettingsStore.
func (r *SensorRepository) GetToolSettings(ctx context.Context, tenantID, sensorID shared.ID, tool string) (*sensor.ToolSettings, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+sensorToolSettingsColumns+`
		FROM sensor_tool_settings
		WHERE tenant_id = $1 AND sensor_id = $2 AND tool = $3`,
		tenantID.String(), sensorID.String(), tool)
	ts, err := scanToolSettings(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return ts, err
}

// SaveToolSettings implements sensor.ToolSettingsStore. The upsert keeps
// the tenant of an existing row: a row of another tenant on the same
// (sensor, tool) is never overwritten (the WHERE of the update).
func (r *SensorRepository) SaveToolSettings(ctx context.Context, ts sensor.ToolSettings) error {
	vals := ts.Values
	if vals == nil {
		vals = map[string]any{}
	}
	doc, err := json.Marshal(vals)
	if err != nil {
		return fmt.Errorf("failed to marshal sensor tool settings: %w", err)
	}
	at := ts.UpdatedAt
	if at.IsZero() {
		at = time.Now().UTC()
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO sensor_tool_settings (`+sensorToolSettingsColumns+`)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
		ON CONFLICT (sensor_id, tool) DO UPDATE
		SET "values" = EXCLUDED."values", schema_digest = EXCLUDED.schema_digest,
		    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
		WHERE sensor_tool_settings.tenant_id = EXCLUDED.tenant_id`,
		ts.TenantID.String(), ts.SensorID.String(), ts.Tool, string(doc), ts.SchemaDigest,
		nullID(ts.UpdatedBy), at)
	if err != nil {
		return fmt.Errorf("failed to save sensor tool settings: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// DeleteToolSettings implements sensor.ToolSettingsStore.
func (r *SensorRepository) DeleteToolSettings(ctx context.Context, tenantID, sensorID shared.ID, tool string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM sensor_tool_settings
		WHERE tenant_id = $1 AND sensor_id = $2 AND tool = $3`,
		tenantID.String(), sensorID.String(), tool)
	if err != nil {
		return false, fmt.Errorf("failed to delete sensor tool settings: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to delete sensor tool settings: %w", err)
	}
	return n > 0, nil
}

func scanToolSettings(row interface{ Scan(dest ...any) error }) (*sensor.ToolSettings, error) {
	var (
		tenantID, sensorID string
		ts                 sensor.ToolSettings
		doc                []byte
		updatedBy          sql.NullString
	)
	if err := row.Scan(&tenantID, &sensorID, &ts.Tool, &doc, &ts.SchemaDigest, &updatedBy, &ts.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan sensor tool settings: %w", err)
	}
	var err error
	if ts.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, fmt.Errorf("sensor tool settings tenant: %w", err)
	}
	if ts.SensorID, err = shared.IDFromString(sensorID); err != nil {
		return nil, fmt.Errorf("sensor tool settings sensor: %w", err)
	}
	if updatedBy.Valid {
		if id, err := shared.IDFromString(updatedBy.String); err == nil {
			ts.UpdatedBy = &id
		}
	}
	if ts.Values, err = sensor.DecodeToolSettingsValues(doc); err != nil {
		return nil, fmt.Errorf("sensor tool settings values: %w", err)
	}
	return &ts, nil
}
