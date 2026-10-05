package postgres

// Sensor config reports (research/26, migration 001054): the latest
// sanitized report per sensor and the sensor's pointer to it. Every query
// is scoped to the sensor's tenant.

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

var _ sensor.ConfigReportStore = (*SensorRepository)(nil)

// SaveConfigReport implements sensor.ConfigReportStore.
func (r *SensorRepository) SaveConfigReport(ctx context.Context, tenantID, sensorID shared.ID, rep *sensor.ConfigReport,
	digest, health string, at time.Time) (bool, bool, error) {
	doc, err := json.Marshal(rep)
	if err != nil {
		return false, false, fmt.Errorf("failed to marshal sensor config report: %w", err)
	}
	var observed any
	if t, err := time.Parse(time.RFC3339, rep.ObservedAt); err == nil {
		observed = t
	}
	counts := sensor.CountChecks(rep.Checks)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, false, fmt.Errorf("failed to begin config report transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The pointer, for an active sensor of the tenant only. The sensor
	// holds this report now, so its heartbeat digest is this one too until
	// the next heartbeat says otherwise.
	res, err := tx.ExecContext(ctx, `
		UPDATE sensors
		SET config_report_digest = $3,
		    config_health = $4,
		    config_heartbeat_digest = $3,
		    updated_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND status = 'active'
	`, sensorID.String(), tenantID.String(), digest, health)
	if err != nil {
		return false, false, fmt.Errorf("failed to point sensor at its config report: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, false, nil
	}

	var stored string
	err = tx.QueryRowContext(ctx, `
		SELECT digest FROM sensor_config_reports
		WHERE sensor_id = $1 AND tenant_id = $2
		FOR UPDATE
	`, sensorID.String(), tenantID.String()).Scan(&stored)
	switch {
	case err == nil && stored == digest:
		// Same report: only the time it was last received moves.
		if _, err := tx.ExecContext(ctx, `
			UPDATE sensor_config_reports SET received_at = $3
			WHERE sensor_id = $1 AND tenant_id = $2
		`, sensorID.String(), tenantID.String(), at); err != nil {
			return false, false, fmt.Errorf("failed to touch sensor config report: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return false, false, fmt.Errorf("failed to commit sensor config report: %w", err)
		}
		return true, false, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return false, false, fmt.Errorf("failed to read sensor config report: %w", err)
	}

	// The tenant guard on the conflict update keeps a row of another
	// tenant untouched (a sensor never changes tenant; defense in depth).
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sensor_config_reports (sensor_id, tenant_id, digest, health, fail_count, warn_count,
		                                   report, observed_at, received_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9)
		ON CONFLICT (sensor_id) DO UPDATE
		SET digest = EXCLUDED.digest,
		    health = EXCLUDED.health,
		    fail_count = EXCLUDED.fail_count,
		    warn_count = EXCLUDED.warn_count,
		    report = EXCLUDED.report,
		    observed_at = EXCLUDED.observed_at,
		    received_at = EXCLUDED.received_at
		WHERE sensor_config_reports.tenant_id = EXCLUDED.tenant_id
	`, sensorID.String(), tenantID.String(), digest, health, counts.Fail+counts.Error, counts.Warn,
		string(doc), observed, at); err != nil {
		return false, false, fmt.Errorf("failed to store sensor config report: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, false, fmt.Errorf("failed to commit sensor config report: %w", err)
	}
	return true, true, nil
}

// GetConfigReport implements sensor.ConfigReportStore.
func (r *SensorRepository) GetConfigReport(ctx context.Context, tenantID, sensorID shared.ID) (*sensor.StoredConfigReport, error) {
	var (
		out sensor.StoredConfigReport
		doc []byte
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT digest, health, report, received_at
		FROM sensor_config_reports
		WHERE sensor_id = $1 AND tenant_id = $2
	`, sensorID.String(), tenantID.String()).Scan(&out.Digest, &out.Health, &doc, &out.ReceivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read sensor config report: %w", err)
	}
	if err := json.Unmarshal(doc, &out.Report); err != nil {
		return nil, fmt.Errorf("failed to decode sensor config report: %w", err)
	}
	return &out, nil
}
