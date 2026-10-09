package postgres

// Sensor manifest versions (docs/rfcs/RFC-033-sensor-manifest.md, migration
// 000258): one row per distinct manifest per sensor, the sensor's pointer to
// the current one, and the reported_* projection dispatch reads.

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

var _ sensor.ManifestStore = (*SensorRepository)(nil)

// SaveManifest implements sensor.ManifestStore.
func (r *SensorRepository) SaveManifest(ctx context.Context, v sensor.ManifestVersion, report *sensor.CapabilityReport, at time.Time) (bool, error) {
	doc, err := json.Marshal(v.Manifest)
	if err != nil {
		return false, fmt.Errorf("failed to marshal sensor manifest: %w", err)
	}
	ignored := v.Ignored
	if ignored == nil {
		ignored = []sensor.ManifestIgnored{}
	}
	ign, err := json.Marshal(ignored)
	if err != nil {
		return false, fmt.Errorf("failed to marshal sensor manifest ignored items: %w", err)
	}
	rep, err := sensorReportArgsOf(report)
	if err != nil {
		return false, err
	}
	tenantID := nullTenant(v.TenantID)

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("failed to begin manifest transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The pointer and, for a manifest the sensor sent, the projection. A
	// manifest is a complete statement: its ceiling and platform replace the
	// stored ones (NULL included), unlike a heartbeat's absent parts.
	res, err := tx.ExecContext(ctx, `
		UPDATE sensors
		SET manifest_digest = $3,
		    manifest_at = $4,
		    manifest_source = $5,
		    reported_tools = CASE WHEN $6 THEN $7::jsonb ELSE reported_tools END,
		    reported_tool_names = CASE WHEN $6 THEN $8::text[] ELSE reported_tool_names END,
		    reported_capabilities = CASE WHEN $6 THEN $9::text[] ELSE reported_capabilities END,
		    reported_max_jobs = CASE WHEN $6 THEN $10::integer ELSE reported_max_jobs END,
		    reported_os = CASE WHEN $6 THEN $11::varchar ELSE reported_os END,
		    reported_arch = CASE WHEN $6 THEN $12::varchar ELSE reported_arch END,
		    reported_at = CASE WHEN $6 THEN $4 ELSE reported_at END,
		    updated_at = NOW()
		WHERE id = $1
		  AND tenant_id IS NOT DISTINCT FROM $2::uuid
		  AND status = 'active'
	`, v.SensorID.String(), tenantID, v.Digest, at, v.Source,
		report != nil, rep.tools, rep.toolNames, rep.capabilities, rep.maxJobs, rep.os, rep.arch)
	if err != nil {
		return false, fmt.Errorf("failed to point sensor at its manifest: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO sensor_manifests (sensor_id, tenant_id, digest, source, manifest, ignored,
		                              first_seen_at, current_since, last_seen_at)
		VALUES ($1, $2::uuid, $3, $4, $5::jsonb, $6::jsonb, $7, $7, $7)
		ON CONFLICT (sensor_id, digest) DO UPDATE
		SET source = EXCLUDED.source,
		    manifest = EXCLUDED.manifest,
		    ignored = EXCLUDED.ignored,
		    current_since = EXCLUDED.current_since,
		    last_seen_at = EXCLUDED.last_seen_at
	`, v.SensorID.String(), tenantID, v.Digest, v.Source, string(doc), string(ign), at); err != nil {
		return false, fmt.Errorf("failed to store sensor manifest: %w", err)
	}

	// Prune: versions beyond the newest kept ones that were last seen before
	// the retention age, and every version beyond the hard cap whatever its
	// age. The current version is the newest, never pruned.
	if _, err := tx.ExecContext(ctx, `
		WITH ranked AS (
		    SELECT id, last_seen_at, row_number() OVER (ORDER BY current_since DESC, id DESC) AS n
		    FROM sensor_manifests
		    WHERE sensor_id = $1)
		DELETE FROM sensor_manifests
		WHERE id IN (
		    SELECT id FROM ranked
		    WHERE n > $4 OR (n > $3 AND last_seen_at < $2))
	`, v.SensorID.String(), at.Add(-sensor.ManifestVersionsMaxAge), sensor.ManifestVersionsKept,
		sensor.ManifestVersionsHardCap); err != nil {
		return false, fmt.Errorf("failed to prune sensor manifests: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("failed to commit sensor manifest: %w", err)
	}
	return true, nil
}

// TouchManifest implements sensor.ManifestStore.
func (r *SensorRepository) TouchManifest(ctx context.Context, tenantID *shared.ID, sensorID shared.ID, digest string, at time.Time) error {
	if _, err := r.db.ExecContext(ctx,
		`UPDATE sensor_manifests SET last_seen_at = $3
		 WHERE sensor_id = $1 AND digest = $2 AND tenant_id IS NOT DISTINCT FROM $4::uuid`,
		sensorID.String(), digest, at, nullTenant(tenantID)); err != nil {
		return fmt.Errorf("failed to touch sensor manifest: %w", err)
	}
	return nil
}

const sensorManifestColumns = `m.sensor_id, m.tenant_id, m.digest, m.source, m.manifest, m.ignored,
	m.first_seen_at, m.current_since, m.last_seen_at`

// CurrentManifest implements sensor.ManifestStore.
func (r *SensorRepository) CurrentManifest(ctx context.Context, tenantID *shared.ID, sensorID shared.ID) (*sensor.ManifestVersion, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+sensorManifestColumns+`
		FROM sensor_manifests m
		JOIN sensors s ON s.id = m.sensor_id AND s.manifest_digest = m.digest
		WHERE m.sensor_id = $1 AND m.tenant_id IS NOT DISTINCT FROM $2::uuid
	`, sensorID.String(), nullTenant(tenantID))
	v, err := scanManifestVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	return v, err
}

// CurrentManifestsByTenant returns the current manifest of every sensor of
// the tenant, keyed by sensor id, in one query (the tool view reads every
// sensor's contracts at once).
func (r *SensorRepository) CurrentManifestsByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensor.ManifestVersion, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sensorManifestColumns+`
		FROM sensor_manifests m
		JOIN sensors s ON s.id = m.sensor_id AND s.manifest_digest = m.digest AND s.tenant_id = $1 AND NOT s.is_platform_sensor
		WHERE m.tenant_id = $1
	`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to read sensor manifests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]*sensor.ManifestVersion{}
	for rows.Next() {
		v, err := scanManifestVersion(rows)
		if err != nil {
			return nil, err
		}
		out[v.SensorID] = v
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read sensor manifests: %w", err)
	}
	return out, nil
}

// ListManifests implements sensor.ManifestStore.
func (r *SensorRepository) ListManifests(ctx context.Context, tenantID *shared.ID, sensorID shared.ID, limit int) ([]sensor.ManifestVersion, error) {
	if limit <= 0 || limit > sensor.ManifestVersionsKept {
		limit = sensor.ManifestVersionsKept
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sensorManifestColumns+`
		FROM sensor_manifests m
		WHERE m.sensor_id = $1 AND m.tenant_id IS NOT DISTINCT FROM $3::uuid
		ORDER BY m.current_since DESC, m.id DESC
		LIMIT $2
	`, sensorID.String(), limit, nullTenant(tenantID))
	if err != nil {
		return nil, fmt.Errorf("failed to list sensor manifests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]sensor.ManifestVersion, 0, sensor.ManifestVersionsKept) // limit is capped at it above
	for rows.Next() {
		v, err := scanManifestVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list sensor manifests: %w", err)
	}
	return out, nil
}

// nullTenant is a tenant id argument: NULL for a platform sensor.
func nullTenant(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

type manifestRowScanner interface {
	Scan(dest ...any) error
}

func scanManifestVersion(row manifestRowScanner) (*sensor.ManifestVersion, error) {
	var (
		sensorID string
		tenantID sql.NullString
		doc, ign []byte
		v        sensor.ManifestVersion
	)
	if err := row.Scan(&sensorID, &tenantID, &v.Digest, &v.Source, &doc, &ign,
		&v.FirstSeenAt, &v.CurrentSince, &v.LastSeenAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("failed to scan sensor manifest: %w", err)
	}
	v.SensorID, _ = shared.IDFromString(sensorID)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		v.TenantID = &tid
	}
	if err := json.Unmarshal(doc, &v.Manifest); err != nil {
		return nil, fmt.Errorf("failed to decode sensor manifest: %w", err)
	}
	if err := json.Unmarshal(ign, &v.Ignored); err != nil {
		return nil, fmt.Errorf("failed to decode sensor manifest ignored items: %w", err)
	}
	return &v, nil
}
