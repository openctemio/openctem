package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorReachRepository reads what a sensor's lookups (fingerprint check,
// baseline diff, suppressions) may answer about: the targets of the commands
// it holds or recently held, its scan zones' ranges, and the assets a set of
// findings or rules sit on. Every query is scoped by tenant.
type SensorReachRepository struct {
	db *DB
}

// NewSensorReachRepository creates a SensorReachRepository.
func NewSensorReachRepository(db *DB) *SensorReachRepository {
	return &SensorReachRepository{db: db}
}

var _ ingest.ReachSource = (*SensorReachRepository)(nil)

// sensorReachMaxCommands bounds how many commands one reach reads.
const sensorReachMaxCommands = 1000

// SensorReachInputs returns the payloads of the commands assigned to the
// sensor that are open, or ended (or were created) at or after since, newest
// first, and the address ranges of the scan zones the sensor serves.
func (r *SensorReachRepository) SensorReachInputs(ctx context.Context, tenantID, sensorID shared.ID, since time.Time) (ingest.ReachInputs, error) {
	var out ingest.ReachInputs
	rows, err := r.db.QueryContext(ctx, `
		SELECT payload
		FROM commands
		WHERE tenant_id = $1 AND sensor_id = $2
		  AND (status IN ('pending', 'acknowledged', 'running')
		       OR COALESCE(completed_at, started_at, acknowledged_at, created_at) >= $3)
		ORDER BY created_at DESC
		LIMIT $4`, tenantID.String(), sensorID.String(), since, sensorReachMaxCommands)
	if err != nil {
		return out, fmt.Errorf("read sensor command targets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var p []byte
		if err := rows.Scan(&p); err != nil {
			return out, fmt.Errorf("scan command payload: %w", err)
		}
		if len(p) > 0 {
			out.CommandPayloads = append(out.CommandPayloads, json.RawMessage(p))
		}
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate command payloads: %w", err)
	}

	zrows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT rng::text
		FROM scan_zone_sensors zs
		JOIN scan_zones z ON z.id = zs.zone_id AND z.tenant_id = zs.tenant_id
		CROSS JOIN LATERAL unnest(z.ranges) AS rng
		WHERE zs.tenant_id = $1 AND zs.sensor_id = $2`, tenantID.String(), sensorID.String())
	if err != nil {
		return out, fmt.Errorf("read sensor zone ranges: %w", err)
	}
	defer func() { _ = zrows.Close() }()
	for zrows.Next() {
		var rng string
		if err := zrows.Scan(&rng); err != nil {
			return out, fmt.Errorf("scan zone range: %w", err)
		}
		out.ZoneRanges = append(out.ZoneRanges, rng)
	}
	if err := zrows.Err(); err != nil {
		return out, fmt.Errorf("iterate zone ranges: %w", err)
	}
	return out, nil
}

// FingerprintAssetIDs maps each given fingerprint that is a finding's
// current key to the assets its findings sit on.
func (r *SensorReachRepository) FingerprintAssetIDs(ctx context.Context, tenantID shared.ID, fingerprints []string) (map[string][]shared.ID, error) {
	out := map[string][]shared.ID{}
	if len(fingerprints) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT DISTINCT fingerprint, asset_id
		FROM findings
		WHERE tenant_id = $1 AND fingerprint = ANY($2) AND asset_id IS NOT NULL`,
		tenantID.String(), pq.Array(fingerprints))
	if err != nil {
		return nil, fmt.Errorf("read finding assets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var fp, id string
		if err := rows.Scan(&fp, &id); err != nil {
			return nil, fmt.Errorf("scan finding asset: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		out[fp] = append(out[fp], aid)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate finding assets: %w", err)
	}
	return out, nil
}

// AssetLocators returns the name and properties of the tenant's assets
// among ids (an id of another tenant, or of no asset, is absent).
func (r *SensorReachRepository) AssetLocators(ctx context.Context, tenantID shared.ID, ids []shared.ID) ([]ingest.AssetLocator, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, name, COALESCE(properties, '{}'::jsonb)
		FROM assets
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID.String(), pq.Array(strs))
	if err != nil {
		return nil, fmt.Errorf("read asset locators: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ingest.AssetLocator
	for rows.Next() {
		var id, name string
		var raw []byte
		if err := rows.Scan(&id, &name, &raw); err != nil {
			return nil, fmt.Errorf("scan asset locator: %w", err)
		}
		aid, err := shared.IDFromString(id)
		if err != nil {
			continue
		}
		loc := ingest.AssetLocator{ID: aid, Name: name}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &loc.Properties)
		}
		out = append(out, loc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate asset locators: %w", err)
	}
	return out, nil
}
