package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorGrantRepository persists per-sensor grants (sensor_grants,
// docs/rfcs/RFC-052-sensor-pairing-and-authorization.md §5). Every query is
// scoped by tenant: a sensor of another tenant reads as not found.
type SensorGrantRepository struct {
	db *DB
}

// NewSensorGrantRepository creates a SensorGrantRepository.
func NewSensorGrantRepository(db *DB) *SensorGrantRepository {
	return &SensorGrantRepository{db: db}
}

var _ sensordom.GrantRepository = (*SensorGrantRepository)(nil)

// The trust level lives on the sensor row (sensors.trust_level); a grant is
// always read joined with its sensor, in the same tenant.
const sensorGrantColumns = `g.tenant_id, g.sensor_id, g.profile, s.trust_level, g.job_types, g.zone_ids, g.tools,
	g.capabilities, g.tier_ceiling, g.target_network, g.target_cidrs, g.target_domains, g.allow_credentials,
	g.allow_push_ingest, g.remote_actions, g.version, g.updated_by, g.created_at, g.updated_at`

const sensorGrantFrom = ` FROM sensor_grants g JOIN sensors s ON s.id = g.sensor_id AND s.tenant_id = g.tenant_id`

// sensorGrantTenantFrom is sensorGrantFrom for the tenant's console lists:
// the grants of the tenant's own sensors, never a shared platform sensor's.
const sensorGrantTenantFrom = sensorGrantFrom + ` AND NOT s.is_platform_sensor`

// Get returns the grant of a sensor of the tenant.
func (r *SensorGrantRepository) Get(ctx context.Context, tenantID, sensorID shared.ID) (*sensordom.Grant, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sensorGrantColumns+sensorGrantFrom+`
		WHERE g.tenant_id = $1 AND g.sensor_id = $2`, tenantID.String(), sensorID.String())
	return scanSensorGrant(row)
}

// Update writes g if the stored version is still g.Version, and bumps it.
func (r *SensorGrantRepository) Update(ctx context.Context, g *sensordom.Grant) (bool, error) {
	args := grantArgs(g)
	args = append(args, g.Version)
	// One statement: the grant row (compare-and-swap on the version) and the
	// sensor's trust level change together or not at all.
	res, err := r.db.ExecContext(ctx, `WITH g AS (
		UPDATE sensor_grants SET
		profile = $3, job_types = $5, zone_ids = $6, tools = $7, capabilities = $8,
		tier_ceiling = $9, target_network = $10, target_cidrs = $11, target_domains = $12,
		allow_credentials = $13, allow_push_ingest = $14, remote_actions = $15, updated_by = $16,
		version = version + 1, updated_at = NOW()
		WHERE tenant_id = $1 AND sensor_id = $2 AND version = $17
		RETURNING sensor_id, tenant_id)
		UPDATE sensors s SET trust_level = $4 FROM g WHERE s.id = g.sensor_id AND s.tenant_id = g.tenant_id`, args...)
	if err != nil {
		return false, fmt.Errorf("update sensor grant: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("update sensor grant: %w", err)
	}
	return n == 1, nil
}

// ReplaceTx writes g inside tx whatever the stored version (inserting it
// when the row is missing), and bumps the version.
func (r *SensorGrantRepository) ReplaceTx(ctx context.Context, tx *sql.Tx, g *sensordom.Grant) error {
	_, err := tx.ExecContext(ctx, `WITH t AS (
		UPDATE sensors SET trust_level = $4 WHERE tenant_id = $1 AND id = $2 RETURNING id)
		INSERT INTO sensor_grants (tenant_id, sensor_id, profile,
		job_types, zone_ids, tools, capabilities, tier_ceiling, target_network, target_cidrs, target_domains,
		allow_credentials, allow_push_ingest, remote_actions, updated_by)
		SELECT $1, t.id, $3, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
		FROM t
		ON CONFLICT (sensor_id) DO UPDATE SET
		profile = EXCLUDED.profile, job_types = EXCLUDED.job_types,
		zone_ids = EXCLUDED.zone_ids, tools = EXCLUDED.tools, capabilities = EXCLUDED.capabilities,
		tier_ceiling = EXCLUDED.tier_ceiling, target_network = EXCLUDED.target_network,
		target_cidrs = EXCLUDED.target_cidrs, target_domains = EXCLUDED.target_domains,
		allow_credentials = EXCLUDED.allow_credentials, allow_push_ingest = EXCLUDED.allow_push_ingest,
		remote_actions = EXCLUDED.remote_actions, updated_by = EXCLUDED.updated_by,
		version = sensor_grants.version + 1, updated_at = NOW()
		WHERE sensor_grants.tenant_id = EXCLUDED.tenant_id`, grantArgs(g)...)
	if err != nil {
		return fmt.Errorf("replace sensor grant: %w", err)
	}
	return nil
}

func grantArgs(g *sensordom.Grant) []any {
	var updatedBy any
	if g.UpdatedBy != nil {
		updatedBy = g.UpdatedBy.String()
	}
	return []any{
		g.TenantID.String(), g.SensorID.String(), g.Profile, string(g.TrustLevel),
		nullableTextArray(g.JobTypes), nullableIDArray(g.ZoneIDs), nullableTextArray(g.Tools), nullableTextArray(g.Capabilities),
		g.TierCeiling, string(g.TargetNetwork), nullableTextArray(g.TargetCIDRs), nullableTextArray(g.TargetDomains),
		g.AllowCredentials, g.AllowPushIngest, pq.Array(nonNilStrings(g.RemoteActions)), updatedBy,
	}
}

// nullableTextArray keeps the nil / empty distinction: nil is SQL NULL (no
// limit), an empty slice is '{}' (nothing).
func nullableTextArray(v []string) any {
	if v == nil {
		return nil
	}
	return pq.Array(v)
}

func nullableIDArray(v []shared.ID) any {
	if v == nil {
		return nil
	}
	s := make([]string, len(v))
	for i, id := range v {
		s[i] = id.String()
	}
	return pq.Array(s)
}

func scanSensorGrant(row interface{ Scan(...any) error }) (*sensordom.Grant, error) {
	var (
		g                                  sensordom.Grant
		tenantID, sensorID, trust, network string
		actions                            pq.StringArray
		updatedBy                          sql.NullString
		jobTypesArr, zonesArr, toolsArr    nullStringArray
		capArr, cidrArr, domainArr         nullStringArray
	)
	if err := row.Scan(&tenantID, &sensorID, &g.Profile, &trust, &jobTypesArr, &zonesArr, &toolsArr, &capArr,
		&g.TierCeiling, &network, &cidrArr, &domainArr, &g.AllowCredentials, &g.AllowPushIngest,
		&actions, &g.Version, &updatedBy, &g.CreatedAt, &g.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan sensor grant: %w", err)
	}
	var err error
	if g.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if g.SensorID, err = shared.IDFromString(sensorID); err != nil {
		return nil, err
	}
	g.TrustLevel, g.TargetNetwork = sensordom.TrustLevel(trust), sensordom.TargetNetwork(network)
	g.JobTypes, g.Tools, g.Capabilities = jobTypesArr.list(), toolsArr.list(), capArr.list()
	g.TargetCIDRs, g.TargetDomains = cidrArr.list(), domainArr.list()
	g.RemoteActions = []string(actions)
	if g.RemoteActions == nil {
		g.RemoteActions = []string{}
	}
	if zonesArr.valid {
		g.ZoneIDs = make([]shared.ID, 0, len(zonesArr.v))
		for _, z := range zonesArr.v {
			id, err := shared.IDFromString(z)
			if err != nil {
				return nil, err
			}
			g.ZoneIDs = append(g.ZoneIDs, id)
		}
	}
	if updatedBy.Valid {
		if id, err := shared.IDFromString(updatedBy.String); err == nil {
			g.UpdatedBy = &id
		}
	}
	return &g, nil
}

// nullStringArray scans a text[] (or uuid[]) keeping NULL apart from '{}'.
type nullStringArray struct {
	v     []string
	valid bool
}

func (a *nullStringArray) Scan(src any) error {
	if src == nil {
		a.v, a.valid = nil, false
		return nil
	}
	var s pq.StringArray
	if err := s.Scan(src); err != nil {
		return err
	}
	a.v, a.valid = []string(s), true
	if a.v == nil {
		a.v = []string{}
	}
	return nil
}

func (a nullStringArray) list() []string {
	if !a.valid {
		return nil
	}
	return a.v
}

// ZonesInTenant reports whether every id is a scan zone of the tenant (a
// grant may name only the tenant's own zones).
func (r *SensorGrantRepository) ZonesInTenant(ctx context.Context, tenantID shared.ID, ids []shared.ID) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	want := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		want[id.String()] = struct{}{}
	}
	list := make([]string, 0, len(want))
	for id := range want {
		list = append(list, id)
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scan_zones WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(list)).Scan(&n); err != nil {
		return false, fmt.Errorf("check grant zones: %w", err)
	}
	return n == len(list), nil
}

// ListSummaries returns the profile and trust level of every sensor of the
// tenant (the console's list flags: legacy-broad, New), at most limit rows.
func (r *SensorGrantRepository) ListSummaries(ctx context.Context, tenantID shared.ID, limit int) ([]sensordom.GrantSummary, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT g.sensor_id, g.profile, s.trust_level`+sensorGrantTenantFrom+`
		WHERE g.tenant_id = $1 ORDER BY g.sensor_id LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list sensor grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []sensordom.GrantSummary{}
	for rows.Next() {
		var id, profile, trust string
		if err := rows.Scan(&id, &profile, &trust); err != nil {
			return nil, fmt.Errorf("scan sensor grant: %w", err)
		}
		sid, err := shared.IDFromString(id)
		if err != nil {
			return nil, err
		}
		out = append(out, sensordom.GrantSummary{SensorID: sid, Profile: profile, TrustLevel: sensordom.TrustLevel(trust)})
	}
	return out, rows.Err()
}

// ListByTenant returns the grant of every sensor of the tenant, by sensor id
// (the tool availability view checks each sensor's grant without one query
// per sensor).
func (r *SensorGrantRepository) ListByTenant(ctx context.Context, tenantID shared.ID) (map[shared.ID]*sensordom.Grant, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+sensorGrantColumns+sensorGrantTenantFrom+`
		WHERE g.tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list sensor grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[shared.ID]*sensordom.Grant{}
	for rows.Next() {
		g, err := scanSensorGrant(rows)
		if err != nil {
			return nil, err
		}
		out[g.SensorID] = g
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list sensor grants: %w", err)
	}
	return out, nil
}
