package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanZoneRepository implements scanzone.Repository (RFC-023 Phase 1).
// Every statement is tenant-scoped; zone/sensor membership is additionally
// enforced by the composite foreign keys of scan_zone_sensors.
type ScanZoneRepository struct {
	db *DB
}

// NewScanZoneRepository creates a ScanZoneRepository.
func NewScanZoneRepository(db *DB) *ScanZoneRepository {
	return &ScanZoneRepository{db: db}
}

var _ scanzone.Repository = (*ScanZoneRepository)(nil)

// activeCommandStatuses are the command states that still need a sensor.
const activeCommandStatuses = `('pending', 'acknowledged', 'running')`

const scanZoneSelect = `
	SELECT z.id, z.tenant_id, z.name, z.description, z.is_default, z.ranges::text[],
	       z.created_by, z.created_at, z.updated_at,
	       COALESCE(
	           array_agg(zs.sensor_id::text ORDER BY zs.sensor_id) FILTER (WHERE zs.sensor_id IS NOT NULL),
	           ARRAY[]::text[]
	       )
	FROM scan_zones z
	LEFT JOIN scan_zone_sensors zs ON zs.zone_id = z.id AND zs.tenant_id = z.tenant_id
`

// Create inserts a zone.
func (r *ScanZoneRepository) Create(ctx context.Context, z *scanzone.Zone) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_zones (id, tenant_id, name, description, is_default, ranges, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6::cidr[], $7, $8, $9)`,
		z.ID.String(), z.TenantID.String(), z.Name, z.Description, z.IsDefault,
		pq.Array(z.RangeStrings()), nullIDString(z.CreatedBy), z.CreatedAt, z.UpdatedAt)
	return mapZoneWriteError(err)
}

// Update writes a zone's mutable fields.
func (r *ScanZoneRepository) Update(ctx context.Context, z *scanzone.Zone) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE scan_zones
		SET name = $3, description = $4, is_default = $5, ranges = $6::cidr[], updated_at = $7
		WHERE tenant_id = $1 AND id = $2`,
		z.TenantID.String(), z.ID.String(), z.Name, z.Description, z.IsDefault,
		pq.Array(z.RangeStrings()), z.UpdatedAt)
	if err != nil {
		return mapZoneWriteError(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return scanzone.ErrZoneNotFound
	}
	return nil
}

func mapZoneWriteError(err error) error {
	if err == nil {
		return nil
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		if pqErr.Constraint == "uq_scan_zones_tenant_default" {
			return scanzone.ErrDefaultZoneTaken
		}
		return scanzone.ErrZoneNameTaken
	}
	if isCheckViolation(err) {
		return fmt.Errorf("%w: scan zone violates a constraint", shared.ErrValidation)
	}
	return fmt.Errorf("write scan zone: %w", err)
}

// Delete removes a zone unless commands routed to it are still active. The
// zone row is locked first so a concurrent assignment cannot interleave.
func (r *ScanZoneRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var locked string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM scan_zones WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenantID.String(), id.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return scanzone.ErrZoneNotFound
	}
	if err != nil {
		return fmt.Errorf("lock scan zone: %w", err)
	}

	var active bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM commands
			WHERE tenant_id = $1 AND scan_zone_id = $2 AND status IN `+activeCommandStatuses+`
		)`, tenantID.String(), id.String()).Scan(&active); err != nil {
		return fmt.Errorf("check active commands: %w", err)
	}
	if active {
		return scanzone.ErrZoneInUse
	}

	// Scans that pin their targets to this zone would fail closed on their
	// next trigger; refuse instead, so the admin moves them first.
	var pinned int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM scans WHERE tenant_id = $1 AND scan_zone_id = $2`,
		tenantID.String(), id.String()).Scan(&pinned); err != nil {
		return fmt.Errorf("check scans using scan zone: %w", err)
	}
	if pinned > 0 {
		return scanzone.ErrZoneSelectedByScans(pinned)
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM scan_zones WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String()); err != nil {
		return fmt.Errorf("delete scan zone: %w", err)
	}
	return tx.Commit()
}

// GetByID returns one zone of the tenant.
func (r *ScanZoneRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scanzone.Zone, error) {
	rows, err := r.db.QueryContext(ctx, scanZoneSelect+`
		WHERE z.tenant_id = $1 AND z.id = $2
		GROUP BY z.id`, tenantID.String(), id.String())
	if err != nil {
		return nil, fmt.Errorf("get scan zone: %w", err)
	}
	zones, err := scanZones(rows)
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, scanzone.ErrZoneNotFound
	}
	return zones[0], nil
}

// List returns every zone of the tenant, ordered by name.
func (r *ScanZoneRepository) List(ctx context.Context, tenantID shared.ID) ([]*scanzone.Zone, error) {
	rows, err := r.db.QueryContext(ctx, scanZoneSelect+`
		WHERE z.tenant_id = $1
		GROUP BY z.id
		ORDER BY lower(z.name), z.id
		LIMIT $2`, tenantID.String(), scanzone.MaxZonesPerTenant)
	if err != nil {
		return nil, fmt.Errorf("list scan zones: %w", err)
	}
	return scanZones(rows)
}

// Count returns how many zones the tenant has.
func (r *ScanZoneRepository) Count(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM scan_zones WHERE tenant_id = $1`, tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count scan zones: %w", err)
	}
	return n, nil
}

func scanZones(rows *sql.Rows) ([]*scanzone.Zone, error) {
	defer rows.Close()
	var out []*scanzone.Zone
	for rows.Next() {
		var (
			z                 scanzone.Zone
			id, tenantID      string
			ranges, sensorIDs pq.StringArray
			createdBy         sql.NullString
		)
		if err := rows.Scan(&id, &tenantID, &z.Name, &z.Description, &z.IsDefault, &ranges,
			&createdBy, &z.CreatedAt, &z.UpdatedAt, &sensorIDs); err != nil {
			return nil, fmt.Errorf("scan scan zone: %w", err)
		}
		var err error
		if z.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		if z.TenantID, err = shared.IDFromString(tenantID); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			if by, err := shared.IDFromString(createdBy.String); err == nil {
				z.CreatedBy = &by
			}
		}
		z.Ranges = make([]netip.Prefix, 0, len(ranges))
		for _, s := range ranges {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("stored zone range %q: %w", s, err)
			}
			z.Ranges = append(z.Ranges, p)
		}
		z.SensorIDs = make([]shared.ID, 0, len(sensorIDs))
		for _, s := range sensorIDs {
			sid, err := shared.IDFromString(s)
			if err != nil {
				return nil, err
			}
			z.SensorIDs = append(z.SensorIDs, sid)
		}
		out = append(out, &z)
	}
	return out, rows.Err()
}

// AssignSensor links a sensor to a zone. Only a non-platform sensor of the
// same tenant qualifies; the composite foreign keys reject a zone of another
// tenant even if this statement were wrong.
func (r *ScanZoneRepository) AssignSensor(ctx context.Context, tenantID, zoneID, sensorID shared.ID, assignedBy *shared.ID) error {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id, created_by)
		SELECT $1, $2, s.id, $4
		FROM sensors s
		WHERE s.id = $3 AND s.tenant_id = $1 AND NOT s.is_platform_sensor
		ON CONFLICT (zone_id, sensor_id) DO NOTHING`,
		tenantID.String(), zoneID.String(), sensorID.String(), nullIDString(assignedBy))
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23503" {
			if pqErr.Constraint == "fk_scan_zone_sensors_zone" {
				return scanzone.ErrZoneNotFound
			}
			return scanzone.ErrSensorNotFound
		}
		return fmt.Errorf("assign sensor to scan zone: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	// Nothing inserted: already assigned (fine), or not a sensor of this tenant.
	var assigned bool
	if err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM scan_zone_sensors
		               WHERE tenant_id = $1 AND zone_id = $2 AND sensor_id = $3)`,
		tenantID.String(), zoneID.String(), sensorID.String()).Scan(&assigned); err != nil {
		return fmt.Errorf("check assignment: %w", err)
	}
	if !assigned {
		return scanzone.ErrSensorNotFound
	}
	return nil
}

// UnassignSensor removes the assignment and returns the zone's still-pending
// commands pinned to that sensor to the zone pool, so another sensor of the
// zone can claim them (the claim predicate keeps them inside the zone).
func (r *ScanZoneRepository) UnassignSensor(ctx context.Context, tenantID, zoneID, sensorID shared.ID) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		DELETE FROM scan_zone_sensors
		WHERE tenant_id = $1 AND zone_id = $2 AND sensor_id = $3`,
		tenantID.String(), zoneID.String(), sensorID.String())
	if err != nil {
		return false, fmt.Errorf("unassign sensor: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE commands SET sensor_id = NULL
		WHERE tenant_id = $1 AND scan_zone_id = $2 AND sensor_id = $3 AND status = 'pending'`,
		tenantID.String(), zoneID.String(), sensorID.String()); err != nil {
		return false, fmt.Errorf("unpin zone commands: %w", err)
	}
	return true, tx.Commit()
}

// RoutableSensors returns the sensors of each zone that can take a job now,
// least busy first: fewest active commands pinned to it, then the most free
// slots (effective capacity minus the commands it holds, narrowed by a fresh
// load report, RFC-030 §5.8), then the highest reported throughput for the
// tool, then name. Tool and capacity are the
// effective ones (what the sensor reports, narrowed by its settings;
// RFC-029 §4.3.1); zone membership is never widened by a report.
func (r *ScanZoneRepository) RoutableSensors(ctx context.Context, tenantID shared.ID, zoneIDs []shared.ID, tool string) (map[shared.ID][]scanzone.SensorCandidate, error) {
	out := make(map[shared.ID][]scanzone.SensorCandidate, len(zoneIDs))
	if len(zoneIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(zoneIDs))
	for i, id := range zoneIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT zs.zone_id, s.id, s.name, `+sensorActiveCommandsSQL("s")+`, s.effective_max_jobs,
		       (SELECT count(*) FROM commands c
		        WHERE c.tenant_id = $1 AND c.sensor_id = s.id
		          AND c.status IN `+activeCommandStatuses+`) AS active_commands,
		       s.reported_local_policy
		FROM scan_zone_sensors zs
		JOIN sensors s ON s.id = zs.sensor_id AND s.tenant_id = zs.tenant_id
		WHERE zs.tenant_id = $1
		  AND zs.zone_id = ANY($2::uuid[])
		  AND s.status = 'active'
		  AND s.health IN `+sensorDispatchableHealthSQL+`
		  AND s.last_seen_at IS NOT NULL
		  AND `+sensorKeyUsableSQL("s")+`
		  AND (s.execution_mode = 'daemon' OR s.type IN ('worker', 'collector'))
		  AND ($3::text = '' OR $3::text = ANY(`+sensorDispatchTools("s")+`))
		ORDER BY zs.zone_id, active_commands ASC,
		         `+sensorFreeSlotsSQL("s")+` DESC,
		         `+sensorToolThroughputSQL("s", "$3")+` DESC NULLS LAST,
		         s.name, s.id`,
		tenantID.String(), pq.Array(ids), tool)
	if err != nil {
		return nil, fmt.Errorf("routable sensors: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			zoneID, sensorID string
			c                scanzone.SensorCandidate
			localPolicy      []byte
		)
		if err := rows.Scan(&zoneID, &sensorID, &c.Name, &c.CurrentJobs, &c.MaxConcurrentJobs, &c.ActiveCommands, &localPolicy); err != nil {
			return nil, fmt.Errorf("scan routable sensor: %w", err)
		}
		zid, err := shared.IDFromString(zoneID)
		if err != nil {
			return nil, err
		}
		if c.ID, err = shared.IDFromString(sensorID); err != nil {
			return nil, err
		}
		c.LocalPolicy, _ = scanLocalPolicy(c.ID, localPolicy, sql.NullTime{})
		out[zid] = append(out[zid], c)
	}
	return out, rows.Err()
}

// coverageAddresses is the tenant's distinct inventory IP addresses: assets
// whose name is a single IP address (ip_address assets, and hosts named by
// their address). Malformed names are skipped, never cast.
const coverageAddresses = `
	WITH addrs AS (
		SELECT DISTINCT a.name::inet AS ip
		FROM assets a
		WHERE a.deleted_at IS NULL AND a.tenant_id = $1
		  AND a.asset_type IN ('ip_address', 'host')
		  AND position('/' IN a.name) = 0
		  AND pg_input_is_valid(a.name, 'inet')
	)
`

// privateCIDRs mirrors scanzone's private address space (RFC 1918, CGNAT, ULA).
const privateCIDRs = `'{10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,fc00::/7}'::cidr[]`

// Coverage reports inventory addresses against the zones (RFC-023 V3).
func (r *ScanZoneRepository) Coverage(ctx context.Context, tenantID shared.ID) (*scanzone.Coverage, error) {
	cov := &scanzone.Coverage{}
	if err := r.db.QueryRowContext(ctx, coverageAddresses+`,
		zoned AS (
			SELECT ad.ip,
			       EXISTS (SELECT 1 FROM scan_zones z, unnest(z.ranges) AS r(c)
			               WHERE z.tenant_id = $1 AND ad.ip <<= r.c) AS in_zone,
			       ad.ip <<= ANY(`+privateCIDRs+`) AS private
			FROM addrs ad
		)
		SELECT count(*),
		       count(*) FILTER (WHERE in_zone),
		       count(*) FILTER (WHERE NOT in_zone AND NOT private),
		       count(*) FILTER (WHERE NOT in_zone AND private),
		       EXISTS (SELECT 1 FROM scan_zones WHERE tenant_id = $1 AND is_default)
		FROM zoned`, tenantID.String()).Scan(
		&cov.InventoryAddresses, &cov.InZones, &cov.OutsidePublic, &cov.OutsidePrivate, &cov.HasDefaultZone); err != nil {
		return nil, fmt.Errorf("zone coverage totals: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, coverageAddresses+`
		SELECT z.id, z.name, z.is_default,
		       EXISTS (SELECT 1 FROM unnest(z.ranges) AS r(c) WHERE r.c && ANY(`+privateCIDRs+`)) AS has_private,
		       (SELECT count(*) FROM scan_zone_sensors zs WHERE zs.tenant_id = z.tenant_id AND zs.zone_id = z.id),
		       (SELECT count(*) FROM scan_zone_sensors zs
		        JOIN sensors s ON s.id = zs.sensor_id AND s.tenant_id = zs.tenant_id
		        WHERE zs.tenant_id = z.tenant_id AND zs.zone_id = z.id
		          AND s.status = 'active' AND s.health IN `+sensorDispatchableHealthSQL+`
		          AND `+sensorKeyUsableSQL("s")+`),
		       (SELECT count(*) FROM addrs ad
		        WHERE EXISTS (SELECT 1 FROM unnest(z.ranges) AS r(c) WHERE ad.ip <<= r.c))
		FROM scan_zones z
		WHERE z.tenant_id = $1
		ORDER BY lower(z.name), z.id
		LIMIT $2`, tenantID.String(), scanzone.MaxZonesPerTenant)
	if err != nil {
		return nil, fmt.Errorf("zone coverage: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			zc scanzone.ZoneCoverage
			id string
		)
		if err := rows.Scan(&id, &zc.Name, &zc.IsDefault, &zc.HasPrivateRange,
			&zc.AssignedSensors, &zc.HealthySensors, &zc.Addresses); err != nil {
			return nil, fmt.Errorf("scan zone coverage: %w", err)
		}
		if zc.ZoneID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		cov.Zones = append(cov.Zones, zc)
	}
	return cov, rows.Err()
}
