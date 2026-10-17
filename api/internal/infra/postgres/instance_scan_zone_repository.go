package postgres

// Instance scan zones (docs/rfcs/RFC-100-shared-sensors.md §6.1). Written
// only by the admin console service. ListForTenant returns only the zones
// assigned to the organization that asks: that filter is what tells
// overlapping ranges of different organizations apart.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/instancezone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// InstanceScanZoneRepository implements instancezone.Repository.
type InstanceScanZoneRepository struct{ db *DB }

// NewInstanceScanZoneRepository creates the repository.
func NewInstanceScanZoneRepository(db *DB) *InstanceScanZoneRepository {
	return &InstanceScanZoneRepository{db: db}
}

var _ instancezone.Repository = (*InstanceScanZoneRepository)(nil)

const instanceZoneSelect = `
	SELECT z.id, z.name, z.description, z.ranges::text[],
	       COALESCE((SELECT array_agg(s.sensor_id::text ORDER BY s.sensor_id) FROM instance_scan_zone_sensors s WHERE s.zone_id = z.id), '{}'),
	       COALESCE((SELECT array_agg(t.tenant_id::text ORDER BY t.tenant_id) FROM instance_scan_zone_tenants t WHERE t.zone_id = z.id), '{}')
	  FROM instance_scan_zones z`

func instanceZoneNameTaken(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "uq_instance_scan_zones_name"
}

// Create inserts the zone (no sensors or organizations yet).
func (r *InstanceScanZoneRepository) Create(ctx context.Context, z *instancezone.Zone, by *shared.ID) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO instance_scan_zones (id, name, description, ranges, created_by)
		VALUES ($1, $2, $3, $4::cidr[], $5)`,
		z.ID.String(), z.Name, z.Description, pq.Array(z.Ranges), nullIDString(by))
	if instanceZoneNameTaken(err) {
		return instancezone.ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("create instance scan zone: %w", err)
	}
	return nil
}

// Update changes the name, description and ranges.
func (r *InstanceScanZoneRepository) Update(ctx context.Context, z *instancezone.Zone) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE instance_scan_zones SET name = $2, description = $3, ranges = $4::cidr[], updated_at = now()
		 WHERE id = $1`, z.ID.String(), z.Name, z.Description, pq.Array(z.Ranges))
	if instanceZoneNameTaken(err) {
		return instancezone.ErrNameTaken
	}
	if err != nil {
		return fmt.Errorf("update instance scan zone: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return instancezone.ErrNotFound
	}
	return nil
}

// Delete removes the zone with its sensors and assignments.
func (r *InstanceScanZoneRepository) Delete(ctx context.Context, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM instance_scan_zones WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("delete instance scan zone: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return instancezone.ErrNotFound
	}
	return nil
}

// Get returns one zone.
func (r *InstanceScanZoneRepository) Get(ctx context.Context, id shared.ID) (*instancezone.Zone, error) {
	zones, err := r.query(ctx, instanceZoneSelect+` WHERE z.id = $1`, id.String())
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, instancezone.ErrNotFound
	}
	return zones[0], nil
}

// List returns every zone, by name.
func (r *InstanceScanZoneRepository) List(ctx context.Context) ([]*instancezone.Zone, error) {
	return r.query(ctx, instanceZoneSelect+` ORDER BY lower(z.name) LIMIT 1000`)
}

// ListForTenant returns the zones assigned to the organization.
func (r *InstanceScanZoneRepository) ListForTenant(ctx context.Context, tenantID shared.ID) ([]*instancezone.Zone, error) {
	return r.query(ctx, instanceZoneSelect+`
		 WHERE EXISTS (SELECT 1 FROM instance_scan_zone_tenants t WHERE t.zone_id = z.id AND t.tenant_id = $1)
		 ORDER BY z.id`, tenantID.String())
}

// SetSensors replaces the zone's sensors in one transaction. The trigger
// refuses a sensor that is not a shared sensor.
func (r *InstanceScanZoneRepository) SetSensors(ctx context.Context, id shared.ID, sensorIDs []shared.ID, by *shared.ID) error {
	return r.replace(ctx, id, "instance_scan_zone_sensors", "sensor_id", sensorIDs, by)
}

// SetTenants replaces the organizations the zone is assigned to.
func (r *InstanceScanZoneRepository) SetTenants(ctx context.Context, id shared.ID, tenantIDs []shared.ID, by *shared.ID) error {
	return r.replace(ctx, id, "instance_scan_zone_tenants", "tenant_id", tenantIDs, by)
}

// replace swaps the member rows of one link table (a fixed table and
// column, never caller input).
func (r *InstanceScanZoneRepository) replace(ctx context.Context, id shared.ID, table, column string, ids []shared.ID, by *shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var locked string
	err = tx.QueryRowContext(ctx, `SELECT id FROM instance_scan_zones WHERE id = $1 FOR UPDATE`, id.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return instancezone.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("lock instance scan zone: %w", err)
	}
	//nolint:gosec // table and column are constants of this file
	if _, err := tx.ExecContext(ctx, `DELETE FROM `+table+` WHERE zone_id = $1`, id.String()); err != nil {
		return fmt.Errorf("clear %s: %w", table, err)
	}
	strs := make([]string, 0, len(ids))
	for _, m := range ids {
		strs = append(strs, m.String())
	}
	if len(strs) > 0 {
		//nolint:gosec // table and column are constants of this file
		_, err = tx.ExecContext(ctx, `
			INSERT INTO `+table+` (zone_id, `+column+`, created_by)
			SELECT $1, m::uuid, $3 FROM unnest($2::text[]) AS m ON CONFLICT DO NOTHING`,
			id.String(), pq.Array(strs), nullIDString(by))
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && (pqErr.Code == "23514" || pqErr.Code == "23503") {
			return fmt.Errorf("%w: %s", shared.ErrValidation, memberRefusal(column))
		}
		if err != nil {
			return fmt.Errorf("set %s: %w", table, err)
		}
	}
	return tx.Commit()
}

func memberRefusal(column string) string {
	if column == "sensor_id" {
		return "every sensor must be an existing shared sensor"
	}
	return "every organization must exist"
}

func (r *InstanceScanZoneRepository) query(ctx context.Context, q string, args ...any) ([]*instancezone.Zone, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list instance scan zones: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*instancezone.Zone
	for rows.Next() {
		var (
			id                       string
			ranges, sensors, tenants pq.StringArray
			z                        instancezone.Zone
		)
		if err := rows.Scan(&id, &z.Name, &z.Description, &ranges, &sensors, &tenants); err != nil {
			return nil, fmt.Errorf("scan instance scan zone: %w", err)
		}
		if z.ID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		z.Ranges = make([]string, 0, len(ranges))
		for _, s := range ranges {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("instance scan zone %s: stored range %q: %w", id, s, err)
			}
			z.Ranges = append(z.Ranges, p.Masked().String())
		}
		sort.Strings(z.Ranges)
		if z.SensorIDs, err = parseInstanceZoneIDs(sensors); err != nil {
			return nil, err
		}
		if z.TenantIDs, err = parseInstanceZoneIDs(tenants); err != nil {
			return nil, err
		}
		out = append(out, &z)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseInstanceZoneIDs(in []string) ([]shared.ID, error) {
	out := make([]shared.ID, 0, len(in))
	for _, s := range in {
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}
