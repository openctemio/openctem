package postgres

// Per-sensor DNS answers of host names (vantage points). Design:
// docs/architecture/scan-zones.md "Vantage resolution".

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// NameResolutionRepository stores what each sensor resolved a name to.
type NameResolutionRepository struct {
	db *DB
}

// NewNameResolutionRepository creates the repository.
func NewNameResolutionRepository(db *DB) *NameResolutionRepository {
	return &NameResolutionRepository{db: db}
}

var (
	_ scanzone.VantageReader = (*NameResolutionRepository)(nil)
	_ scanzone.VantageWriter = (*NameResolutionRepository)(nil)
)

// Bounds of one write and one read.
const (
	maxVantageNamesPerWrite = 5000
	maxVantageNamesPerRead  = 10000
	maxVantageNameLen       = 253
)

// RecordAnswers upserts the sensor's latest answer for each name. Names are
// lower-cased and bounded, addresses de-duplicated and capped at
// scanzone.MaxAnswerAddrs; a name without a valid address is skipped (no
// answer is not recorded here: asset_resolution keeps that state).
func (r *NameResolutionRepository) RecordAnswers(ctx context.Context, tenantID, sensorID shared.ID, zoneID *shared.ID, answers map[string][]netip.Addr, at time.Time) error {
	if len(answers) == 0 {
		return nil
	}
	names := make([]string, 0, min(len(answers), maxVantageNamesPerWrite))
	lists := make([]string, 0, cap(names))
	for name, addrs := range answers {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
		if n == "" || len(n) > maxVantageNameLen {
			continue
		}
		seen := map[netip.Addr]bool{}
		vals := make([]string, 0, min(len(addrs), scanzone.MaxAnswerAddrs))
		for _, a := range addrs {
			a = a.Unmap()
			if !a.IsValid() || seen[a] {
				continue
			}
			seen[a] = true
			vals = append(vals, a.String())
			if len(vals) == scanzone.MaxAnswerAddrs {
				break
			}
		}
		if len(vals) == 0 {
			continue
		}
		names = append(names, n)
		// One text per name: comma-joined addresses (an address never holds
		// a comma), split back in SQL.
		lists = append(lists, strings.Join(vals, ","))
		if len(names) == maxVantageNamesPerWrite {
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	var zone any
	if zoneID != nil {
		zone = zoneID.String()
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO name_resolutions (tenant_id, name, sensor_id, zone_id, addrs, observed_at)
		SELECT $1, n.name, $2, $3::uuid, string_to_array(n.addrs, ','), $6
		FROM unnest($4::text[], $5::text[]) AS n(name, addrs)
		-- The sensor must be the tenant's own: never another tenant's.
		WHERE EXISTS (SELECT 1 FROM sensors s WHERE s.id = $2 AND s.tenant_id = $1)
		ON CONFLICT (tenant_id, name, sensor_id) DO UPDATE
		SET zone_id = EXCLUDED.zone_id, addrs = EXCLUDED.addrs, observed_at = EXCLUDED.observed_at
		WHERE name_resolutions.observed_at <= EXCLUDED.observed_at`,
		tenantID.String(), sensorID.String(), zone, pq.Array(names), pq.Array(lists), at)
	if err != nil {
		return fmt.Errorf("failed to record name resolutions: %w", err)
	}
	return nil
}

// VantageAnswers returns the tenant's answers for names observed since
// since. Only this tenant's rows are read.
func (r *NameResolutionRepository) VantageAnswers(ctx context.Context, tenantID shared.ID, names []string, since time.Time) (scanzone.VantageAnswers, error) {
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > maxVantageNamesPerRead {
		names = names[:maxVantageNamesPerRead]
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT name, sensor_id, zone_id, addrs, observed_at
		FROM name_resolutions
		WHERE tenant_id = $1 AND name = ANY($2::text[]) AND observed_at >= $3`,
		tenantID.String(), pq.Array(names), since)
	if err != nil {
		return nil, fmt.Errorf("failed to read name resolutions: %w", err)
	}
	defer rows.Close()
	out := scanzone.VantageAnswers{}
	for rows.Next() {
		var (
			name, sensor string
			zone         *string
			addrs        []string
			at           time.Time
		)
		if err := rows.Scan(&name, &sensor, &zone, pq.Array(&addrs), &at); err != nil {
			return nil, fmt.Errorf("failed to scan name resolution: %w", err)
		}
		sid, err := shared.IDFromString(sensor)
		if err != nil {
			continue
		}
		a := scanzone.Answer{Observer: sid, ObservedAt: at}
		if zone != nil {
			if zid, err := shared.IDFromString(*zone); err == nil {
				a.ZoneID = &zid
			}
		}
		for _, s := range addrs {
			if ad, err := netip.ParseAddr(s); err == nil {
				a.Addrs = append(a.Addrs, ad)
			}
		}
		if len(a.Addrs) > 0 {
			out[name] = append(out[name], a)
		}
	}
	return out, rows.Err()
}
