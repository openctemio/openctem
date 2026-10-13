package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GrantUsage reads what a sensor of the tenant did since since, for the
// grant suggestion: the distinct jobs it was given (at most maxJobs; more
// marks the usage incomplete), whether it sent results without a job, and
// the zones it is assigned to. Every query is scoped by tenant and sensor.
func (r *SensorGrantRepository) GrantUsage(ctx context.Context, tenantID, sensorID shared.ID, since time.Time, maxJobs int) (sensordom.GrantUsage, error) {
	u := sensordom.GrantUsage{Complete: true}
	tid, sid := tenantID.String(), sensorID.String()
	rows, err := r.db.QueryContext(ctx, `
		SELECT type, payload, scan_zone_id, count(*)
		FROM commands
		WHERE tenant_id = $1 AND sensor_id = $2 AND created_at >= $3
		GROUP BY type, payload, scan_zone_id
		LIMIT $4`, tid, sid, since, maxJobs+1)
	if err != nil {
		return u, fmt.Errorf("read sensor jobs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			typ     string
			payload []byte
			zone    sql.NullString
			n       int
		)
		if err := rows.Scan(&typ, &payload, &zone, &n); err != nil {
			return u, fmt.Errorf("scan sensor job: %w", err)
		}
		if len(u.Jobs) == maxJobs {
			u.Complete = false
			break
		}
		j := sensordom.UsageJob{Type: typ, Payload: json.RawMessage(payload)}
		if zone.Valid {
			z, err := shared.IDFromString(zone.String)
			if err != nil {
				return u, err
			}
			j.ZoneID = &z
		}
		u.Jobs = append(u.Jobs, j)
		u.JobCount += n
	}
	if err := rows.Err(); err != nil {
		return u, err
	}
	if !u.Complete {
		return u, nil
	}

	// Results without a job: v2 reports with no command, the v1 queue's
	// reports, and results the unsolicited gate held for review.
	if err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM ingest_reports
		               WHERE tenant_id = $1 AND sensor_id = $2 AND command_id IS NULL AND received_at >= $3)
		    OR EXISTS (SELECT 1 FROM ingest_jobs
		               WHERE tenant_id = $1 AND sensor_id = $2 AND ingest_report_id IS NULL AND created_at >= $3)
		    OR EXISTS (SELECT 1 FROM sensor_result_quarantine
		               WHERE tenant_id = $1 AND sensor_id = $2 AND created_at >= $3)`,
		tid, sid, since).Scan(&u.PushIngest); err != nil {
		return u, fmt.Errorf("read sensor pushed results: %w", err)
	}

	zrows, err := r.db.QueryContext(ctx, `SELECT zone_id FROM scan_zone_sensors WHERE tenant_id = $1 AND sensor_id = $2`, tid, sid)
	if err != nil {
		return u, fmt.Errorf("read sensor zones: %w", err)
	}
	defer func() { _ = zrows.Close() }()
	for zrows.Next() {
		var z string
		if err := zrows.Scan(&z); err != nil {
			return u, err
		}
		id, err := shared.IDFromString(z)
		if err != nil {
			return u, err
		}
		u.AssignedZones = append(u.AssignedZones, id)
	}
	return u, zrows.Err()
}
