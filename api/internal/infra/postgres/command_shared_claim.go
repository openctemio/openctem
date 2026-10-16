package postgres

// The shared claim path (docs/rfcs/RFC-100-shared-sensors.md §8, RFC-090
// W11): a shared sensor (scope instance, no tenant) claims shared jobs
// (is_platform_job) of every organization, fairly. It is the only way a
// shared job is handed out; an organization sensor's claim never takes one
// (tenantJobPredicate) and a shared sensor's claim never takes anything else.

import (
	"context"
	"database/sql"
	"fmt"
	"slices"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// sharedSensorGateSQL keeps a command the shared sensor bound to $1 may run:
// the sensor is an active shared sensor (scope instance, no tenant) that
// reported the shared isolation profile and accepts unzoned jobs; it
// verified the command's tool; the command names no region or the sensor's
// region; and the sensor reported every feature the command requires.
var sharedSensorGateSQL = `EXISTS (
			SELECT 1 FROM sensors ss
			WHERE ss.id = $1
			  AND ss.scope = 'instance' AND ss.tenant_id IS NULL
			  AND ss.status = 'active'
			  AND ss.accepts_unzoned_jobs
			  AND '` + command.CapabilitySharedIsolation + `' = ANY(COALESCE(ss.reported_capabilities, ARRAY[]::text[]))
			  AND (` + commandToolSQL + ` IS NULL OR ` + commandToolSQL + ` = ANY(` + sensorDispatchTools("ss") + `))
			  AND (NULLIF(commands.payload->>'` + command.PayloadKeyPreferredRegion + `', '') IS NULL
			       OR commands.payload->>'` + command.PayloadKeyPreferredRegion + `' = ss.region)
			  AND (` + noRequiredFeaturesSQL + `
			       OR NOT EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(commands.payload->'` + command.PayloadKeyRequiredFeatures + `') AS rf(feature)
				WHERE rf.feature <> ALL(COALESCE(ss.reported_capabilities, ARRAY[]::text[]))))
		)`

// sharedClaimWhere is the shared poll's and claim's predicate for the
// shared sensor bound to $1 with the capabilities bound to $2: a shared job,
// pending, unheld, due, unexpired, unzoned (shared sensors take no zone
// work), its hosts free in its organization (the same per-host politeness
// keys as the organization's own sensors), not refused by this sensor,
// within the sensor's gates (sharedSensorGateSQL) and the capability gate.
var sharedClaimWhere = `commands.is_platform_job = TRUE
		AND commands.status = 'pending'
		AND commands.sensor_id IS NULL
		AND commands.scan_zone_id IS NULL
		AND (commands.expires_at IS NULL OR commands.expires_at > NOW())
		AND ` + scheduledDuePredicate + `
		AND ` + hostFreePredicate + `
		AND ` + refusedByPredicate("$1") + `
		AND ` + sharedSensorGateSQL + `
		AND ` + capabilityClaimPredicate("$2")

// GetSharedPendingForSensor returns the shared jobs the shared sensor may
// claim now, at most limit, in the shared dispatch order: priority class
// (one class up per 30 minutes waited, never into critical), then the
// organization with the fewest shared jobs in flight (shared sensors are
// shared fairly across organizations), then queue priority and age.
func (r *CommandRepository) GetSharedPendingForSensor(ctx context.Context, sensorID shared.ID, capabilities []string, limit int) ([]*command.Command, error) {
	if limit <= 0 {
		limit = 1
	}
	query := `
		WITH cand AS (
			SELECT commands.id AS c_id, ` + claimClassSQL + ` AS c_cls
			FROM commands
			WHERE ` + sharedClaimWhere + `
			ORDER BY c_cls, commands.created_at
			LIMIT ` + fmt.Sprint(fairCandidateWindow) + `
		), load AS (
			SELECT l.tenant_id AS l_tenant, count(*) AS l_n
			FROM commands l
			WHERE l.is_platform_job = TRUE AND l.status IN ('acknowledged', 'running')
			GROUP BY l.tenant_id
		)
		` + r.selectQuery() + `
		JOIN cand ON cand.c_id = commands.id
		LEFT JOIN load ON load.l_tenant = commands.tenant_id
		ORDER BY cand.c_cls, COALESCE(load.l_n, 0), commands.queue_priority DESC,
		         COALESCE(commands.queued_at, commands.created_at), commands.id
		LIMIT $3`
	rows, err := r.db.QueryContext(ctx, query, sensorID.String(), pq.Array(capabilities), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get shared jobs: %w", err)
	}
	defer rows.Close()
	var out []*command.Command
	for rows.Next() {
		c, err := r.scanCommandFromRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClaimManyShared acknowledges for the shared sensor those of ids that it
// may still claim, with a lease, and returns them. Per organization, in id
// order: a transaction lock on the organization's shared jobs, then its
// shared jobs in flight are counted and the organization gets no more than
// limits[tenant] minus that count (absent from limits or negative: no
// limit; an organization at its limit gets none and its jobs wait); then
// the host locks and host checks of the organization's own claims, so a
// shared job and an organization sensor's job never take one host at once.
// The gates are re-checked at claim time (the ids came from an earlier
// read); a job of no organization the caller read is never claimed.
func (r *CommandRepository) ClaimManyShared(ctx context.Context, sensorID shared.ID, capabilities []string, ids []shared.ID, limits map[shared.ID]int) ([]shared.ID, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	want := make([]string, len(ids))
	for i, id := range ids {
		want[i] = id.String()
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to claim shared jobs: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	byTenant, tenants, err := sharedJobTenants(ctx, tx, want)
	if err != nil {
		return nil, err
	}
	keep := make([]string, 0, len(want))
	for _, tenant := range tenants {
		mine := byTenant[tenant]
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('shared-tenant|' || $1, 0))`,
			tenant.String()); err != nil {
			return nil, fmt.Errorf("failed to lock the organization's shared jobs: %w", err)
		}
		if limit, ok := limits[tenant]; ok && limit >= 0 {
			var inFlight int
			if err := tx.QueryRowContext(ctx, `
				SELECT count(*) FROM commands
				WHERE tenant_id = $1 AND is_platform_job = TRUE AND status IN ('acknowledged', 'running')`,
				tenant.String()).Scan(&inFlight); err != nil {
				return nil, fmt.Errorf("failed to count the organization's shared jobs: %w", err)
			}
			mine = mine[:min(len(mine), max(0, limit-inFlight))]
		}
		if len(mine) == 0 {
			continue
		}
		if err := lockHostKeys(ctx, tx, tenant, mine); err != nil {
			return nil, err
		}
		if mine, err = dropSharedHosts(ctx, tx, tenant, mine); err != nil {
			return nil, err
		}
		keep = append(keep, mine...)
	}
	if len(keep) == 0 {
		return nil, nil
	}
	out, err := claimedIDs(ctx, tx, `
		UPDATE commands c
		SET status = 'acknowledged', sensor_id = $1, acknowledged_at = NOW(),
		    lease_epoch = c.lease_epoch + 1, window_hold = NULL, window_closed_at = NULL,
		    `+clearProgressSQL+`,
		    lease_expires_at = NOW() + make_interval(secs => $4)
		WHERE c.id IN (
			SELECT commands.id FROM commands
			WHERE `+sharedClaimWhere+`
			  AND commands.id = ANY($3::uuid[])
			FOR UPDATE SKIP LOCKED
		)
		  AND c.status = 'pending' AND c.is_platform_job = TRUE
		RETURNING c.id`, []any{sensorID.String(), pq.Array(capabilities), pq.Array(keep), r.leaseSeconds()}, len(keep))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to claim shared jobs: %w", err)
	}
	return out, nil
}

// sharedJobTenants groups the shared jobs among ids by organization, each
// group in the order of ids, and lists the organizations sorted by id (the
// one lock order of every shared claim, so two claims never deadlock).
func sharedJobTenants(ctx context.Context, tx *sql.Tx, ids []string) (map[shared.ID][]string, []shared.ID, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id::text, tenant_id FROM commands WHERE id = ANY($1::uuid[]) AND is_platform_job = TRUE`, pq.Array(ids))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read shared jobs: %w", err)
	}
	defer rows.Close()
	tenantOf := map[string]shared.ID{}
	for rows.Next() {
		var id, tenant string
		if err := rows.Scan(&id, &tenant); err != nil {
			return nil, nil, fmt.Errorf("failed to read shared jobs: %w", err)
		}
		tid, err := shared.IDFromString(tenant)
		if err != nil {
			continue
		}
		tenantOf[id] = tid
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("failed to read shared jobs: %w", err)
	}
	byTenant := map[shared.ID][]string{}
	var tenants []shared.ID
	for _, id := range ids {
		tid, ok := tenantOf[id]
		if !ok {
			continue
		}
		if _, seen := byTenant[tid]; !seen {
			tenants = append(tenants, tid)
		}
		byTenant[tid] = append(byTenant[tid], id)
	}
	slices.SortFunc(tenants, func(a, b shared.ID) int {
		switch as, bs := a.String(), b.String(); {
		case as < bs:
			return -1
		case as > bs:
			return 1
		}
		return 0
	})
	return byTenant, tenants, nil
}

// CountHeldSharedScans counts the shared scan jobs the shared sensor holds
// (acknowledged or running), in every organization.
func (r *CommandRepository) CountHeldSharedScans(ctx context.Context, sensorID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM commands
		WHERE sensor_id = $1 AND is_platform_job = TRUE AND type = 'scan'
		  AND status IN ('acknowledged', 'running')`, sensorID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to count held shared jobs: %w", err)
	}
	return n, nil
}

// HeldSharedJobs returns, by organization, the ids among ids of the shared
// jobs the shared sensor holds (acknowledged or running). The organization
// is read from each command; ids that are not well-formed, not shared jobs
// or not held by the sensor are left out.
func (r *CommandRepository) HeldSharedJobs(ctx context.Context, sensorID shared.ID, ids []string) (map[shared.ID][]string, error) {
	valid := validIDs(ids)
	if len(valid) == 0 {
		return map[shared.ID][]string{}, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT id::text, tenant_id FROM commands
		WHERE sensor_id = $1 AND is_platform_job = TRUE AND status IN ('acknowledged', 'running')
		  AND id = ANY($2::uuid[])
		ORDER BY id`, sensorID.String(), pq.Array(valid))
	if err != nil {
		return nil, fmt.Errorf("failed to read held shared jobs: %w", err)
	}
	defer rows.Close()
	out := map[shared.ID][]string{}
	for rows.Next() {
		var id, tenant string
		if err := rows.Scan(&id, &tenant); err != nil {
			return nil, fmt.Errorf("failed to read held shared jobs: %w", err)
		}
		if tid, err := shared.IDFromString(tenant); err == nil {
			out[tid] = append(out[tid], id)
		}
	}
	return out, rows.Err()
}

// RenewSharedLeases extends the leases of the shared jobs among ids that the
// shared sensor holds (acknowledged or running), in whatever organization.
func (r *CommandRepository) RenewSharedLeases(ctx context.Context, sensorID shared.ID, ids []string) (int64, error) {
	valid := validIDs(ids)
	if len(valid) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET lease_expires_at = NOW() + make_interval(secs => $3)
		WHERE sensor_id = $1 AND is_platform_job = TRUE
		  AND status IN ('acknowledged', 'running')
		  AND id = ANY($2::uuid[])`, sensorID.String(), pq.Array(valid), r.leaseSeconds())
	if err != nil {
		return 0, fmt.Errorf("failed to renew shared job leases: %w", err)
	}
	return res.RowsAffected()
}

// SharedCommandsToCancel is CommandsToCancel for a shared sensor: every
// well-formed id among ids except the shared jobs it still holds
// (acknowledged or running) or completed. A command it does not hold, of any
// organization, is reported like an unknown one.
func (r *CommandRepository) SharedCommandsToCancel(ctx context.Context, sensorID shared.ID, ids []string) ([]string, error) {
	valid := validIDs(ids)
	if len(valid) == 0 {
		return nil, nil
	}
	return r.textIDs(ctx, `
		SELECT DISTINCT r.id
		FROM unnest($2::text[]) AS r(id)
		WHERE NOT EXISTS (
			SELECT 1 FROM commands c
			WHERE c.id = r.id::uuid AND c.sensor_id = $1 AND c.is_platform_job = TRUE
			  AND c.status IN ('acknowledged', 'running', 'completed'))
		ORDER BY r.id`, sensorID.String(), pq.Array(valid))
}

// SharedCommandsToStop is CommandsToStop for a shared sensor: the shared
// jobs among ids it holds, running and stop-requested.
func (r *CommandRepository) SharedCommandsToStop(ctx context.Context, sensorID shared.ID, ids []string) ([]string, error) {
	valid := validIDs(ids)
	if len(valid) == 0 {
		return nil, nil
	}
	return r.textIDs(ctx, `
		SELECT c.id::text FROM commands c
		WHERE c.sensor_id = $1 AND c.is_platform_job = TRUE AND c.status = 'running'
		  AND c.stop_requested_at IS NOT NULL
		  AND c.id = ANY($2::uuid[])
		ORDER BY c.id`, sensorID.String(), pq.Array(valid))
}

func (r *CommandRepository) textIDs(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to read command ids: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to read command ids: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// validIDs keeps the well-formed ids.
func validIDs(ids []string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := shared.IDFromString(id); err == nil {
			out = append(out, id)
		}
	}
	return out
}
