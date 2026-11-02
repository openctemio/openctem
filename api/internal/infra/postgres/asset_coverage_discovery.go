package postgres

// The discovery stages reads and nudges the coverage ledger
// (docs/architecture/easm.md, "Discovery management"). Every statement starts
// from the tenant: the ledger, the managed coverage scans and their runs and
// tasks are all filtered on tenant_id.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/coverage"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ coverage.DiscoveryStore = (*AssetCoverageRepository)(nil)

// DiscoveryStats returns, per capability, the ledger figures and the latest
// run of the tenant's managed coverage scan of that capability; task counts
// are read for an active run only.
func (r *AssetCoverageRepository) DiscoveryStats(ctx context.Context, tenantID shared.ID, capabilities []string) ([]coverage.CapabilityDiscovery, error) {
	if len(capabilities) == 0 {
		return nil, nil
	}
	byCap := map[string]*coverage.CapabilityDiscovery{}
	get := func(c string) *coverage.CapabilityDiscovery {
		if p, ok := byCap[c]; ok {
			return p
		}
		p := &coverage.CapabilityDiscovery{Capability: c}
		p.Stage, _ = coverage.DiscoveryStageOf(c)
		byCap[c] = p
		return p
	}
	if err := r.discoveryLedger(ctx, tenantID, capabilities, get); err != nil {
		return nil, err
	}
	if err := r.discoveryRuns(ctx, tenantID, capabilities, get); err != nil {
		return nil, err
	}
	out := make([]coverage.CapabilityDiscovery, 0, len(byCap))
	for _, c := range capabilities {
		if p, ok := byCap[c]; ok {
			out = append(out, *p)
		}
	}
	return out, nil
}

// discoveryLedger fills the ledger figures of each capability.
func (r *AssetCoverageRepository) discoveryLedger(ctx context.Context, tenantID shared.ID, capabilities []string, get func(string) *coverage.CapabilityDiscovery) error {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.capability,
		       count(*) FILTER (WHERE c.state <> 'not_applicable'),
		       count(*) FILTER (WHERE c.state = 'covered'),
		       count(*) FILTER (WHERE `+plannableSQL+` AND (c.next_due_at IS NULL OR c.next_due_at <= now())),
		       count(*) FILTER (WHERE c.state = 'queued'),
		       count(*) FILTER (WHERE c.state = 'failed'),
		       count(*) FILTER (WHERE c.state = 'blocked'),
		       count(*) FILTER (WHERE c.state = 'paused' AND c.reason = ANY($3::text[])),
		       COALESCE(min(c.reason) FILTER (WHERE c.state = 'paused' AND c.reason = ANY($3::text[])), ''),
		       max(c.last_attempt_at), max(c.last_success_at)
		FROM asset_coverage c
		WHERE c.tenant_id = $1 AND c.capability = ANY($2::text[]) AND c.vantage = ''
		GROUP BY c.capability`,
		tenantID.String(), pq.Array(capabilities), pq.Array(coverage.ReadinessReasons()))
	if err != nil {
		return fmt.Errorf("read discovery stages ledger: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			c            string
			p            coverage.CapabilityDiscovery
			last, lastOK sql.NullTime
		)
		if err := rows.Scan(&c, &p.Pairs, &p.Covered, &p.DueNow, &p.Queued, &p.Failed, &p.Blocked,
			&p.Paused, &p.PausedReason, &last, &lastOK); err != nil {
			return err
		}
		dst := get(c)
		p.Capability, p.Stage = dst.Capability, dst.Stage
		p.LastAttemptAt, p.LastSuccessAt = nullTimeValue(last), nullTimeValue(lastOK)
		*dst = p
	}
	return rows.Err()
}

// discoveryRuns fills the latest run of each capability's managed coverage
// scan, with the task counts of an active one.
func (r *AssetCoverageRepository) discoveryRuns(ctx context.Context, tenantID shared.ID, capabilities []string, get func(string) *coverage.CapabilityDiscovery) error {
	rows, err := r.db.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (s.managed_key) s.managed_key, sr.id, sr.status, sr.created_at, sr.started_at, sr.completed_at
			FROM scans s
			JOIN scan_runs sr ON sr.tenant_id = s.tenant_id AND sr.scan_id = s.id
			WHERE s.tenant_id = $1 AND s.managed_by = $2 AND s.managed_key = ANY($3::text[])
			ORDER BY s.managed_key, sr.created_at DESC, sr.id DESC
		)
		SELECT l.managed_key, l.id, COALESCE(l.status, ''), l.created_at, l.started_at, l.completed_at,
		       COALESCE(t.total, 0), COALESCE(t.done, 0)
		FROM latest l
		LEFT JOIN LATERAL (
			SELECT count(*) AS total,
			       count(*) FILTER (WHERE cm.status IN ('completed', 'failed', 'canceled', 'expired')) AS done
			FROM commands cm
			JOIN scan_run_steps st ON st.id = cm.scan_run_step_id AND st.scan_run_id = l.id
			WHERE cm.tenant_id = $1 AND l.status IN ('pending', 'running')
		) t ON true`,
		tenantID.String(), string(scan.ManagedByCoverage), pq.Array(capabilities))
	if err != nil {
		return fmt.Errorf("read discovery stages runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			c, id     string
			run       coverage.CapabilityRun
			started   sql.NullTime
			completed sql.NullTime
		)
		if err := rows.Scan(&c, &id, &run.Status, &run.CreatedAt, &started, &completed, &run.TasksTotal, &run.TasksDone); err != nil {
			return err
		}
		run.RunID = id
		run.StartedAt, run.CompletedAt = nullTimeValue(started), nullTimeValue(completed)
		get(c).LastRun = &run
	}
	return rows.Err()
}

// MakeDueNow moves the due time of plannable pairs (covered, due, failed)
// of the given capabilities to now minus each capability's wait. Pairs never
// scheduled (no due time) are due already and are left as they are, so are
// pairs already due long enough.
func (r *AssetCoverageRepository) MakeDueNow(ctx context.Context, tenantID shared.ID, waits map[string]time.Duration) (int, error) {
	if len(waits) == 0 {
		return 0, nil
	}
	caps := make([]string, 0, len(waits))
	secs := make([]float64, 0, len(waits))
	for c, w := range waits {
		caps = append(caps, c)
		secs = append(secs, max(w, 0).Seconds())
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE asset_coverage c SET next_due_at = now() - make_interval(secs => w.secs), updated_at = now()
		FROM unnest($2::text[], $3::float8[]) AS w(cap, secs)
		WHERE c.tenant_id = $1 AND c.capability = w.cap AND c.vantage = ''
		  AND c.state IN ('covered', 'due', 'failed')
		  AND c.next_due_at IS NOT NULL
		  AND c.next_due_at > now() - make_interval(secs => w.secs)`,
		tenantID.String(), pq.Array(caps), pq.Array(secs))
	if err != nil {
		return 0, fmt.Errorf("make coverage due: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ActiveCoverageRuns returns the tenant's unfinished runs of managed
// coverage scans.
func (r *AssetCoverageRepository) ActiveCoverageRuns(ctx context.Context, tenantID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT sr.id FROM scan_runs sr
		JOIN scans s ON s.tenant_id = sr.tenant_id AND s.id = sr.scan_id
		WHERE sr.tenant_id = $1 AND s.managed_by = $2 AND sr.status IN ('pending', 'running')
		ORDER BY sr.created_at`, tenantID.String(), string(scan.ManagedByCoverage))
	if err != nil {
		return nil, fmt.Errorf("list active coverage runs: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		if rid, err := shared.IDFromString(id); err == nil {
			out = append(out, rid)
		}
	}
	return out, rows.Err()
}

// LastAutoValidation counts the assets whose automatic attribution (no
// person decided it) was written during the latest run of the given
// capabilities, up to coverage.AutoValidationSettle after it ended.
func (r *AssetCoverageRepository) LastAutoValidation(ctx context.Context, tenantID shared.ID, capabilities []string) (coverage.AutoValidation, error) {
	var out coverage.AutoValidation
	if len(capabilities) == 0 {
		return out, nil
	}
	var start, end sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		WITH last AS (
			SELECT COALESCE(sr.started_at, sr.created_at) AS start_at,
			       CASE WHEN sr.completed_at IS NULL THEN now()
			            ELSE sr.completed_at + make_interval(secs => $4) END AS end_at
			FROM scan_runs sr
			JOIN scans s ON s.tenant_id = sr.tenant_id AND s.id = sr.scan_id
			WHERE sr.tenant_id = $1 AND s.managed_by = $2 AND s.managed_key = ANY($3::text[])
			ORDER BY sr.created_at DESC, sr.id DESC
			LIMIT 1
		)
		SELECT last.start_at, last.end_at,
		       (SELECT count(*) FROM asset_attributions aa
		        WHERE aa.tenant_id = $1 AND aa.decided_at IS NULL
		          AND aa.updated_at >= last.start_at AND aa.updated_at <= last.end_at)
		FROM last`,
		tenantID.String(), string(scan.ManagedByCoverage), pq.Array(capabilities),
		coverage.AutoValidationSettle.Seconds()).Scan(&start, &end, &out.Assets)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, fmt.Errorf("count last auto-validation: %w", err)
	}
	out.WindowStart, out.WindowEnd = nullTimeValue(start), nullTimeValue(end)
	return out, nil
}

// DiscoveryRunLimiter limits Run of a discovery stage across replicas with a
// lease per key that is never released: the next Run is allowed once it
// expires. Keys name the tenant (coverageapp builds them from the
// principal's tenant), so one tenant's lease never limits another's.
type DiscoveryRunLimiter struct {
	db     *DB
	leases *ControllerLeaseRepository
}

// NewDiscoveryRunLimiter creates the limiter.
func NewDiscoveryRunLimiter(db *DB) *DiscoveryRunLimiter {
	return &DiscoveryRunLimiter{db: db, leases: NewControllerLeaseRepository(db)}
}

// Acquire takes key for window; when it is held it returns false and its
// expiry.
func (l *DiscoveryRunLimiter) Acquire(ctx context.Context, key string, window time.Duration) (bool, time.Time, error) {
	_, ok, err := l.leases.TryAcquire(ctx, key, LeaseHolderID(), window)
	if err != nil || ok {
		return ok, time.Time{}, err
	}
	until, err := l.AvailableAt(ctx, []string{key})
	return false, until[key], err
}

// AvailableAt returns the expiry of each held key.
func (l *DiscoveryRunLimiter) AvailableAt(ctx context.Context, keys []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := l.db.QueryContext(ctx, `SELECT name, expires_at FROM controller_leases
		WHERE name = ANY($1::text[]) AND expires_at > now()`, pq.Array(keys))
	if err != nil {
		return nil, fmt.Errorf("read discovery run leases: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			name string
			at   time.Time
		)
		if err := rows.Scan(&name, &at); err != nil {
			return nil, err
		}
		out[name] = at
	}
	return out, rows.Err()
}
