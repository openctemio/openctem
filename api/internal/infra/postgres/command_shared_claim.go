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
	"strings"
	"time"

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
			  AND ` + sharedSensorConditions("ss") + `
		)`

// sharedSensorConditions is the part of sharedSensorGateSQL about the
// sensor aliased alias and the command: an active shared sensor (scope
// instance, no tenant) with the shared isolation profile that accepts
// unzoned jobs, verified the command's tool, is in the command's region
// when it names one and reported every feature the command requires. The
// shared re-queue check (RequeueCandidates) uses it for the other shared
// sensors a refused shared job may go to.
func sharedSensorConditions(alias string) string {
	return alias + `.scope = 'instance' AND ` + alias + `.tenant_id IS NULL
			  AND ` + alias + `.status = 'active'
			  AND ` + alias + `.accepts_unzoned_jobs
			  AND '` + command.CapabilitySharedIsolation + `' = ANY(COALESCE(` + alias + `.reported_capabilities, ARRAY[]::text[]))
			  AND (` + commandToolSQL + ` IS NULL OR ` + commandToolSQL + ` = ANY(` + sensorDispatchTools(alias) + `))
			  AND (NULLIF(commands.payload->>'` + command.PayloadKeyPreferredRegion + `', '') IS NULL
			       OR commands.payload->>'` + command.PayloadKeyPreferredRegion + `' = ` + alias + `.region)
			  AND (` + noRequiredFeaturesSQL + `
			       OR NOT EXISTS (
				SELECT 1 FROM jsonb_array_elements_text(commands.payload->'` + command.PayloadKeyRequiredFeatures + `') AS rf(feature)
				WHERE rf.feature <> ALL(COALESCE(` + alias + `.reported_capabilities, ARRAY[]::text[]))))`
}

// sharedClaimWhere is the shared poll's and claim's predicate for the
// shared sensor bound to $1 with the capabilities bound to $2: a shared job,
// pending, unheld, due, unexpired, unzoned (shared sensors take no zone
// work), its hosts free in its organization (the same per-host politeness
// keys as the organization's own sensors) and on the shared fleet
// (sharedFleetHostFreePredicate), not refused by this sensor,
// within the sensor's gates (sharedSensorGateSQL) and the capability gate.
var sharedClaimWhere = `commands.is_platform_job = TRUE
		AND commands.status = 'pending'
		AND commands.sensor_id IS NULL
		AND commands.scan_zone_id IS NULL
		AND (commands.expires_at IS NULL OR commands.expires_at > NOW())
		AND ` + scheduledDuePredicate + `
		AND ` + hostFreePredicate + `
		AND ` + sharedFleetHostFreePredicate + `
		AND ` + refusedByPredicate("$1") + `
		AND ` + failedOnPredicate("$1") + `
		AND ` + sharedSensorGateSQL + `
		AND ` + capabilityClaimPredicate("$2") + `
		AND ` + organizationActiveSQL("commands.tenant_id")

// sharedFleetHostLimitSQL is command.SharedFleetHostLimitFor of the
// command's dispatch gate.
var sharedFleetHostLimitSQL = fmt.Sprintf(`(CASE WHEN commands.dispatch_gate->>'intensity' = 'intrusive'
			     OR COALESCE(commands.dispatch_gate->>'tier', '0') NOT IN ('0', '1') THEN %d ELSE %d END)`,
	command.SharedFleetIntrusiveHostLimit, command.SharedFleetHostLimit)

// sharedFleetHostFreePredicate keeps a shared job whose hosts are free on
// the shared fleet: for no key it conflicts with do as many shared jobs of
// any organization as its limit (sharedFleetHostLimitSQL) hold that key
// unsettled. The harm of shared traffic lands on the target and the
// platform's egress whoever asked, so this check is across organizations;
// the organization's own rule (hostFreePredicate) still applies too. The
// GIN probe (&&) narrows the holders first. It reads only counts: a waiting
// job learns nothing about who holds the host. The claim re-checks it under
// lockSharedFleetHostKeysForPlatform and counts its own batch (dropSharedFleetHostsForPlatform).
var sharedFleetHostFreePredicate = `(commands.host_keys IS NULL OR NOT EXISTS (
			SELECT 1 FROM commands hk, unnest(hk.host_keys) AS hkk(k)
			WHERE hk.is_platform_job = TRUE
			  AND hk.id <> commands.id
			  AND hk.host_keys IS NOT NULL
			  AND hk.status IN ('acknowledged', 'running')
			  AND hk.host_keys && ` + hostKeyConflictsSQL + `
			  AND hkk.k = ANY(` + hostKeyConflictsSQL + `)
			  AND (hk.settled_host_keys IS NULL OR hkk.k <> ALL(hk.settled_host_keys))
			GROUP BY hkk.k
			HAVING count(DISTINCT hk.id) >= ` + sharedFleetHostLimitSQL + `))`

// sharedTenantBurst is how many of one organization's shared jobs a poll
// offers before the next organization's: jobs are offered in rounds of this
// many per organization. One organization's deep or old queue therefore never
// fills the candidate window or the poll, and an organization the claim then
// skips (not allowed, or at its in-flight limit) cannot starve the others.
const sharedTenantBurst = 5

// GetSharedPendingForSensor returns the shared jobs the shared sensor may
// claim now, at most limit, in the shared dispatch order: rounds of
// sharedTenantBurst jobs per organization (each organization's own jobs in
// class and age order), and within a round the organization with the fewest
// shared jobs in flight, then priority class (one class up per 30 minutes
// waited, never into critical), then queue priority and age.
func (r *CommandRepository) GetSharedPendingForSensor(ctx context.Context, sensorID shared.ID, capabilities []string, limit int) ([]*command.Command, error) {
	return r.GetSharedPendingForSensorExcluding(ctx, sensorID, capabilities, limit, nil)
}

// sharedTenantWindow bounds the organizations one shared poll ranks: the
// first this many, in the order of sharedOrgOrder, that have a job the sensor
// may claim now. With sharedTenantBurst jobs per organization per round it
// fills the same fairCandidateWindow as before.
const sharedTenantWindow = fairCandidateWindow / sharedTenantBurst

// sharedPriorities are the values of commands.priority (chk_command_priority)
// plus NULL. A poll reads each organization's oldest pending shared jobs per
// value through idx_commands_shared_pending: within one value, an older job
// never has a later class (aging only lifts), so the first n jobs of the
// organization in class and age order are among the first n of each value.
var sharedPriorities = []string{"critical", "high", "normal", "low", ""}

// sharedInFlightSQL counts the shared jobs in flight (acknowledged or
// running) of the organization in col, through idx_commands_shared_inflight,
// which holds no finished job.
func sharedInFlightSQL(col string) string {
	return `(SELECT count(*) FROM commands l
			WHERE l.tenant_id = ` + col + ` AND l.is_platform_job = TRUE AND l.status IN ('acknowledged', 'running'))`
}

// perRowGateSQL is the predicate where as one opaque check per row. The
// planner sees through a plain predicate: it turns the gates' EXISTS into
// joins and, from their low estimated selectivity, reads every pending job
// of the organization and sorts them instead of walking the index in order
// and stopping at the limit. A CASE keeps the gates as a per-row filter with
// a neutral estimate.
func perRowGateSQL(where string) string {
	return "(CASE WHEN " + where + " THEN TRUE ELSE FALSE END)"
}

// sharedOrgFirstJobsSQL is the first limitSQL jobs matching where of the
// organization in col, in class and age order, as (c_id, c_at, c_cls): the
// oldest of each priority value, then ordered. Each value's jobs are read in
// idx_commands_shared_pending order and the gates run on that stream, so a
// deep queue costs only the rows up to the first limitSQL that pass
// (perRowGateSQL).
func sharedOrgFirstJobsSQL(col, where, limitSQL string) string {
	parts := make([]string, 0, len(sharedPriorities))
	for _, p := range sharedPriorities {
		prio := "commands.priority IS NULL"
		if p != "" {
			prio = "commands.priority = '" + p + "'"
		}
		parts = append(parts, `(SELECT commands.id AS c_id, commands.created_at AS c_at, `+claimClassSQL+` AS c_cls
				FROM commands
				WHERE commands.tenant_id = `+col+` AND `+prio+`
				  AND commands.is_platform_job = TRUE AND commands.status = 'pending'
				  AND `+perRowGateSQL(where)+`
				ORDER BY commands.created_at, commands.id
				LIMIT `+limitSQL+`)`)
	}
	return `SELECT b.c_id, b.c_at, b.c_cls FROM (
				` + strings.Join(parts, "\n				UNION ALL\n				") + `
			) b
			ORDER BY b.c_cls, b.c_at, b.c_id
			LIMIT ` + limitSQL
}

// GetSharedPendingForSensorExcluding is GetSharedPendingForSensor without
// the jobs in exclude (the next page of a shared claim whose first
// candidates were withheld after the query).
//
// Within a round the organization with the fewest shared jobs in flight
// comes first, before the priority class (fair share before priority,
// research/191 W-3): an organization's aged jobs no longer outrank another
// organization's fresh job whatever the load. One job may jump that order:
// an organization's first job of the round when it is a verification
// (critical class) job.
//
// The work of one poll is bounded by the organizations with pending shared
// jobs, not by the jobs: it lists those organizations by a skip scan of
// idx_commands_shared_pending, orders them (a pending verification job
// first, then fewest in flight), keeps the first sharedTenantWindow that have
// a job this sensor may claim, and reads at most limit jobs of each through
// the same index. Gates run only on the rows it reads.
func (r *CommandRepository) GetSharedPendingForSensorExcluding(ctx context.Context, sensorID shared.ID, capabilities []string, limit int, exclude []shared.ID) ([]*command.Command, error) {
	if limit <= 0 {
		limit = 1
	}
	where := sharedClaimWhere
	args := []any{sensorID.String(), pq.Array(capabilities), limit}
	if len(exclude) > 0 {
		where += " AND commands.id <> ALL($4::uuid[])"
		args = append(args, pq.Array(commandIDStrings(exclude)))
	}
	// A poll reads a few hundred rows at most, but its estimated cost (many
	// correlated gates) passes the JIT threshold, and compiling it costs far
	// more than running it: JIT is off for this one read-only transaction.
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("failed to get shared jobs: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL jit = off`); err != nil {
		return nil, fmt.Errorf("failed to get shared jobs: %w", err)
	}
	rows, err := tx.QueryContext(ctx, sharedPendingQuery(r.selectQuery(), where), args...)
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to get shared jobs: %w", err)
	}
	return out, nil
}

// sharedPendingQuery is the shared poll over the jobs matching where ($1
// sensor, $2 capabilities, $3 limit), in the shared dispatch order
// (GetSharedPendingForSensorExcluding). selectSQL is the repository's column
// list FROM commands.
func sharedPendingQuery(selectSQL, where string) string {
	// An organization with a full first round reads whole rounds up to the
	// rows the poll still lacks after the first round (more.extra), so the
	// last round it offers is complete and the order inside a round holds.
	burst := fmt.Sprint(sharedTenantBurst)
	deepLimit := "(" + burst + " * ((" + burst + " + (SELECT extra FROM more) + " + burst + " - 1) / " + burst + "))"
	return `
		WITH RECURSIVE orgs AS (
			(SELECT p.tenant_id FROM commands p
			 WHERE p.is_platform_job = TRUE AND p.status = 'pending'
			 ORDER BY p.tenant_id LIMIT 1)
			UNION ALL
			SELECT (SELECT p.tenant_id FROM commands p
			        WHERE p.is_platform_job = TRUE AND p.status = 'pending' AND p.tenant_id > orgs.tenant_id
			        ORDER BY p.tenant_id LIMIT 1)
			FROM orgs WHERE orgs.tenant_id IS NOT NULL
		), ordered AS (
			SELECT o.o_tenant, o.o_load FROM (
				SELECT orgs.tenant_id AS o_tenant, ` + sharedInFlightSQL("orgs.tenant_id") + ` AS o_load,
				       EXISTS (SELECT 1 FROM commands p
				               WHERE p.tenant_id = orgs.tenant_id AND p.is_platform_job = TRUE
				                 AND p.status = 'pending' AND p.priority = 'critical') AS o_crit
				FROM orgs WHERE orgs.tenant_id IS NOT NULL
			) o
			ORDER BY o.o_crit DESC, o.o_load, o.o_tenant
			OFFSET 0
		), picked AS (
			SELECT ordered.o_tenant, ordered.o_load FROM ordered
			WHERE EXISTS (SELECT 1 FROM commands
			              WHERE commands.tenant_id = ordered.o_tenant
			                AND commands.is_platform_job = TRUE AND commands.status = 'pending'
			                AND ` + perRowGateSQL(where) + `)
			LIMIT ` + fmt.Sprint(sharedTenantWindow) + `
		), first AS MATERIALIZED (
			SELECT picked.o_tenant AS c_tenant, picked.o_load AS c_load, j.c_id, j.c_at, j.c_cls
			FROM picked CROSS JOIN LATERAL (
				` + sharedOrgFirstJobsSQL("picked.o_tenant", where, fmt.Sprint(sharedTenantBurst)) + `
			) j
		), more AS (
			SELECT GREATEST(0, $3 - count(*)) AS extra FROM first
		), deep AS (
			SELECT c_tenant, c_load FROM first
			WHERE (SELECT extra FROM more) > 0
			GROUP BY c_tenant, c_load
			HAVING count(*) = ` + fmt.Sprint(sharedTenantBurst) + `
		), elig AS (
			SELECT c_tenant, c_load, c_id, c_at, c_cls FROM first
			WHERE c_tenant NOT IN (SELECT c_tenant FROM deep)
			UNION ALL
			SELECT deep.c_tenant, deep.c_load, j.c_id, j.c_at, j.c_cls
			FROM deep CROSS JOIN LATERAL (
				` + sharedOrgFirstJobsSQL("deep.c_tenant", where, deepLimit) + `
			) j
		), ranked AS (
			SELECT c_id, c_cls, c_at, c_load,
			       ROW_NUMBER() OVER (PARTITION BY c_tenant ORDER BY c_cls, c_at, c_id) - 1 AS c_rn
			FROM elig
		), cand AS (
			SELECT c_id, c_cls, c_load, c_rn / ` + fmt.Sprint(sharedTenantBurst) + ` AS c_round,
			       (c_cls = 1 AND c_rn % ` + fmt.Sprint(sharedTenantBurst) + ` = 0) AS c_jump
			FROM ranked
			ORDER BY c_round, c_cls, c_at, c_id
			LIMIT ` + fmt.Sprint(fairCandidateWindow) + `
		)
		` + selectSQL + `
		JOIN cand ON cand.c_id = commands.id
		ORDER BY cand.c_round, cand.c_jump DESC, cand.c_load, cand.c_cls, commands.queue_priority DESC,
		         COALESCE(commands.queued_at, commands.created_at), commands.id
		LIMIT $3`
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

	// The shared-fleet host locks first, for every candidate and in key
	// order, before any organization's lock: every shared claim takes them
	// in that one order, so two never deadlock.
	if err := lockSharedFleetHostKeysForPlatform(ctx, tx, want); err != nil {
		return nil, err
	}
	byTenant, tenants, err := sharedJobTenantsForPlatform(ctx, tx, want)
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
			if err := tx.QueryRowContext(ctx, `SELECT `+sharedInFlightSQL("$1::uuid"),
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
	if keep, err = dropSharedFleetHostsForPlatform(ctx, tx, want, keep); err != nil {
		return nil, err
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

// lockSharedFleetHostKeysForPlatform takes a transaction advisory lock on every host
// key of the shared jobs among ids, across organizations ("shost|" key), in
// key order: two shared claims of one host run one after the other, so the
// second sees the first one's claim in sharedFleetHostFreePredicate. A
// bucket marker and a range key of the same bucket take one lock
// (command.HostKeyLock).
func lockSharedFleetHostKeysForPlatform(ctx context.Context, tx *sql.Tx, ids []string) error {
	_, err := tx.ExecContext(ctx, `
		SELECT count(pg_advisory_xact_lock(hashtextextended('shost|' || keys.k, 0)))
		FROM (
			SELECT DISTINCT CASE WHEN k LIKE 'in:%' THEN 'b:' || substr(k, 4)
			                     WHEN k LIKE 'net:%' THEN 'b:' || substr(k, 5)
			                     ELSE k END AS k
			FROM commands c, unnest(c.host_keys) AS k
			WHERE c.id = ANY($1::uuid[]) AND c.is_platform_job = TRUE AND c.host_keys IS NOT NULL
			ORDER BY 1
		) keys`, pq.Array(ids))
	if err != nil {
		return fmt.Errorf("failed to lock shared job hosts: %w", err)
	}
	return nil
}

// dropSharedFleetHostsForPlatform keeps, in the order of order, the ids of keep that
// the shared-fleet host limit still allows once the shared jobs in flight
// and the ids kept before them are counted
// (command.SharedFleetHostsAllowed): one claim batch never puts more shared
// jobs on one host than the limit, whatever their organizations.
func dropSharedFleetHostsForPlatform(ctx context.Context, tx *sql.Tx, order, keep []string) ([]string, error) {
	if len(keep) == 0 {
		return keep, nil
	}
	rows, err := tx.QueryContext(ctx, sharedFleetJobHostsSQL, pq.Array(keep))
	if err != nil {
		return nil, fmt.Errorf("failed to read shared job hosts: %w", err)
	}
	defer rows.Close()
	jobOf := map[string]command.SharedFleetJob{}
	var conflicts []string
	for rows.Next() {
		var j command.SharedFleetJob
		if err := rows.Scan(&j.ID, pq.Array(&j.Keys), &j.Limit); err != nil {
			return nil, fmt.Errorf("failed to read shared job hosts: %w", err)
		}
		jobOf[j.ID] = j
		conflicts = append(conflicts, command.HostKeyConflicts(j.Keys)...)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read shared job hosts: %w", err)
	}
	if len(jobOf) == 0 {
		return keep, nil
	}
	held, err := sharedFleetHeldKeys(ctx, tx, conflicts)
	if err != nil {
		return nil, err
	}
	kept := make(map[string]bool, len(keep))
	for _, id := range keep {
		kept[id] = true
	}
	jobs := make([]command.SharedFleetJob, 0, len(keep))
	for _, id := range order {
		if !kept[id] {
			continue
		}
		j, ok := jobOf[id]
		if !ok {
			j = command.SharedFleetJob{ID: id}
		}
		jobs = append(jobs, j)
	}
	return command.SharedFleetHostsAllowed(held, jobs), nil
}

// sharedFleetJobHostsSQL reads the host keys and the shared-fleet host limit
// of the commands among $1 that hold hosts.
var sharedFleetJobHostsSQL = `
		SELECT commands.id::text, commands.host_keys, ` + sharedFleetHostLimitSQL + `
		FROM commands
		WHERE commands.id = ANY($1::uuid[]) AND commands.host_keys IS NOT NULL`

// sharedFleetHeldKeys counts, per key among keys, the shared jobs in flight
// (of any organization) that hold it unsettled.
func sharedFleetHeldKeys(ctx context.Context, tx *sql.Tx, keys []string) (map[string]int, error) {
	held := map[string]int{}
	if len(keys) == 0 {
		return held, nil
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT hkk.k, count(DISTINCT hk.id)
		FROM commands hk, unnest(hk.host_keys) AS hkk(k)
		WHERE hk.is_platform_job = TRUE
		  AND hk.host_keys IS NOT NULL
		  AND hk.status IN ('acknowledged', 'running')
		  AND hk.host_keys && $1::text[]
		  AND hkk.k = ANY($1::text[])
		  AND (hk.settled_host_keys IS NULL OR hkk.k <> ALL(hk.settled_host_keys))
		GROUP BY hkk.k`, pq.Array(keys))
	if err != nil {
		return nil, fmt.Errorf("failed to count shared job hosts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int
		if err := rows.Scan(&k, &n); err != nil {
			return nil, fmt.Errorf("failed to count shared job hosts: %w", err)
		}
		held[k] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to count shared job hosts: %w", err)
	}
	return held, nil
}

// sharedJobTenantsForPlatform groups the shared jobs among ids by organization, each
// group in the order of ids, and lists the organizations sorted by id (the
// one lock order of every shared claim, so two claims never deadlock).
func sharedJobTenantsForPlatform(ctx context.Context, tx *sql.Tx, ids []string) (map[shared.ID][]string, []shared.ID, error) {
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

// HeldSharedJobsForPlatform returns, by organization, the ids among ids of the shared
// jobs the shared sensor holds (acknowledged or running). The organization
// is read from each command; ids that are not well-formed, not shared jobs
// or not held by the sensor are left out.
func (r *CommandRepository) HeldSharedJobsForPlatform(ctx context.Context, sensorID shared.ID, ids []string) (map[shared.ID][]string, error) {
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

// RenewSharedLeasesForPlatform extends the leases of the shared jobs among ids that the
// shared sensor holds (acknowledged or running), in whatever organization,
// whose lease has less than command.LeaseRenewBefore(lease, interval) left.
func (r *CommandRepository) RenewSharedLeasesForPlatform(ctx context.Context, sensorID shared.ID, ids []string, interval time.Duration) (int64, error) {
	valid := validIDs(ids)
	if len(valid) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET lease_expires_at = NOW() + make_interval(secs => $3)
		WHERE sensor_id = $1 AND is_platform_job = TRUE
		  AND status IN ('acknowledged', 'running')
		  AND id = ANY($2::uuid[])
		  AND (lease_expires_at IS NULL OR lease_expires_at < NOW() + make_interval(secs => $4))`,
		sensorID.String(), pq.Array(valid), r.leaseSeconds(), r.renewBeforeSeconds(interval))
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

// SharedCommandsToStopForPlatform is CommandsToStop for a shared sensor: the shared
// jobs among ids it holds, running and stop-requested.
func (r *CommandRepository) SharedCommandsToStopForPlatform(ctx context.Context, sensorID shared.ID, ids []string) ([]string, error) {
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
