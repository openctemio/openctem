package postgres

// Scale of the shared poll (command_shared_claim.go,
// docs/rfcs/RFC-129-shared-fleet-scheduling.md): one poll's work is bounded
// by the organizations with pending shared work, never by the depth of their
// queues or by finished shared jobs, and the fair-share order is unchanged.
// Requires DATABASE_URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// seedTenants creates n organizations in one statement and removes them and
// their commands at cleanup.
func seedTenants(ctx context.Context, t testing.TB, db *sql.DB, n int) []shared.ID {
	t.Helper()
	rows, err := db.QueryContext(ctx, `
		INSERT INTO tenants (id, name, slug)
		SELECT u, 'shared claim scale test', 'test-' || u::text
		FROM (SELECT gen_random_uuid() AS u FROM generate_series(1, $1::int)) g
		RETURNING id::text`, n)
	if err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	defer rows.Close()
	ids := make([]shared.ID, 0, n)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	strs := idStrings(ids)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE tenant_id = ANY($1::uuid[])`, pq.Array(strs))
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, pq.Array(strs))
	})
	return ids
}

// seedSharedJobs inserts per organization of tenants n shared jobs of tool in
// status (sensor holds the in-flight ones), created an hour ago and older.
func seedSharedJobs(ctx context.Context, t testing.TB, db *sql.DB, tenants []shared.ID, n int, tool, status string, sensor *shared.ID) {
	t.Helper()
	var holder any
	if sensor != nil {
		holder = sensor.String()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queued_at, created_at,
		                      sensor_id, acknowledged_at, completed_at)
		SELECT gen_random_uuid(), t.id, 'scan', 'normal', jsonb_build_object('scanner', $3::text), $4::text, TRUE,
		       NOW() - interval '1 hour', NOW() - interval '1 hour' - make_interval(secs => g),
		       CASE WHEN $4::text = 'pending' THEN NULL ELSE $5::uuid END,
		       CASE WHEN $4::text = 'pending' THEN NULL ELSE NOW() END,
		       CASE WHEN $4::text IN ('completed', 'failed') THEN NOW() END
		FROM unnest($1::uuid[]) AS t(id), generate_series(1, $2::int) g`,
		pq.Array(idStrings(tenants)), n, tool, status, holder); err != nil {
		t.Fatalf("seed %s shared jobs: %v", status, err)
	}
}

// sharedPollRowsRead runs the shared poll for sensor under EXPLAIN ANALYZE
// and returns the rows it read from commands (returned plus filtered out,
// over every loop) and the index names it used.
func sharedPollRowsRead(ctx context.Context, t testing.TB, db *sql.DB, repo *CommandRepository, sensor shared.ID, limit int) (float64, map[string]bool) {
	t.Helper()
	var raw []byte
	if err := db.QueryRowContext(ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+sharedPendingQuery(repo.selectQuery(), sharedClaimWhere),
		sensor.String(), pq.Array([]string(nil)), limit).Scan(&raw); err != nil {
		t.Fatalf("explain shared poll: %v", err)
	}
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("read plan: %v", err)
	}
	indexes := map[string]bool{}
	var walk func(n map[string]any) float64
	walk = func(n map[string]any) float64 {
		var sum float64
		if n["Relation Name"] == "commands" {
			loops, _ := n["Actual Loops"].(float64)
			got, _ := n["Actual Rows"].(float64)
			removed, _ := n["Rows Removed by Filter"].(float64)
			recheck, _ := n["Rows Removed by Index Recheck"].(float64)
			sum += (got + removed + recheck) * loops
			if idx, ok := n["Index Name"].(string); ok {
				indexes[idx] = true
			}
		}
		if kids, ok := n["Plans"].([]any); ok {
			for _, k := range kids {
				if m, ok := k.(map[string]any); ok {
					sum += walk(m)
				}
			}
		}
		return sum
	}
	return walk(plans[0].Plan), indexes
}

func analyzeCommands(ctx context.Context, t testing.TB, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `ANALYZE commands`); err != nil {
		t.Fatalf("analyze commands: %v", err)
	}
}

// Deep queues and finished shared jobs do not grow the work of a poll: it
// reads a few jobs per organization through the pending and in-flight
// indexes. Before, the poll ranked every eligible pending shared job and
// counted in-flight jobs through an index that also held every finished one.
func TestSharedClaim_PollWorkBoundedByOrganizations(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	orgs := seedTenants(ctx, t, db, 100)
	seedSharedJobs(ctx, t, db, orgs, 10, tool, "pending", nil)
	seedSharedJobs(ctx, t, db, orgs[:30], 2, tool, "running", &sensor)
	analyzeCommands(ctx, t, db)

	before, _ := sharedPollRowsRead(ctx, t, db, repo, sensor, 100)

	// Six times deeper queues and 10k finished shared jobs.
	seedSharedJobs(ctx, t, db, orgs, 50, tool, "pending", nil)
	seedSharedJobs(ctx, t, db, orgs, 100, tool, "completed", &sensor)
	analyzeCommands(ctx, t, db)

	after, indexes := sharedPollRowsRead(ctx, t, db, repo, sensor, 100)
	added := float64(100*50 + 100*100)
	if after-before > added/50 {
		t.Fatalf("a poll read %.0f rows of commands before and %.0f after adding %.0f deeper or finished jobs: "+
			"the work must not grow with queue depth or history", before, after, added)
	}
	for _, idx := range []string{"idx_commands_shared_pending", "idx_commands_shared_inflight"} {
		if !indexes[idx] {
			t.Errorf("the poll did not use %s (used %v)", idx, indexes)
		}
	}
}

// One organization with a very deep queue gets at most one round of a poll
// while a hundred others wait: every one of them is offered in the same poll.
func TestSharedClaim_DeepQueueOffersOneRoundAmongManyOrganizations(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	deep := seedTenants(ctx, t, db, 1)
	seedSharedJobs(ctx, t, db, deep, 10000, tool, "pending", nil)
	quiet := seedTenants(ctx, t, db, 95)
	seedSharedJobs(ctx, t, db, quiet, 1, tool, "pending", nil)
	analyzeCommands(ctx, t, db)

	cands, err := repo.GetSharedPendingForSensor(ctx, sensor, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	quietSet := map[shared.ID]bool{}
	for _, id := range quiet {
		quietSet[id] = true
	}
	deepN, quietSeen := 0, map[shared.ID]bool{}
	for _, c := range cands {
		switch {
		case c.TenantID == deep[0]:
			deepN++
		case quietSet[c.TenantID]:
			quietSeen[c.TenantID] = true
		}
	}
	if deepN > sharedTenantBurst || len(quietSeen) != len(quiet) {
		t.Fatalf("poll of 100 offered %d jobs of the deep organization and %d of %d quiet organizations; want at most %d and all",
			deepN, len(quietSeen), len(quiet), sharedTenantBurst)
	}
}

// A poll with room for more than one round per organization still fills up
// from the organizations with deeper queues, in their class and age order.
func TestSharedClaim_PollFillsLaterRoundsFromDeepQueues(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	orgs := seedTenants(ctx, t, db, 2)
	seedSharedJobs(ctx, t, db, orgs[:1], 30, tool, "pending", nil)
	small := seedSharedJob(ctx, t, db, orgs[1], sharedJobSeed{tool: tool, platform: true})

	cands, err := repo.GetSharedPendingForSensor(ctx, sensor, nil, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 20 {
		t.Fatalf("a poll of 20 offered %d jobs; want 20 (the deep queue fills the later rounds)", len(cands))
	}
	// The deep organization's offered jobs are its oldest ones: rounds take
	// each organization's jobs in class and age order, so 19 offered jobs are
	// its first three rounds (15 oldest) and four of its fourth round.
	var oldest []string
	rows, err := db.QueryContext(ctx, `SELECT id::text FROM commands WHERE tenant_id = $1 ORDER BY created_at, id LIMIT 20`, orgs[0].String())
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		oldest = append(oldest, id)
	}
	_ = rows.Close()
	want := map[string]bool{}
	for _, id := range oldest {
		want[id] = true
	}
	offeredSet := map[string]bool{}
	for _, c := range cands {
		offeredSet[c.ID.String()] = true
	}
	for _, id := range oldest[:3*sharedTenantBurst] {
		if !offeredSet[id] {
			t.Fatalf("the deep organization's job %s of its first three rounds was not offered", id)
		}
	}
	sawSmall := false
	for i, c := range cands {
		if c.ID == small {
			sawSmall = true
			if i >= 2*sharedTenantBurst {
				t.Fatalf("the small organization's job came at %d, after the first round", i)
			}
			continue
		}
		if !want[c.ID.String()] {
			t.Fatalf("offered %s of the deep organization, not among its first four rounds", c.ID)
		}
	}
	if !sawSmall {
		t.Fatal("the small organization's job was not offered")
	}
}

// Organizations whose pending shared work this sensor cannot run (another
// tool) do not use up the organizations a poll ranks: an organization with a
// job for this sensor is still offered behind more than sharedTenantWindow of
// them, even when it sorts after all of them (more in flight).
func TestSharedClaim_OrganizationWindowCountsOnlyClaimableWork(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, other := uniqueTool(), uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	otherSensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{other}})
	blockers := seedTenants(ctx, t, db, sharedTenantWindow+50)
	seedSharedJobs(ctx, t, db, blockers, 1, other, "pending", nil)
	mine := seedTenants(ctx, t, db, 1)
	seedSharedJobs(ctx, t, db, mine, 1, tool, "running", &otherSensor)
	job := seedSharedJob(ctx, t, db, mine[0], sharedJobSeed{tool: tool, platform: true})

	if got := offered(ctx, t, repo, sensor, nil, job); len(got) != 1 {
		t.Fatalf("the job was not offered behind %d organizations with only other tools' work", len(blockers))
	}
}

// A verification (critical) job still jumps the order when its organization
// has more in flight than sharedTenantWindow organizations with work.
func TestSharedClaim_CriticalJobJumpsBeyondOrganizationWindow(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	others := seedTenants(ctx, t, db, sharedTenantWindow+20)
	seedSharedJobs(ctx, t, db, others, 1, tool, "pending", nil)
	busy := seedTenants(ctx, t, db, 1)
	seedSharedJobs(ctx, t, db, busy, 5, tool, "running", &sensor)
	crit := seedSharedJob(ctx, t, db, busy[0], sharedJobSeed{tool: tool, platform: true, priority: "critical"})

	cands, err := repo.GetSharedPendingForSensor(ctx, sensor, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) == 0 || cands[0].ID != crit {
		t.Fatalf("the verification job of a busy organization was not offered first among %d organizations", len(others)+1)
	}
}

// BenchmarkSharedClaimPoll measures one shared poll at fleet scale: 2,000
// organizations with 50 pending shared jobs each, 300 in flight and 200,000
// finished. Opt in with SHARED_CLAIM_BENCH=1 (it seeds about 300k rows).
func BenchmarkSharedClaimPoll(b *testing.B) {
	if os.Getenv("SHARED_CLAIM_BENCH") == "" {
		b.Skip("set SHARED_CLAIM_BENCH=1 to seed the fleet-scale data set")
	}
	if testdb.URL() == "" {
		b.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", testdb.URL())
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := shared.NewID()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sensors (id, tenant_id, scope, name, type, status, api_key_hash, api_key_prefix,
		                     reported_tool_names, reported_capabilities, accepts_unzoned_jobs)
		VALUES ($1, NULL, 'instance', $2, 'sensor', 'active', $3, $4, $5, ARRAY['`+command.CapabilitySharedIsolation+`'], TRUE)`,
		sensor.String(), "bench "+sensor.String(), "hash-"+sensor.String(), sensor.String()[:8], pq.Array([]string{tool})); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE sensor_id = $1`, sensor.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, sensor.String())
	})
	orgs := seedTenants(ctx, b, db, 2000)
	seedSharedJobs(ctx, b, db, orgs, 50, tool, "pending", nil)
	seedSharedJobs(ctx, b, db, orgs[:300], 1, tool, "running", &sensor)
	seedSharedJobs(ctx, b, db, orgs, 100, tool, "completed", &sensor)
	analyzeCommands(ctx, b, db)

	durations := make([]time.Duration, 0, b.N)
	b.ResetTimer()
	for range b.N {
		start := time.Now()
		if _, err := repo.GetSharedPendingForSensor(ctx, sensor, nil, 100); err != nil {
			b.Fatal(err)
		}
		durations = append(durations, time.Since(start))
	}
	b.StopTimer()
	slices.Sort(durations)
	b.ReportMetric(float64(durations[len(durations)*95/100].Microseconds())/1000, "p95-ms")
	rows, idx := sharedPollRowsRead(ctx, b, db, repo, sensor, 100)
	var names []string
	for k := range idx {
		names = append(names, k)
	}
	b.ReportMetric(rows, "rows-read/op")
	b.Logf("rows read per poll: %.0f; indexes: %s", rows, strings.Join(names, ", "))
}
