package postgres

// The shared claim path (command_shared_claim.go,
// docs/rfcs/RFC-100-shared-sensors.md §8): who may take a shared job, in what
// order, under which limits. Requires DATABASE_URL.
//
// The shared queue is global, so every test names its own tool on its jobs
// and sensors, reads only its own jobs out of a poll and claims only its own
// ids: other tests' shared jobs are never touched.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type sharedSensorSeed struct {
	tools, reported []string
	region          string
	status          string
	noUnzoned       bool
}

// seedSharedSensor creates a shared sensor (scope instance, no tenant). By
// default it is active, reports the shared isolation profile and accepts
// unzoned jobs.
func seedSharedSensor(ctx context.Context, t *testing.T, db *sql.DB, s sharedSensorSeed) shared.ID {
	t.Helper()
	id := shared.NewID()
	if s.status == "" {
		s.status = "active"
	}
	if s.reported == nil {
		s.reported = []string{command.CapabilitySharedIsolation}
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sensors (id, tenant_id, scope, name, type, status, api_key_hash, api_key_prefix,
		                     reported_tool_names, reported_capabilities, region, accepts_unzoned_jobs)
		VALUES ($1, NULL, 'instance', $2, 'sensor', $3, $4, $5, $6, $7, $8, $9)`,
		id.String(), "shared "+id.String(), s.status, "hash-"+id.String(), id.String()[:8],
		pq.Array(s.tools), pq.Array(s.reported), s.region, !s.noUnzoned); err != nil {
		t.Fatalf("seed shared sensor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE sensor_id = $1`, id.String())
		_, _ = db.ExecContext(context.Background(), `DELETE FROM sensors WHERE id = $1`, id.String())
	})
	return id
}

type sharedJobSeed struct {
	tool, priority, status string
	platform               bool
	queuePriority          int
	holder                 *shared.ID
	hostKeys               []string
	extra                  string // more payload members, e.g. `"preferred_region":"eu"`
}

func seedSharedJob(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID, s sharedJobSeed) shared.ID {
	t.Helper()
	id := shared.NewID()
	if s.priority == "" {
		s.priority = "normal"
	}
	if s.status == "" {
		s.status = "pending"
	}
	payload := `{"scanner":"` + s.tool + `"`
	if s.extra != "" {
		payload += "," + s.extra
	}
	payload += "}"
	var holder any
	if s.holder != nil {
		holder = s.holder.String()
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO commands (id, tenant_id, type, priority, payload, status, is_platform_job, queue_priority, queued_at,
		                      sensor_id, acknowledged_at, host_keys)
		VALUES ($1, $2, 'scan', $3, $4::jsonb, $5::text, $6, $7, NOW(), $8,
		        CASE WHEN $5::text = 'pending' THEN NULL ELSE NOW() END, $9)`,
		id.String(), tenant.String(), s.priority, payload, s.status, s.platform, s.queuePriority, holder,
		hostKeysArg(s.hostKeys)); err != nil {
		t.Fatalf("seed shared job: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String())
	})
	return id
}

// offered is the order in which the poll offers sensor the jobs among mine.
func offered(ctx context.Context, t *testing.T, repo *CommandRepository, sensor shared.ID, caps []string, mine ...shared.ID) []shared.ID {
	t.Helper()
	cands, err := repo.GetSharedPendingForSensor(ctx, sensor, caps, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := map[shared.ID]bool{}
	for _, id := range mine {
		want[id] = true
	}
	var out []shared.ID
	for _, c := range cands {
		if want[c.ID] {
			out = append(out, c.ID)
		}
	}
	return out
}

func uniqueTool() string { return "tool-" + shared.NewID().String() }

func TestSharedClaim_FairShareAcrossOrganizations(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	busy, quiet := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	// busy already runs three shared jobs.
	for range 3 {
		seedSharedJob(ctx, t, db, busy, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor})
	}
	busyNext := seedSharedJob(ctx, t, db, busy, sharedJobSeed{tool: tool, platform: true, queuePriority: 900})
	quietNext := seedSharedJob(ctx, t, db, quiet, sharedJobSeed{tool: tool, platform: true, queuePriority: 100})
	busyHigh := seedSharedJob(ctx, t, db, busy, sharedJobSeed{tool: tool, platform: true, priority: "high"})

	got := offered(ctx, t, repo, sensor, nil, busyNext, quietNext, busyHigh)
	want := []shared.ID{busyHigh, quietNext, busyNext}
	if len(got) != len(want) {
		t.Fatalf("offered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("offered %v, want %v (a higher class first, then the organization with fewer shared jobs in flight)", got, want)
		}
	}
}

func TestSharedClaim_SensorAndJobGates(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	tenant := seedTestTenant(ctx, t, db)

	plain := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})
	tenantJob := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: false})
	otherTool := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: uniqueTool(), platform: true})
	needsCap := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true, extra: `"required_capabilities":["cap-x"]`})
	needsFeature := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true, extra: `"required_features":["net.confined@1"]`})
	inEU := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true, extra: `"preferred_region":"eu"`})
	all := []shared.ID{plain, tenantJob, otherTool, needsCap, needsFeature, inEU}

	has := func(ids []shared.ID, id shared.ID) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}

	us := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}, region: "us"})
	got := offered(ctx, t, repo, us, nil, all...)
	if len(got) != 1 || got[0] != plain {
		names := map[shared.ID]string{plain: "plain", tenantJob: "tenant job", otherTool: "other tool",
			needsCap: "needs capability", needsFeature: "needs feature", inEU: "in eu"}
		var n []string
		for _, id := range got {
			n = append(n, names[id])
		}
		t.Fatalf("offered %v, want only the plain shared job", n)
	}

	eu := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}, region: "eu",
		reported: []string{command.CapabilitySharedIsolation, "net.confined@1"}})
	got = offered(ctx, t, repo, eu, []string{"cap-x"}, all...)
	for _, want := range []shared.ID{plain, needsCap, needsFeature, inEU} {
		if !has(got, want) {
			t.Fatalf("offered %v; missing %s (region, capability and reported feature match)", got, want)
		}
	}
	if has(got, tenantJob) || has(got, otherTool) {
		t.Fatalf("offered %v: a tenant job or a job of a tool the sensor does not have", got)
	}

	// Shared sensors that get nothing at all.
	for name, s := range map[string]sharedSensorSeed{
		"no shared isolation reported": {tools: []string{tool}, reported: []string{}},
		"zone work only":               {tools: []string{tool}, noUnzoned: true},
		"disabled":                     {tools: []string{tool}, status: "disabled"},
		"revoked":                      {tools: []string{tool}, status: "revoked"},
	} {
		id := seedSharedSensor(ctx, t, db, s)
		if got := offered(ctx, t, repo, id, nil, all...); len(got) != 0 {
			t.Errorf("%s: offered %v", name, got)
		}
		if ids, err := repo.ClaimManyShared(ctx, id, nil, all, nil); err != nil || len(ids) != 0 {
			t.Errorf("%s: claimed %v (%v)", name, ids, err)
		}
	}

	// An organization sensor never uses the shared path, even one with the
	// tool and the isolation capability reported.
	org := seedJobSensor(ctx, t, db, tenant)
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET reported_tool_names = $2, reported_capabilities = $3 WHERE id = $1`,
		org.String(), pq.Array([]string{tool}), pq.Array([]string{command.CapabilitySharedIsolation})); err != nil {
		t.Fatal(err)
	}
	if got := offered(ctx, t, repo, org, nil, all...); len(got) != 0 {
		t.Fatalf("an organization sensor was offered shared jobs: %v", got)
	}
	if ids, err := repo.ClaimManyShared(ctx, org, nil, all, nil); err != nil || len(ids) != 0 {
		t.Fatalf("an organization sensor claimed shared jobs: %v (%v)", ids, err)
	}
}

func TestSharedClaim_SetsHolderLeaseAndEpoch(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	a := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	b := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	tenant := seedTestTenant(ctx, t, db)
	job := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})

	ids, err := repo.ClaimManyShared(ctx, a, nil, []shared.ID{job}, nil)
	if err != nil || len(ids) != 1 || ids[0] != job {
		t.Fatalf("claim: %v %v", ids, err)
	}
	cmd, err := repo.GetHeldSharedJob(ctx, a, job)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != command.CommandStatusAcknowledged || cmd.SensorID == nil || *cmd.SensorID != a ||
		cmd.LeaseEpoch != 1 || cmd.LeaseExpiresAt == nil || cmd.TenantID != tenant {
		t.Fatalf("claimed job %+v", cmd)
	}
	if _, err := repo.GetHeldSharedJob(ctx, b, job); err == nil {
		t.Fatal("another shared sensor reads the job as held")
	}
	if ids, err := repo.ClaimManyShared(ctx, b, nil, []shared.ID{job}, nil); err != nil || len(ids) != 0 {
		t.Fatalf("a held job was claimed again: %v %v", ids, err)
	}
	if n, err := repo.CountHeldSharedScans(ctx, a); err != nil || n != 1 {
		t.Fatalf("held scans %d %v", n, err)
	}
}

func TestSharedClaim_PerOrganizationLimit(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	limited, free := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	seedSharedJob(ctx, t, db, limited, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor})
	l1 := seedSharedJob(ctx, t, db, limited, sharedJobSeed{tool: tool, platform: true})
	l2 := seedSharedJob(ctx, t, db, limited, sharedJobSeed{tool: tool, platform: true})
	f1 := seedSharedJob(ctx, t, db, free, sharedJobSeed{tool: tool, platform: true})
	f2 := seedSharedJob(ctx, t, db, free, sharedJobSeed{tool: tool, platform: true})

	// At its limit (1 in flight, limit 1): skipped; its jobs wait. The
	// unlimited organization gets all of its jobs.
	ids, err := repo.ClaimManyShared(ctx, sensor, nil, []shared.ID{l1, l2, f1, f2},
		map[shared.ID]int{limited: 1, free: -1})
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if got[l1] || got[l2] || !got[f1] || !got[f2] {
		t.Fatalf("claimed %v; want f1, f2 and nothing of the organization at its limit", ids)
	}
	// Limit 2: room for exactly one more.
	ids, err = repo.ClaimManyShared(ctx, sensor, nil, []shared.ID{l1, l2}, map[shared.ID]int{limited: 2})
	if err != nil || len(ids) != 1 || ids[0] != l1 {
		t.Fatalf("claimed %v (%v); want only %s", ids, err, l1)
	}
}

// Per-host politeness: a shared job and the organization's own jobs share
// the host keys and locks of that organization; another organization's work
// on the same address never holds it back.
func TestSharedClaim_HostKeysSharedWithOrganizationSensors(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	tenantA, tenantB := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	orgSensor := seedJobSensor(ctx, t, db, tenantA)

	// The organization's own sensor port-scans 198.51.100.0/24 as a range.
	running := seedSharedJob(ctx, t, db, tenantA, sharedJobSeed{tool: tool, status: "running", holder: &orgSensor,
		hostKeys: []string{"net:198.51.100.0/24"}})
	// Another organization scans the very address.
	seedSharedJob(ctx, t, db, tenantB, sharedJobSeed{tool: tool, status: "running",
		hostKeys: []string{"198.51.100.7", "in:198.51.100.0/24"}})

	waits := seedSharedJob(ctx, t, db, tenantA, sharedJobSeed{tool: tool, platform: true,
		hostKeys: []string{"198.51.100.7", "in:198.51.100.0/24"}})
	free := seedSharedJob(ctx, t, db, tenantA, sharedJobSeed{tool: tool, platform: true,
		hostKeys: []string{"198.51.101.9", "in:198.51.101.0/24"}})

	if got := offered(ctx, t, repo, sensor, nil, waits, free); len(got) != 1 || got[0] != free {
		t.Fatalf("offered %v; want only the job of the free bucket", got)
	}
	if ids, err := repo.ClaimManyShared(ctx, sensor, nil, []shared.ID{waits}, nil); err != nil || len(ids) != 0 {
		t.Fatalf("claimed %v (%v) while the organization scans its bucket", ids, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, running.String()); err != nil {
		t.Fatal(err)
	}
	if ids, err := repo.ClaimManyShared(ctx, sensor, nil, []shared.ID{waits}, nil); err != nil || len(ids) != 1 {
		t.Fatalf("claimed %v (%v) after the range scan finished", ids, err)
	}
}

// A shared job whose lease ran out goes back to the queue for any shared
// sensor; the next claim starts a new epoch, so the old holder is fenced.
func TestSharedClaim_LeaseExpiryRequeues(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	a := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	b := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	tenant := seedTestTenant(ctx, t, db)
	job := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})
	if ids, err := repo.ClaimManyShared(ctx, a, nil, []shared.ID{job}, nil); err != nil || len(ids) != 1 {
		t.Fatalf("claim: %v %v", ids, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET lease_expires_at = NOW() - interval '1 minute' WHERE id = $1`, job.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RequeueExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	cmd, err := repo.GetByTenantAndID(ctx, tenant, job)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Status != command.CommandStatusPending || cmd.SensorID != nil {
		t.Fatalf("after the lease ran out: %s held by %v", cmd.Status, cmd.SensorID)
	}
	if ids, err := repo.ClaimManyShared(ctx, b, nil, []shared.ID{job}, nil); err != nil || len(ids) != 1 {
		t.Fatalf("re-claim: %v %v", ids, err)
	}
	if cmd, err = repo.GetHeldSharedJob(ctx, b, job); err != nil || cmd.LeaseEpoch != 2 {
		t.Fatalf("re-claimed job epoch %v (%v), want 2", cmd, err)
	}
}

// The queue limit of shared jobs counts from the last time a job went back
// to the queue, not from when it was first queued.
func TestSharedClaim_QueueLimitCountsFromRequeue(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool := uniqueTool()
	tenant := seedTestTenant(ctx, t, db)
	stale := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})
	requeued := seedSharedJob(ctx, t, db, tenant, sharedJobSeed{tool: tool, platform: true})
	for _, id := range []shared.ID{stale, requeued} {
		if _, err := db.ExecContext(ctx, `UPDATE commands SET queued_at = NOW() - interval '90 minutes' WHERE id = $1`, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	// requeued was claimed and handed back just now (a 'requeued' event).
	for _, st := range []string{"acknowledged", "pending"} {
		if _, err := db.ExecContext(ctx, `UPDATE commands SET status = $2 WHERE id = $1`, requeued.String(), st); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := repo.FindQueueExpiredPlatformJobs(ctx, 60)
	if err != nil {
		t.Fatal(err)
	}
	found := map[shared.ID]bool{}
	for _, c := range jobs {
		found[c.ID] = true
	}
	if !found[stale] || found[requeued] {
		t.Fatalf("expired stale=%v requeued=%v; want only the job that waited 60 minutes since it was queued", found[stale], found[requeued])
	}
}
