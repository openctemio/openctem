package postgres

// Per-host politeness on the shared fleet across organizations
// (command_shared_claim.go, docs/rfcs/RFC-129-shared-fleet-scheduling.md §5):
// shared jobs of different organizations on one host are coordinated; an
// organization's own sensors keep per-organization keys. Requires
// DATABASE_URL.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// uniqueHost is a host name no other test uses (the shared fleet's host
// limit is global, so tests must not share hosts).
func uniqueHost() string { return shared.NewID().String() + ".example.com" }

func setIntrusive(ctx context.Context, t *testing.T, db *sql.DB, id shared.ID) {
	t.Helper()
	if _, err := db.ExecContext(ctx, `UPDATE commands SET dispatch_gate = '{"tier":2,"intensity":"intrusive"}'::jsonb WHERE id = $1`,
		id.String()); err != nil {
		t.Fatal(err)
	}
}

func claimShared(ctx context.Context, t *testing.T, repo *CommandRepository, sensor shared.ID, ids ...shared.ID) []shared.ID {
	t.Helper()
	got, err := repo.ClaimManyShared(ctx, sensor, nil, ids, nil)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Two organizations hitting one host from the shared fleet are coordinated:
// with one shared job of another organization on the host, a second may
// start; with two, a third waits (offered and claimed by id alike) until one
// releases the host.
func TestSharedFleetPoliteness_AcrossOrganizations(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	a, b, c := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	seedSharedJob(ctx, t, db, a, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	jobB := seedSharedJob(ctx, t, db, b, sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}})
	if got := offered(ctx, t, repo, sensor, nil, jobB); len(got) != 1 {
		t.Fatalf("B's job was not offered with one other shared job on the host (limit %d)", command.SharedFleetHostLimit)
	}

	holderC := seedSharedJob(ctx, t, db, c, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	if got := offered(ctx, t, repo, sensor, nil, jobB); len(got) != 0 {
		t.Fatalf("B's job was offered while %d shared jobs of other organizations hold the host", command.SharedFleetHostLimit)
	}
	if got := claimShared(ctx, t, repo, sensor, jobB); len(got) != 0 {
		t.Fatalf("B's job was claimed by id while the host is at its shared-fleet limit")
	}

	// C's job settles the host: it no longer counts.
	if _, err := db.ExecContext(ctx, `UPDATE commands SET settled_host_keys = host_keys WHERE id = $1`, holderC.String()); err != nil {
		t.Fatal(err)
	}
	if got := claimShared(ctx, t, repo, sensor, jobB); len(got) != 1 {
		t.Fatalf("B's job was not claimed after C settled the host")
	}
}

// An intrusive shared job runs alone on its host: one shared job of another
// organization on the host is enough to hold it.
func TestSharedFleetPoliteness_IntrusiveRunsAlone(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	a, b := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)

	holder := seedSharedJob(ctx, t, db, a, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	intrusive := seedSharedJob(ctx, t, db, b, sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}})
	setIntrusive(ctx, t, db, intrusive)

	if got := offered(ctx, t, repo, sensor, nil, intrusive); len(got) != 0 {
		t.Fatal("an intrusive shared job was offered while another organization's shared job holds the host")
	}
	if got := claimShared(ctx, t, repo, sensor, intrusive); len(got) != 0 {
		t.Fatal("an intrusive shared job was claimed while another organization's shared job holds the host")
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, holder.String()); err != nil {
		t.Fatal(err)
	}
	if got := claimShared(ctx, t, repo, sensor, intrusive); len(got) != 1 {
		t.Fatal("the intrusive shared job was not claimed once the host was free")
	}
}

// One claim batch never puts more shared jobs on one host than the limit,
// whatever their organizations; a range and an address of one bucket count
// as one host.
func TestSharedFleetPoliteness_ClaimBatchCountsItself(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})

	var ids []shared.ID
	for range 4 {
		ids = append(ids, seedSharedJob(ctx, t, db, seedTestTenant(ctx, t, db), sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}}))
	}
	if got := claimShared(ctx, t, repo, sensor, ids...); len(got) != command.SharedFleetHostLimit {
		t.Fatalf("one batch claimed %d shared jobs on one host of four organizations; want %d", len(got), command.SharedFleetHostLimit)
	}

	// A range scan of a bucket and an address in it, intrusive range: the
	// address job holds the bucket, so the intrusive range waits.
	bucket := "203.0.113.0/24"
	addr := seedSharedJob(ctx, t, db, seedTestTenant(ctx, t, db), sharedJobSeed{tool: tool, platform: true,
		hostKeys: []string{"203.0.113.9", "in:" + bucket}})
	rng := seedSharedJob(ctx, t, db, seedTestTenant(ctx, t, db), sharedJobSeed{tool: tool, platform: true,
		hostKeys: []string{"net:" + bucket}})
	setIntrusive(ctx, t, db, rng)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `UPDATE commands SET status = 'completed' WHERE id = ANY($1::uuid[])`,
			pq.Array([]string{addr.String(), rng.String()}))
	})
	got := claimShared(ctx, t, repo, sensor, addr, rng)
	if len(got) != 1 || got[0] != addr {
		t.Fatalf("claimed %v; want only the address job (the intrusive range of its bucket waits)", got)
	}
}

// Organization sensors keep per-organization keys: shared jobs of other
// organizations on a host never hold an organization's own job, and an
// organization's own running job never counts toward the shared fleet's
// limit for another organization.
func TestSharedFleetPoliteness_OrganizationSensorsUnaffected(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	a, b, c := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	orgSensorB := seedJobSensor(ctx, t, db, b)
	orgSensorC := seedJobSensor(ctx, t, db, c)

	// Two shared jobs of A and C hold the host on the shared fleet.
	seedSharedJob(ctx, t, db, a, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	seedSharedJob(ctx, t, db, c, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})

	// B's own job (no tool) for its own sensor is offered and claimed.
	own := seedSharedJob(ctx, t, db, b, sharedJobSeed{hostKeys: []string{host}})
	cands, err := repo.GetPendingForSensor(ctx, b, &orgSensorB, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, cand := range cands {
		found = found || cand.ID == own
	}
	if !found {
		t.Fatal("an organization sensor's job waited on other organizations' shared jobs")
	}
	if got, err := repo.ClaimManyForSensor(ctx, b, orgSensorB, nil, []shared.ID{own}); err != nil || len(got) != 1 {
		t.Fatalf("claimed %v (%v); the organization's own job must not wait on the shared fleet", got, err)
	}

	// D's shared job: B's own running job and C's organization-sensor job
	// do not count; only the two shared holders do, so it waits; once A's
	// shared job ends, one shared holder is left and it starts.
	d := seedTestTenant(ctx, t, db)
	seedSharedJob(ctx, t, db, c, sharedJobSeed{status: "running", holder: &orgSensorC, hostKeys: []string{host}})
	jobD := seedSharedJob(ctx, t, db, d, sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}})
	if got := claimShared(ctx, t, repo, sensor, jobD); len(got) != 0 {
		t.Fatal("D's shared job was claimed past the shared-fleet limit")
	}
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE tenant_id = $1 AND is_platform_job`, a.String()); err != nil {
		t.Fatal(err)
	}
	if got := claimShared(ctx, t, repo, sensor, jobD); len(got) != 1 {
		t.Fatal("D's shared job waited on organization sensors' jobs")
	}
}

// A waiting organization learns nothing about who holds the host: the host
// wait of its job names only its own organization's tasks.
func TestSharedFleetPoliteness_WaitShowsNoOtherOrganization(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	a, b, c := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	seedSharedJob(ctx, t, db, a, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	seedSharedJob(ctx, t, db, c, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	jobB := seedSharedJob(ctx, t, db, b, sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}})

	if got := offered(ctx, t, repo, sensor, nil, jobB); len(got) != 0 {
		t.Fatal("B's job was offered at the shared-fleet limit")
	}
	_, holders, err := repo.HostHolders(ctx, b, jobB, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(holders) != 0 {
		t.Fatalf("B's host wait names %d tasks of other organizations", len(holders))
	}
	if _, _, err := repo.HostHolders(ctx, a, jobB, 10); err == nil {
		t.Fatal("organization A read the hosts of B's job")
	}
}

// The operations queue view counts a shared job held by the shared-fleet
// host limit as waiting for its hosts.
func TestSharedFleetPoliteness_OpsQueueSaysHostBusy(t *testing.T) {
	db := openPlatformJobDB(t)
	ctx := context.Background()
	tool, host := uniqueTool(), uniqueHost()
	sensor := seedSharedSensor(ctx, t, db, sharedSensorSeed{tools: []string{tool}})
	a, b, c := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	seedSharedJob(ctx, t, db, a, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	seedSharedJob(ctx, t, db, c, sharedJobSeed{tool: tool, platform: true, status: "running", holder: &sensor, hostKeys: []string{host}})
	seedSharedJob(ctx, t, db, b, sharedJobSeed{tool: tool, platform: true, hostKeys: []string{host}})

	depths, err := readOpsQueue(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range depths {
		if d.Tool == opsQueueToolCustom && d.Wait == QueueWaitHostBusy && d.Count >= 1 {
			return
		}
	}
	t.Fatalf("the shared job held by the shared-fleet host limit is not counted as %q: %+v", QueueWaitHostBusy, depths)
}
