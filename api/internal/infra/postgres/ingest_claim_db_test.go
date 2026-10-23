package postgres

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// mine keeps the claimed jobs of one tenant (the queue is shared with other
// tests), in claim order.
func mine(jobs []*ingestjob.Job, tenant shared.ID) []*ingestjob.Job {
	var out []*ingestjob.Job
	for _, j := range jobs {
		if j.TenantID() == tenant {
			out = append(out, j)
		}
	}
	return out
}

func enqueueRouted(t *testing.T, repo *IngestJobRepository, tenant shared.ID, name string, lane ingestjob.Lane, scope string) *ingestjob.Job {
	t.Helper()
	j := ingestjob.NewJob(tenant, nil, name, "trivy", []byte(name)).Route(lane, scope)
	stored, _, err := repo.Enqueue(context.Background(), j)
	if err != nil {
		t.Fatalf("enqueue %s: %v", name, err)
	}
	return stored
}

// At most one job per scope key runs at a time: a batch takes one, a second
// claim while it runs takes none of that scope, and the next one runs once
// the first is done. Concurrent claimers never run two of one scope.
func TestIngestClaim_OneRunningJobPerScope_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	repo.SetMaxRunningPerTenant(100)
	scope := ingestjob.ScopeKey(tenant, "repo", shared.NewID().String())
	for _, n := range []string{"s1", "s2", "s3"} {
		enqueueRouted(t, repo, tenant, n, ingestjob.LaneInteractive, scope)
	}
	got, err := repo.ClaimBatch(ctx, "w1", 100)
	if err != nil {
		t.Fatal(err)
	}
	first := mine(got, tenant)
	if len(first) != 1 {
		t.Fatalf("claimed %d jobs of one scope in a batch, want 1", len(first))
	}
	got, err = repo.ClaimBatch(ctx, "w2", 100)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(mine(got, tenant)); n != 0 {
		t.Fatalf("claimed %d jobs of a scope that has one running", n)
	}
	if err := repo.Complete(ctx, first[0].ID(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.ClaimBatch(ctx, "w3", 100)
	if n := len(mine(got, tenant)); n != 1 {
		t.Fatalf("after the first finished: claimed %d, want 1", n)
	}

	// Many claimers at once over a fresh scope: one runs, whatever the race.
	scope2 := ingestjob.ScopeKey(tenant, "repo", shared.NewID().String())
	for i := range 6 {
		enqueueRouted(t, repo, tenant, "race-"+string(rune('a'+i)), ingestjob.LaneInteractive, scope2)
	}
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := repo.ClaimBatch(ctx, "racer", 3); err != nil {
				t.Errorf("claimer %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	var running int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_jobs WHERE scope_key = $1 AND status = 'processing'`, scope2).Scan(&running); err != nil {
		t.Fatal(err)
	}
	if running != 1 {
		t.Fatalf("%d jobs of one scope running after a claim race, want 1", running)
	}
}

// Lanes come first: an urgent job enqueued after bulk jobs is claimed first,
// then interactive, then bulk.
func TestIngestClaim_LaneOrder_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	repo.SetMaxRunningPerTenant(100)
	for i := range 3 {
		enqueueRouted(t, repo, tenant, "bulk-"+string(rune('0'+i)), ingestjob.LaneBulk, "")
	}
	time.Sleep(5 * time.Millisecond)
	enqueueRouted(t, repo, tenant, "interactive", ingestjob.LaneInteractive, "")
	urgent := enqueueRouted(t, repo, tenant, "urgent", ingestjob.LaneUrgent, "")
	got, err := repo.ClaimBatch(ctx, "w", 100)
	if err != nil {
		t.Fatal(err)
	}
	claimed := mine(got, tenant)
	if len(claimed) != 5 || claimed[0].ID() != urgent.ID() || claimed[0].Lane() != ingestjob.LaneUrgent ||
		claimed[1].Lane() != ingestjob.LaneInteractive || claimed[4].Lane() != ingestjob.LaneBulk {
		lanes := []ingestjob.Lane{}
		for _, j := range claimed {
			lanes = append(lanes, j.Lane())
		}
		t.Fatalf("claim order %v", lanes)
	}
}

// A tenant has at most the running cap of jobs processing; another tenant
// still gets its job in the same batch.
func TestIngestClaim_TenantRunningCap_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	a, b := newIngestJobTestTenant(t, db), newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	repo.SetMaxRunningPerTenant(2)
	for i := range 5 {
		enqueueRouted(t, repo, a, "a-"+string(rune('0'+i)), ingestjob.LaneBulk, "")
	}
	enqueueRouted(t, repo, b, "b-0", ingestjob.LaneBulk, "")
	got, err := repo.ClaimBatch(ctx, "w", 100)
	if err != nil {
		t.Fatal(err)
	}
	if na, nb := len(mine(got, a)), len(mine(got, b)); na != 2 || nb != 1 {
		t.Fatalf("claimed A=%d B=%d, want 2/1", na, nb)
	}
	got, _ = repo.ClaimBatch(ctx, "w", 100)
	if na := len(mine(got, a)); na != 0 {
		t.Fatalf("a tenant at its cap got %d more", na)
	}
}

// A job whose attempts ran out is never claimed; a lease that expires on
// the last attempt makes the job dead (returned once), an earlier one
// returns it to pending.
func TestIngestClaim_PoisonCap_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	repo.SetMaxRunningPerTenant(100)
	spent := enqueueRouted(t, repo, tenant, "spent", ingestjob.LaneBulk, "")
	if _, err := db.ExecContext(ctx, `UPDATE ingest_jobs SET attempts = max_attempts WHERE id = $1`, spent.ID().String()); err != nil {
		t.Fatal(err)
	}
	got, _ := repo.ClaimBatch(ctx, "w", 100)
	for _, j := range mine(got, tenant) {
		if j.ID() == spent.ID() {
			t.Fatal("a job with no attempts left was claimed")
		}
	}

	last := enqueueRouted(t, repo, tenant, "last", ingestjob.LaneBulk, "")
	early := enqueueRouted(t, repo, tenant, "early", ingestjob.LaneBulk, "")
	if _, err := db.ExecContext(ctx, `UPDATE ingest_jobs SET status = 'processing', locked_at = now() - interval '1 hour',
		attempts = CASE WHEN id = $1 THEN max_attempts ELSE 1 END WHERE id IN ($1, $2)`, last.ID().String(), early.ID().String()); err != nil {
		t.Fatal(err)
	}
	_, dead, err := repo.ReleaseStale(ctx, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deadMine := mine(dead, tenant)
	if len(deadMine) != 1 || deadMine[0].ID() != last.ID() || deadMine[0].PublicError() != ingestjob.ErrorApplyFailed {
		t.Fatalf("dead = %+v", deadMine)
	}
	if j, _ := repo.GetByID(ctx, tenant, early.ID()); j.Status() != ingestjob.StatusPending {
		t.Fatalf("early lease expiry: %s, want pending", j.Status())
	}
	if j, _ := repo.GetByID(ctx, tenant, last.ID()); j.Status() != ingestjob.StatusDead {
		t.Fatalf("last lease expiry: %s, want dead", j.Status())
	}
}

func TestIngestClaim_TenantDepth_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	j1 := enqueueRouted(t, repo, tenant, "d1", ingestjob.LaneBulk, "")
	enqueueRouted(t, repo, tenant, "d2", ingestjob.LaneBulk, "")
	if err := repo.Complete(ctx, j1.ID(), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	unfinished, finished, err := repo.TenantDepth(ctx, tenant, time.Now().Add(-time.Minute))
	if err != nil || unfinished != 1 || finished != 1 {
		t.Fatalf("depth %d finished %d err %v", unfinished, finished, err)
	}
	if u, _, _ := repo.TenantDepth(ctx, shared.NewID(), time.Now().Add(-time.Minute)); u != 0 {
		t.Fatalf("another tenant sees %d", u)
	}
}
