package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/ingestjob"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Exercises the full ingest_jobs lifecycle against a real Postgres
// (enqueue/idempotency, claim, complete, fail/backoff, release-stale, count).
// Self-contained: uses a random tenant (the table has no FKs) and cleans up.
// Skipped unless DATABASE_URL is set.
func TestIngestJobRepository_Lifecycle(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping ingest_jobs DB lifecycle test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	repo := NewIngestJobRepository(&DB{DB: db})
	tenantID := shared.NewID()
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), "DELETE FROM ingest_jobs WHERE tenant_id = $1", tenantID.String())
	})

	payload := []byte(`{"version":"1.0","findings":[]}`)

	// Enqueue → created.
	job := ingestjob.NewJob(tenantID, nil, "scan-1", "trivy", payload)
	stored, created, err := repo.Enqueue(ctx, job)
	if err != nil || !created {
		t.Fatalf("Enqueue: created=%v err=%v", created, err)
	}
	if stored.Status() != ingestjob.StatusPending {
		t.Fatalf("expected pending, got %s", stored.Status())
	}

	// Idempotent re-enqueue (same tenant/report/payload) → existing, not created.
	dup := ingestjob.NewJob(tenantID, nil, "scan-1", "trivy", payload)
	storedDup, created2, err := repo.Enqueue(ctx, dup)
	if err != nil {
		t.Fatalf("Enqueue dup: %v", err)
	}
	if created2 {
		t.Fatal("expected idempotent re-enqueue to NOT create a new job")
	}
	if storedDup.ID() != stored.ID() {
		t.Fatalf("idempotent enqueue returned different id: %s vs %s", storedDup.ID(), stored.ID())
	}

	// Count pending.
	if n, err := repo.CountPendingByTenant(ctx, tenantID); err != nil || n != 1 {
		t.Fatalf("CountPendingByTenant = %d, err=%v (want 1)", n, err)
	}

	// Claim.
	claimed, err := repo.ClaimBatch(ctx, "worker-1", 10)
	if err != nil {
		t.Fatalf("ClaimBatch: %v", err)
	}
	var got *ingestjob.Job
	for _, j := range claimed {
		if j.ID() == stored.ID() {
			got = j
		}
	}
	if got == nil {
		t.Fatal("claimed batch did not include our job")
	}
	if got.Status() != ingestjob.StatusProcessing || got.Attempts() != 1 {
		t.Fatalf("after claim: status=%s attempts=%d (want processing/1)", got.Status(), got.Attempts())
	}

	// Complete.
	if err := repo.Complete(ctx, stored.ID(), []byte(`{"findings_created":0}`)); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	done, err := repo.GetByID(ctx, tenantID, stored.ID())
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if done.Status() != ingestjob.StatusCompleted || len(done.Result()) == 0 {
		t.Fatalf("after complete: status=%s result=%q", done.Status(), done.Result())
	}

	// Fail with future backoff → pending but not immediately claimable.
	job2 := ingestjob.NewJob(tenantID, nil, "scan-2", "trivy", []byte(`{"version":"1.0"}`))
	stored2, _, err := repo.Enqueue(ctx, job2)
	if err != nil {
		t.Fatalf("Enqueue job2: %v", err)
	}
	if err := repo.Fail(ctx, stored2.ID(), "boom", time.Now().Add(time.Hour), false); err != nil {
		t.Fatalf("Fail: %v", err)
	}
	again, _ := repo.GetByID(ctx, tenantID, stored2.ID())
	if again.Status() != ingestjob.StatusPending || again.LastError() != "boom" {
		t.Fatalf("after fail: status=%s err=%q (want pending/boom)", again.Status(), again.LastError())
	}
	// available_at is in the future → must not be claimed now.
	claimed2, _ := repo.ClaimBatch(ctx, "worker-1", 10)
	for _, j := range claimed2 {
		if j.ID() == stored2.ID() {
			t.Fatal("claimed a job whose available_at is in the future")
		}
	}

	// ReleaseStale: claim job2 after making it due, age the lock, then release.
	_, _ = db.ExecContext(ctx, "UPDATE ingest_jobs SET available_at = NOW() WHERE id = $1", stored2.ID().String())
	if _, err := repo.ClaimBatch(ctx, "worker-1", 10); err != nil {
		t.Fatalf("ClaimBatch job2: %v", err)
	}
	_, _ = db.ExecContext(ctx, "UPDATE ingest_jobs SET locked_at = NOW() - interval '1 hour' WHERE id = $1", stored2.ID().String())
	released, err := repo.ReleaseStale(ctx, 30*time.Minute)
	if err != nil || released < 1 {
		t.Fatalf("ReleaseStale = %d, err=%v (want >=1)", released, err)
	}
	final, _ := repo.GetByID(ctx, tenantID, stored2.ID())
	if final.Status() != ingestjob.StatusPending {
		t.Fatalf("after release-stale: status=%s (want pending)", final.Status())
	}
}
