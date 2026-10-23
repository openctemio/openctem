package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
)

// A worker writes the outcome only for the attempt it claimed and only while
// the job is still processing: after its lease was released (or the job was
// claimed again) Complete and Fail answer ErrLeaseLost and change nothing.
func TestIngestLease_CompleteAndFailAreConditional_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	status := func(j *ingestjob.Job) ingestjob.Status {
		got, err := repo.GetByID(ctx, tenant, j.ID())
		if err != nil {
			t.Fatal(err)
		}
		return got.Status()
	}

	j := enqueueRouted(t, repo, tenant, "lease-a", ingestjob.LaneBulk, "")
	attempt := processing(t, db, j.ID())

	// The wrong attempt writes nothing.
	if err := repo.Complete(ctx, j.ID(), attempt+1, []byte(`{}`)); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Complete with another attempt = %v", err)
	}
	if err := repo.Fail(ctx, j.ID(), attempt+1, "x", "", time.Now(), false); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Fail with another attempt = %v", err)
	}
	if status(j) != ingestjob.StatusProcessing {
		t.Fatalf("status = %s after refused writes", status(j))
	}

	// The lease expires: the job is released; the old worker may not write,
	// and a second claim (a new attempt) is not overwritten by it either.
	if _, err := db.ExecContext(ctx, `UPDATE ingest_jobs SET locked_at = NOW() - interval '1 hour' WHERE id = $1`, j.ID().String()); err != nil {
		t.Fatal(err)
	}
	if n, _, err := repo.ReleaseStale(ctx, 5*time.Minute); err != nil || n < 1 {
		t.Fatalf("ReleaseStale = %d, %v", n, err)
	}
	if err := repo.Complete(ctx, j.ID(), attempt, []byte(`{}`)); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Complete after release = %v", err)
	}
	if status(j) != ingestjob.StatusPending {
		t.Fatalf("status = %s, want pending", status(j))
	}
	second := processing(t, db, j.ID())
	if err := repo.Fail(ctx, j.ID(), attempt, "late", "", time.Now(), true); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Fail by the first attempt = %v", err)
	}
	if err := repo.Complete(ctx, j.ID(), second, []byte(`{}`)); err != nil {
		t.Fatalf("Complete by the holder: %v", err)
	}
	if status(j) != ingestjob.StatusCompleted {
		t.Fatalf("status = %s, want completed", status(j))
	}
}

// Renew keeps a running job out of ReleaseStale, and only for the attempt
// that holds it.
func TestIngestLease_RenewKeepsTheLease_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	j := enqueueRouted(t, repo, tenant, "lease-b", ingestjob.LaneBulk, "")
	attempt := processing(t, db, j.ID())

	if _, err := db.ExecContext(ctx, `UPDATE ingest_jobs SET locked_at = NOW() - interval '1 hour' WHERE id = $1`, j.ID().String()); err != nil {
		t.Fatal(err)
	}
	if err := repo.Renew(ctx, j.ID(), attempt+1); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Renew with another attempt = %v", err)
	}
	if err := repo.Renew(ctx, j.ID(), attempt); err != nil {
		t.Fatal(err)
	}
	if _, dead, err := repo.ReleaseStale(ctx, 5*time.Minute); err != nil || len(mine(dead, tenant)) != 0 {
		t.Fatalf("ReleaseStale: %v %v", dead, err)
	}
	got, _ := repo.GetByID(ctx, tenant, j.ID())
	if got.Status() != ingestjob.StatusProcessing {
		t.Fatalf("a renewed job was released: %s", got.Status())
	}
	if err := repo.Complete(ctx, j.ID(), attempt, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := repo.Renew(ctx, j.ID(), attempt); !errors.Is(err, ingestjob.ErrLeaseLost) {
		t.Fatalf("Renew of a finished job = %v", err)
	}
}
