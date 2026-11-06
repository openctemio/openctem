package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Finished jobs leave the queue after the cutoff, unfinished ones never;
// stored parts go once applied, expired or orphaned, and stay while their
// job may still need them.
func TestIngestQueueRetention_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant := newIngestJobTestTenant(t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	payloads := NewIngestPayloadRepository(&DB{DB: db})
	sealer, _ := ingestpayload.NewSealer(bytes.Repeat([]byte{4}, 32))

	mk := func(name, status string, age time.Duration) *ingestjob.Job {
		j := enqueueRouted(t, repo, tenant, name, ingestjob.LaneBulk, "")
		if _, err := db.ExecContext(ctx, `UPDATE ingest_jobs SET status = $2, updated_at = now() - make_interval(secs => $3) WHERE id = $1`,
			j.ID().String(), status, age.Seconds()); err != nil {
			t.Fatal(err)
		}
		return j
	}
	day := 24 * time.Hour
	oldDone := mk("old-done", "completed", 40*day)
	oldDead := mk("old-dead", "dead", 40*day)
	newDone := mk("new-done", "completed", day)
	oldPending := mk("old-pending", "pending", 40*day)

	put := func(job shared.ID, expires time.Time, created time.Duration) {
		p, err := sealer.Seal(tenant, job, 0, "x", []byte("raw"))
		if err != nil {
			t.Fatal(err)
		}
		p.ExpiresAt = expires
		if err := payloads.Put(ctx, p); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE ingest_payloads SET created_at = now() - make_interval(secs => $2) WHERE job_id = $1`,
			job.String(), created.Seconds()); err != nil {
			t.Fatal(err)
		}
	}
	future := time.Now().Add(day)
	put(newDone.ID(), future, 0)                       // applied: goes
	put(oldPending.ID(), future, 0)                    // still needed: stays
	put(oldDead.ID(), time.Now().Add(-time.Minute), 0) // expired: goes
	orphanOld, orphanNew := shared.NewID(), shared.NewID()
	put(orphanOld, future, 2*time.Hour) // staged, never enqueued: goes
	put(orphanNew, future, 0)           // being received: stays

	now := time.Now()
	if _, err := repo.PurgePayloadsForPlatform(ctx, now, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PurgeFinishedJobsForPlatform(ctx, now.Add(-30*day), 1000); err != nil {
		t.Fatal(err)
	}
	left := func(job shared.ID) int {
		var n int
		_ = db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_payloads WHERE job_id = $1`, job.String()).Scan(&n)
		return n
	}
	for name, c := range map[string]struct {
		id   shared.ID
		want int
	}{"applied": {newDone.ID(), 0}, "pending": {oldPending.ID(), 1}, "expired": {oldDead.ID(), 0},
		"orphan old": {orphanOld, 0}, "orphan new": {orphanNew, 1}} {
		if got := left(c.id); got != c.want {
			t.Errorf("parts of %s: %d, want %d", name, got, c.want)
		}
	}
	exists := func(j *ingestjob.Job) bool {
		_, err := repo.GetByID(ctx, tenant, j.ID())
		return err == nil
	}
	if exists(oldDone) || exists(oldDead) {
		t.Fatal("a finished job past the cutoff was kept")
	}
	if !exists(newDone) || !exists(oldPending) {
		t.Fatal("a recent or unfinished job was purged")
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM ingest_payloads WHERE job_id = ANY($1)`, "{"+orphanNew.String()+","+oldPending.ID().String()+"}")
}
