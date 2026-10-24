package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/domain/ingestpayload"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Upload jobs (CI results, file imports): one job per tenant + report id +
// digest, scoped reads, dead jobs left out of the digest window, and the
// stored parts readable only by their own tenant.
func TestIngestUploadJobs_DB(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	repo := NewIngestJobRepository(&DB{DB: db})
	payloads := NewIngestPayloadRepository(&DB{DB: db})
	digest := bytes.Repeat([]byte{1}, 32)
	runRef := shared.NewID().String()

	job := ingestjob.NewUploadJob(shared.NewID(), tenant, ingestjob.KindCIResults, runRef, "run:"+runRef, "ci:"+runRef, []byte(`{"export":false}`), digest)
	stored, created, err := repo.EnqueueUpload(ctx, job)
	if err != nil || !created || stored.Kind() != ingestjob.KindCIResults || stored.SourceRef() != runRef || stored.SubmittedBy() != "run:"+runRef {
		t.Fatalf("enqueue: %+v created=%v err=%v", stored, created, err)
	}
	again := ingestjob.NewUploadJob(shared.NewID(), tenant, ingestjob.KindCIResults, runRef, "run:"+runRef, "ci:"+runRef, nil, digest)
	if st, created, err := repo.EnqueueUpload(ctx, again); err != nil || created || st.ID() != job.ID() {
		t.Fatalf("same key again: %v %v %v", st, created, err)
	}
	// The same key in another tenant is that tenant's own job.
	otherJob := ingestjob.NewUploadJob(shared.NewID(), other, ingestjob.KindCIResults, runRef, "run:"+runRef, "ci:"+runRef, nil, digest)
	if _, created, err := repo.EnqueueUpload(ctx, otherJob); err != nil || !created {
		t.Fatalf("other tenant: %v %v", created, err)
	}
	if _, err := repo.GetUploadByKey(ctx, other, "ci:"+runRef, bytes.Repeat([]byte{2}, 32)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	if got, err := repo.BySource(ctx, tenant, ingestjob.KindCIResults, runRef); err != nil || got.ID() != job.ID() {
		t.Fatalf("by source: %v %v", got, err)
	}

	pending, dead, err := repo.SourceState(ctx, tenant, ingestjob.KindCIResults, runRef)
	if err != nil || pending != 1 || dead != 0 {
		t.Fatalf("state: %d %d %v", pending, dead, err)
	}
	if recent, err := repo.FindRecentUpload(ctx, tenant, ingestjob.KindCIResults, "run:"+runRef, digest, time.Now().Add(-time.Minute)); err != nil || recent.ID() != job.ID() {
		t.Fatalf("recent: %v %v", recent, err)
	}
	// Outside the window, or another principal: none.
	if _, err := repo.FindRecentUpload(ctx, tenant, ingestjob.KindCIResults, "run:"+runRef, digest, time.Now().Add(time.Minute)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("outside the window: %v", err)
	}
	if _, err := repo.FindRecentUpload(ctx, tenant, ingestjob.KindCIResults, "user:x", digest, time.Now().Add(-time.Minute)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another principal: %v", err)
	}

	// Dead: out of the digest window, counted dead, requeued only while its
	// stored report is there.
	if err := repo.Fail(ctx, job.ID(), processing(t, db, job.ID()), "boom", ingestjob.ErrorApplyFailed, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.GetByID(ctx, tenant, job.ID()); got.PublicError() != ingestjob.ErrorApplyFailed {
		t.Fatalf("public error = %q", got.PublicError())
	}
	if _, err := repo.FindRecentUpload(ctx, tenant, ingestjob.KindCIResults, "run:"+runRef, digest, time.Now().Add(-time.Minute)); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("a dead upload is still recent: %v", err)
	}
	if _, dead, _ := repo.SourceState(ctx, tenant, ingestjob.KindCIResults, runRef); dead != 1 {
		t.Fatalf("dead = %d", dead)
	}
	if ok, err := repo.RequeueDeadUpload(ctx, tenant, job.ID()); err != nil || ok {
		t.Fatalf("requeued without a stored report: %v %v", ok, err)
	}
	sealer, _ := ingestpayload.NewSealer(bytes.Repeat([]byte{5}, 32))
	part, _ := sealer.Seal(tenant, job.ID(), 0, "results", []byte("report"))
	if err := payloads.Put(ctx, part); err != nil {
		t.Fatal(err)
	}
	if ok, err := repo.RequeueDeadUpload(ctx, other, job.ID()); err != nil || ok {
		t.Fatalf("another tenant requeued the job: %v %v", ok, err)
	}
	if ok, err := repo.RequeueDeadUpload(ctx, tenant, job.ID()); err != nil || !ok {
		t.Fatalf("requeue: %v %v", ok, err)
	}
	if got, _ := repo.GetByID(ctx, tenant, job.ID()); got.Status() != ingestjob.StatusPending || got.Attempts() != 0 || got.PublicError() != "" {
		t.Fatalf("after requeue: %s attempts %d code %q", got.Status(), got.Attempts(), got.PublicError())
	}

	// Parts: the other tenant reads none and deletes none.
	if got, err := payloads.List(ctx, other, job.ID()); err != nil || len(got) != 0 {
		t.Fatalf("another tenant listed %d parts (%v)", len(got), err)
	}
	if err := payloads.DeleteJob(ctx, other, job.ID()); err != nil {
		t.Fatal(err)
	}
	got, err := payloads.List(ctx, tenant, job.ID())
	if err != nil || len(got) != 1 {
		t.Fatalf("parts: %d %v", len(got), err)
	}
	if plain, err := sealer.Open(got[0]); err != nil || string(plain) != "report" {
		t.Fatalf("open stored part: %q %v", plain, err)
	}
	// A retry failure keeps the report; apply_failed (dead) keeps it for a
	// requeue; a permanent failure with a fixed code deletes it with the
	// failure (it never runs again), and only the failed job's own parts.
	if err := repo.Fail(ctx, job.ID(), processing(t, db, job.ID()), "transient", "", time.Now(), false); err != nil {
		t.Fatal(err)
	}
	if err := repo.Fail(ctx, job.ID(), processing(t, db, job.ID()), "boom", ingestjob.ErrorApplyFailed, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := payloads.List(ctx, tenant, job.ID()); len(got) != 1 {
		t.Fatalf("apply_failed dropped the stored report: %d parts", len(got))
	}
	permRef := shared.NewID().String()
	perm := ingestjob.NewUploadJob(shared.NewID(), tenant, ingestjob.KindCIResults, permRef, "run:"+permRef, "ci:"+permRef, nil, digest)
	if _, _, err := repo.EnqueueUpload(ctx, perm); err != nil {
		t.Fatal(err)
	}
	permPart, _ := sealer.Seal(tenant, perm.ID(), 0, "results", []byte("garbage"))
	if err := payloads.Put(ctx, permPart); err != nil {
		t.Fatal(err)
	}
	if err := repo.Fail(ctx, perm.ID(), processing(t, db, perm.ID()), "unreadable", "unreadable", time.Now(), true); err != nil {
		t.Fatal(err)
	}
	if got, _ := payloads.List(ctx, tenant, perm.ID()); len(got) != 0 {
		t.Fatalf("a permanently failed upload kept %d stored parts", len(got))
	}
	if got, _ := payloads.List(ctx, tenant, job.ID()); len(got) != 1 {
		t.Fatalf("another job's report was deleted: %d parts", len(got))
	}
	if ok, err := repo.RequeueDeadUpload(ctx, tenant, job.ID()); err != nil || !ok {
		t.Fatalf("requeue after apply_failed: %v %v", ok, err)
	}

	// An applied upload keeps no envelope.
	if err := repo.Complete(ctx, job.ID(), processing(t, db, job.ID()), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if done, _ := repo.GetByID(ctx, tenant, job.ID()); string(done.Payload()) != "{}" {
		t.Fatalf("applied job payload = %q", done.Payload())
	}
}
