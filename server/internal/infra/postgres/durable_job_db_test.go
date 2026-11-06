package postgres

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/durablejob"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func countJobs(ctx context.Context, t *testing.T, db *DB, tenantID shared.ID, kind durablejob.Kind, subject shared.ID) (n int, payload string) {
	t.Helper()
	if err := db.QueryRowContext(ctx, `SELECT count(*), COALESCE(max(payload), '') FROM durable_jobs
		WHERE tenant_id = $1 AND kind = $2 AND subject_id = $3`, tenantID.String(), string(kind), subject.String()).Scan(&n, &payload); err != nil {
		t.Fatal(err)
	}
	return n, payload
}

// A status change of a linked finding queues its ticket status push in the
// status write's transaction: the job exists exactly when the status moved,
// a burst coalesces to one pending job, and a write that changed nothing or
// rolled back queues nothing. Before, the push lived only in Redis and an
// enqueue failure was logged and dropped.
func TestDurableJobs_QueuedWithTheStatusWrite(t *testing.T) {
	ctx := context.Background()
	db := &DB{DB: openGroupsDB(t)}
	repo := NewFindingRepository(db)
	tenantID := seedTestTenant(ctx, t, db.DB)
	other := seedTestTenant(ctx, t, db.DB)
	assetID := seedTestAsset(ctx, t, db.DB, tenantID)

	f, err := vulnerability.NewFinding(tenantID, assetID, vulnerability.FindingSourceSCA, "trivy", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	f.SetFingerprint("fp-durable-" + f.ID().String())
	if err := repo.Create(ctx, f); err != nil {
		t.Fatal(err)
	}

	move := func(ctx context.Context, tid shared.ID, status vulnerability.FindingStatus) error {
		ctx = durablejob.WithEnqueue(vulnerability.WithPersonMove(ctx), durablejob.StatusSyncJobs(tid, f.ID())...)
		return repo.UpdateStatusBatch(ctx, tid, []shared.ID{f.ID()}, status, "", nil, vulnerability.Closure{})
	}

	// Another tenant's write moves nothing and queues nothing.
	if err := move(ctx, other, vulnerability.FindingStatusConfirmed); err != nil {
		t.Fatal(err)
	}
	if n, _ := countJobs(ctx, t, db, other, durablejob.KindJiraStatusSync, f.ID()); n != 0 {
		t.Fatalf("cross-tenant write queued %d jobs", n)
	}

	for _, st := range []vulnerability.FindingStatus{vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress} {
		if err := move(ctx, tenantID, st); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []durablejob.Kind{durablejob.KindJiraStatusSync, durablejob.KindGitHubStatusSync} {
		if n, _ := countJobs(ctx, t, db, tenantID, k, f.ID()); n != 1 {
			t.Fatalf("%s jobs after two moves = %d, want 1 pending", k, n)
		}
	}

	// A job that cannot be written (an unknown tenant breaks its foreign
	// key) rolls the status back with it: both or neither.
	bad := durablejob.WithEnqueue(vulnerability.WithPersonMove(ctx), durablejob.Job{
		Kind: durablejob.KindJiraStatusSync, TenantID: shared.NewID(), SubjectID: shared.NewID()})
	if err := repo.UpdateStatusBatch(bad, tenantID, []shared.ID{f.ID()}, vulnerability.FindingStatusConfirmed, "", nil, vulnerability.Closure{}); err == nil {
		t.Fatal("status write with an unwritable job succeeded")
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM findings WHERE id = $1 AND tenant_id = $2`, f.ID().String(), tenantID.String()).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != string(vulnerability.FindingStatusInProgress) {
		t.Fatalf("status = %s after the failed write, want it unchanged (in_progress)", status)
	}
}

// The invitation e-mail is queued with the invitation, and a resend (token
// rotation) replaces the unsent e-mail of the old token.
func TestDurableJobs_InvitationEmailQueuedWithTheInvitation(t *testing.T) {
	ctx := context.Background()
	db := openRoleRaceDB(t)
	repo := NewTenantRepository(db)
	tenantID := seedTenant(ctx, t, db)
	inviter := seedUser(ctx, t, db)
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenant_invitations WHERE invited_by = $1`, inviter.String())
	})
	inv, err := tenant.NewInvitation(tenantID, "durable-"+shared.NewID().String()[24:]+"@example.com", tenant.RoleMember, inviter,
		[]string{"00000000-0000-0000-0000-000000000003"})
	if err != nil {
		t.Fatal(err)
	}
	job := func(payload string) context.Context {
		return durablejob.WithEnqueue(ctx, durablejob.Job{Kind: durablejob.KindInvitationEmail, TenantID: tenantID, SubjectID: inv.ID(), Payload: payload})
	}
	if err := repo.CreateInvitation(job("sealed-1"), inv); err != nil {
		t.Fatal(err)
	}
	if n, p := countJobs(ctx, t, db, tenantID, durablejob.KindInvitationEmail, inv.ID()); n != 1 || p != "sealed-1" {
		t.Fatalf("after create: %d jobs, payload %q", n, p)
	}

	got, err := repo.GetInvitationByToken(ctx, inv.Token())
	if err != nil {
		t.Fatal(err)
	}
	if err := got.MarkResent(time.Now().Add(tenant.ResendCooldown)); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdateInvitation(job("sealed-2"), got); err != nil {
		t.Fatal(err)
	}
	if n, p := countJobs(ctx, t, db, tenantID, durablejob.KindInvitationEmail, inv.ID()); n != 1 || p != "sealed-2" {
		t.Fatalf("after resend: %d jobs, payload %q, want the new token's only", n, p)
	}
}

// Claiming: two workers never get the same job; a job whose worker died is
// claimed again after its lease; kinds without a handler are left alone; a
// retry is superseded by a newer pending job; a buried job loses its payload.
func TestDurableJobs_ClaimRetryBury(t *testing.T) {
	ctx := context.Background()
	db := &DB{DB: openGroupsDB(t)}
	store := NewDurableJobRepository(db)
	tenantID := seedTestTenant(ctx, t, db.DB)
	// Jobs of other tests in the same database must not be claimed here.
	if _, err := db.ExecContext(ctx, `DELETE FROM durable_jobs`); err != nil {
		t.Fatal(err)
	}
	queue := func(jobs ...durablejob.Job) {
		t.Helper()
		if err := db.Transaction(ctx, func(tx *sql.Tx) error { return insertDurableJobsTx(ctx, tx, jobs) }); err != nil {
			t.Fatal(err)
		}
	}
	var subjects []shared.ID
	for range 20 {
		s := shared.NewID()
		subjects = append(subjects, s)
		queue(durablejob.Job{Kind: durablejob.KindJiraStatusSync, TenantID: tenantID, SubjectID: s})
	}
	queue(durablejob.Job{Kind: durablejob.KindInvitationEmail, TenantID: tenantID, SubjectID: shared.NewID(), Payload: "secret"})

	kinds := []durablejob.Kind{durablejob.KindJiraStatusSync}
	var mu sync.Mutex
	seen := map[shared.ID]int{}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				jobs, err := store.Claim(ctx, kinds, 3, time.Minute)
				if err != nil {
					t.Error(err)
					return
				}
				if len(jobs) == 0 {
					return
				}
				mu.Lock()
				for _, j := range jobs {
					seen[j.ID]++
					if j.Kind != durablejob.KindJiraStatusSync || j.TenantID != tenantID || j.Attempts != 1 {
						t.Errorf("claimed %+v", j)
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(seen) != 20 {
		t.Fatalf("claimed %d distinct jobs, want 20", len(seen))
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("job %s claimed %d times", id, n)
		}
	}

	// A worker that died: its lease passes and the job is claimed again.
	if _, err := db.ExecContext(ctx, `UPDATE durable_jobs SET locked_until = now() - interval '1 second' WHERE subject_id = $1`, subjects[0].String()); err != nil {
		t.Fatal(err)
	}
	again, err := store.Claim(ctx, kinds, 10, time.Minute)
	if err != nil || len(again) != 1 || again[0].SubjectID != subjects[0] || again[0].Attempts != 2 {
		t.Fatalf("reclaim = %+v, %v", again, err)
	}

	// Retry: due again later; superseded when a newer pending job exists.
	if err := store.Retry(ctx, again[0], time.Now().Add(-time.Second), "boom"); err != nil {
		t.Fatal(err)
	}
	retried, err := store.Claim(ctx, kinds, 10, time.Minute)
	if err != nil || len(retried) != 1 || retried[0].Attempts != 3 {
		t.Fatalf("retry claim = %+v, %v", retried, err)
	}
	queue(durablejob.Job{Kind: durablejob.KindJiraStatusSync, TenantID: tenantID, SubjectID: subjects[0]})
	if err := store.Retry(ctx, retried[0], time.Now(), "boom"); err != nil {
		t.Fatal(err)
	}
	if n, _ := countJobs(ctx, t, db, tenantID, durablejob.KindJiraStatusSync, subjects[0]); n != 1 {
		t.Fatalf("jobs for a retried subject with a newer pending job = %d, want 1", n)
	}

	// Bury keeps the row for inspection without its payload; complete removes.
	inv, err := store.Claim(ctx, []durablejob.Kind{durablejob.KindInvitationEmail}, 10, time.Minute)
	if err != nil || len(inv) != 1 || inv[0].Payload != "secret" {
		t.Fatalf("invitation claim = %+v, %v", inv, err)
	}
	if err := store.Bury(ctx, inv[0], "smtp refused"); err != nil {
		t.Fatal(err)
	}
	var status, lastErr string
	var payload *string
	if err := db.QueryRowContext(ctx, `SELECT status, payload, last_error FROM durable_jobs WHERE id = $1 AND tenant_id = $2`,
		inv[0].ID.String(), tenantID.String()).Scan(&status, &payload, &lastErr); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || payload != nil || lastErr != "smtp refused" {
		t.Fatalf("buried = %s %v %q", status, payload, lastErr)
	}
	if err := store.Complete(ctx, again[0]); err != nil {
		t.Fatal(err)
	}
}
