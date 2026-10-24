package contentsource_test

// Which rule source packs reach sensors: only the current snapshot's pack of
// a source, never a candidate that was superseded unapproved, an orphan left
// by a failed sync, or a rejected snapshot whose cleanup failed.

import (
	"context"
	"errors"
	"testing"
	"time"

	contentpackapp "github.com/openctemio/openctem/api/internal/app/contentpack"
	app "github.com/openctemio/openctem/api/internal/app/contentsource"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// deliverable lists the pack ids sensors of tenant A may receive.
func (e *env) deliverable(t *testing.T) []string {
	t.Helper()
	list, _, err := e.packs.List(context.Background(), contentpackapp.ListInput{TenantID: e.tenantA.String(), Status: "active", Deliverable: true, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, p := range list {
		out = append(out, p.ID.String())
	}
	return out
}

func (e *env) gitPacks(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.db.QueryRowContext(context.Background(), `SELECT count(*) FROM content_packs WHERE tenant_id = $1 AND source = 'git'`, e.tenantA.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

type failCreateRepo struct {
	dom.Repository
	fail bool
}

func (r *failCreateRepo) CreateSnapshot(ctx context.Context, sn *dom.Snapshot) error {
	if r.fail {
		return errors.New("create snapshot failed")
	}
	return r.Repository.CreateSnapshot(ctx, sn)
}

type failDeletePacks struct {
	app.PackStore
	fail bool
}

func (p *failDeletePacks) DeleteSourcePack(ctx context.Context, tenantID, id shared.ID) error {
	if p.fail {
		return errors.New("delete pack failed")
	}
	return p.PackStore.DeleteSourcePack(ctx, tenantID, id)
}

// SECURITY: a candidate held for review that the next commit supersedes was
// never approved and must not reach sensors.
func TestRuleSources_SupersededCandidateNotDelivered_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-held", func(in *app.CreateInput) { in.Policy = "review" })

	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r1", "r2")})
	src = e.runSync(t, src)

	var held, newest *dom.Snapshot
	for _, sn := range e.snapshots(t, src) {
		switch sn.State {
		case dom.StateSuperseded:
			held = sn
		case dom.StateCandidate:
			newest = sn
		}
	}
	if held == nil || newest == nil {
		t.Fatalf("want a superseded and a candidate snapshot: %+v", e.snapshots(t, src))
	}
	if got := e.deliverable(t); len(got) != 0 {
		t.Fatalf("an unapproved candidate is deliverable: %v", got)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, newest.ID); err != nil {
		t.Fatal(err)
	}
	got := e.deliverable(t)
	if len(got) != 1 || got[0] != newest.ContentPackID.String() {
		t.Fatalf("after promotion deliverable = %v, want only %s (not the superseded %s)", got, newest.ContentPackID, held.ContentPackID)
	}
}

// A sync whose snapshot row cannot be stored leaves no pack behind; if the
// pack delete fails too, the orphan is not deliverable and the collector
// removes it.
func TestRuleSources_FailedSnapshotLeavesNoDeliverablePack_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-orphan", nil)
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})

	broken := &failCreateRepo{Repository: e.repo, fail: true}
	src = e.runSyncOn(t, e.service(broken, e.packs), src)
	if src.LastSyncStatus != dom.SyncFailed || e.gitPacks(t) != 0 || len(e.deliverable(t)) != 0 {
		t.Fatalf("after a failed CreateSnapshot: status %s, git packs %d, deliverable %v", src.LastSyncStatus, e.gitPacks(t), e.deliverable(t))
	}

	// The pack delete fails as well: an orphan stays, undeliverable.
	e.clock = e.clock.Add(2 * time.Hour)
	src = e.runSyncOn(t, e.service(broken, &failDeletePacks{PackStore: e.packs, fail: true}), src)
	if e.gitPacks(t) != 1 || len(e.deliverable(t)) != 0 {
		t.Fatalf("orphan: git packs %d, deliverable %v", e.gitPacks(t), e.deliverable(t))
	}
	if _, err := e.service(e.repo, e.packs).CollectGarbage(ctx); err != nil {
		t.Fatal(err)
	}
	if e.gitPacks(t) != 0 {
		t.Fatalf("the collector left the orphan pack")
	}
}

// SECURITY: a rejected snapshot is collected; if its pack cannot be deleted
// the rejected content must still not be deliverable.
func TestRuleSources_FailedCleanupKeepsRejectedUndeliverable_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-reject", func(in *app.CreateInput) { in.Policy = "review" })
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	cand := e.snapshots(t, src)[0]
	if err := e.svc.Reject(ctx, e.actor(e.tenantA, e.user2), src.ID, cand.ID, "no"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, `UPDATE content_source_snapshots SET created_at = now() - interval '2 days' WHERE id = $1`, cand.ID.String()); err != nil {
		t.Fatal(err)
	}
	svc := e.service(e.repo, &failDeletePacks{PackStore: e.packs, fail: true})
	if n, err := svc.CollectGarbage(ctx); err != nil || n != 1 {
		t.Fatalf("collect: %d %v", n, err)
	}
	if e.gitPacks(t) != 1 || len(e.deliverable(t)) != 0 {
		t.Fatalf("after a failed pack delete: git packs %d, deliverable %v", e.gitPacks(t), e.deliverable(t))
	}
	e.clock = e.clock.Add(2 * time.Hour)
	if _, err := e.service(e.repo, e.packs).CollectGarbage(ctx); err != nil || e.gitPacks(t) != 0 {
		t.Fatalf("retry: %v, git packs %d", err, e.gitPacks(t))
	}
}
