package contentsource_test

// Fetch guards: a server-wide cap on concurrent fetches shared by Test and
// the sync worker, a low-disk refusal, and the per-organization private
// network decision handed to the connection.

import (
	"context"
	"errors"
	"testing"
	"time"

	app "github.com/openctemio/openctem/api/internal/app/contentsource"
	"github.com/openctemio/openctem/api/internal/infra/fetchers"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
	"github.com/openctemio/openctem/api/pkg/domain/limits"
)

// With every fetch slot taken, Test answers busy (503) and the sync worker
// claims nothing; with a slot free the due source syncs.
func TestRuleSources_FetchSlotsAreSharedByTestAndSync_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-slots", nil)
	e.svc.SetMaxConcurrentFetches(1)

	entered, unblock := make(chan struct{}), make(chan struct{})
	e.svc.SetFetcher(func(ctx context.Context, req fetchers.GitRequest) (*fetchers.GitSnapshot, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-unblock
		return e.git.fetch(ctx, req)
	}, nil)
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})

	in := app.TestInput{Kind: "semgrep-rules", URL: "https://git.example.com/acme/rules.git", Ref: "main"}
	done := make(chan error, 1)
	go func() { _, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), in); done <- err }()
	<-entered

	if _, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), in); !errors.Is(err, dom.ErrFetchBusy) || !errors.Is(err, dom.ErrUnavailable) {
		t.Fatalf("second Test while the slot is taken: %v", err)
	}
	if err := e.repo.RequestSync(ctx, e.tenantA, src.ID, e.clock); err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.RunDue(ctx); err != nil || n != 0 {
		t.Fatalf("sync run while the slot is taken: %d %v", n, err)
	}
	if leased, _ := e.leaseOf(t, src.ID.String()); leased {
		t.Fatal("the worker claimed a source it could not fetch")
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n, err := e.svc.RunDue(ctx); err != nil || n != 1 {
		t.Fatalf("sync run with a free slot: %d %v", n, err)
	}
}

// A server low on disk answers unavailable for Test and records a failed
// sync, never a partial fetch.
func TestRuleSources_LowDiskRefusesFetch_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-disk", nil)
	e.svc.SetFetcher(func(context.Context, fetchers.GitRequest) (*fetchers.GitSnapshot, error) {
		return nil, fetchers.ErrLowDisk
	}, nil)
	in := app.TestInput{Kind: "semgrep-rules", URL: "https://git.example.com/acme/rules.git", Ref: "main"}
	if _, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), in); !errors.Is(err, dom.ErrLowDisk) || !errors.Is(err, dom.ErrUnavailable) {
		t.Fatalf("Test on a low disk: %v", err)
	}
	src = e.runSync(t, src)
	if src.LastSyncStatus != dom.SyncFailed || len(e.snapshots(t, src)) != 0 {
		t.Fatalf("sync on a low disk: %s", src.LastSyncStatus)
	}
}

// SECURITY: the private-network decision follows the organization's feature
// and reaches the connection: an organization without private_git is never
// handed the installation's private ranges, even for a host that looked
// public when it was checked.
func TestRuleSources_PrivateAccessIsPerOrganization_DB(t *testing.T) {
	e := newEnv(t)
	src := e.create(t, "acme-priv", nil)
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})

	e.private = false
	src = e.runSync(t, src)
	if !e.git.last.PrivateOK {
		t.Fatal("an organization with the feature is not handed the private ranges")
	}

	e.lim.denied[limits.FeatureContentPrivateGit] = true
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r1", "r2")})
	src = e.runSync(t, src)
	if e.git.last.PrivateOK {
		t.Fatal("an organization without the feature is handed the private ranges")
	}
	// A host that resolves private is refused before any fetch.
	e.private = true
	calls := e.git.calls
	e.clock = e.clock.Add(time.Minute)
	src = e.runSync(t, src)
	if e.git.calls != calls || src.LastSyncStatus != dom.SyncFailed {
		t.Fatalf("a private host without the feature: fetches %d->%d status %s", calls, e.git.calls, src.LastSyncStatus)
	}
}
