package contentsource_test

import (
	"context"
	"errors"
	"testing"
	"time"

	app "github.com/openctemio/openctem/api/internal/app/contentsource"
	"github.com/openctemio/openctem/api/internal/infra/fetchers"
	dom "github.com/openctemio/openctem/api/pkg/domain/contentsource"
)

func (e *env) candidate(t *testing.T, src *dom.Source) *dom.Snapshot {
	t.Helper()
	for _, sn := range e.snapshots(t, src) {
		if sn.State == dom.StateCandidate {
			return sn
		}
	}
	t.Fatal("no candidate snapshot")
	return nil
}

// SECURITY: a sync does not consume the config authors. user2 points the
// source at a repository user2 controls, pushes again, and a later config
// change by another member must not let user2 promote the new content.
func TestFourEyes_AuthorsSurviveSyncs_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-bypass", func(in *app.CreateInput) { in.Policy = "review" })
	url := "https://evil.example.com/user2/rules.git"
	if _, err := e.svc.Update(ctx, e.actor(e.tenantA, e.user2), src.ID, app.UpdateInput{URL: &url}); err != nil {
		t.Fatal(err)
	}
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r1", "evil")})
	src = e.runSync(t, src)
	cand := e.candidate(t, src)
	if len(cand.ConfigAuthors) == 0 {
		t.Fatal("the second snapshot lost the config authors")
	}
	if _, err := e.svc.SetCredential(ctx, e.actor(e.tenantA, e.user3), src.ID, "x-access-token", "ghp_"+"abcdefghijklmnopqrstuvwxyz0123456789"); err != nil {
		t.Fatal(err)
	}
	src = e.runSync(t, src) // unchanged content also leaves the authors
	if got, _ := e.repo.Get(ctx, e.tenantA, src.ID); len(got.ConfigAuthors) == 0 {
		t.Fatal("an unchanged sync cleared the config authors")
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, cand.ID); !errors.Is(err, dom.ErrFourEyes) {
		t.Fatalf("BYPASS: user2 promoted content from the repository user2 configured: %v", err)
	}
}

// A review by someone else consumes the authors it covered: afterwards a
// former author may review later snapshots, and a change made after the
// reviewed snapshot's claim stays recorded.
func TestFourEyes_ReviewConsumesAuthors_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-consume", func(in *app.CreateInput) { in.Policy = "review" })
	url := "https://git.example.com/user2/rules.git"
	if _, err := e.svc.Update(ctx, e.actor(e.tenantA, e.user2), src.ID, app.UpdateInput{URL: &url}); err != nil {
		t.Fatal(err)
	}
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	s1 := e.candidate(t, src)
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, s1.ID); !errors.Is(err, dom.ErrFourEyes) {
		t.Fatalf("author promoted: %v", err)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user3), src.ID, s1.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.repo.Get(ctx, e.tenantA, src.ID); len(got.ConfigAuthors) != 0 {
		t.Fatalf("a review by another member kept the authors: %v", got.ConfigAuthors)
	}
	e.git.set(sha('b'), map[string]string{"a.yaml": rulesFile("r1", "r2")})
	src = e.runSync(t, src)
	s2 := e.candidate(t, src)
	if _, err := e.svc.SetCredential(ctx, e.actor(e.tenantA, e.user3), src.ID, "x-access-token", "ghp_"+"abcdefghijklmnopqrstuvwxyz0123456789"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, s2.ID); err != nil {
		t.Fatalf("a former author whose change was reviewed: %v", err)
	}
}

// Promoting a snapshot does not consume a change made after its claim.
func TestFourEyes_LaterChangeStaysAfterReview_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-later", func(in *app.CreateInput) { in.Policy = "review" })
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	s1 := e.candidate(t, src)
	e.clock = e.clock.Add(time.Second) // the change is after the claim
	if _, err := e.svc.SetCredential(ctx, e.actor(e.tenantA, e.user3), src.ID, "x-access-token", "ghp_"+"abcdefghijklmnopqrstuvwxyz0123456789"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Promote(ctx, e.actor(e.tenantA, e.user2), src.ID, s1.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := e.repo.Get(ctx, e.tenantA, src.ID)
	found := false
	for _, a := range got.ConfigAuthors {
		found = found || a.Equals(e.user3)
	}
	if !found {
		t.Fatalf("a change after the claim was consumed: %v", got.ConfigAuthors)
	}
}

// A switch to review made during a sync stops that sync's auto promotion.
func TestAutoPromotion_ReadsPolicyUnderLock_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	src := e.create(t, "acme-switch", nil)
	review := "review"
	e.svc.SetFetcher(func(c context.Context, req fetchers.GitRequest) (*fetchers.GitSnapshot, error) {
		if _, err := e.svc.Update(ctx, e.actor(e.tenantA, e.user1), src.ID, app.UpdateInput{Policy: &review}); err != nil {
			t.Error(err)
		}
		return e.git.fetch(c, req)
	}, nil)
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	src = e.runSync(t, src)
	if src.CurrentSnapshotID != nil {
		t.Fatal("auto promotion ran after the policy switched to review")
	}
	sn := e.candidate(t, src)
	if !sn.ReviewRequired {
		t.Fatal("the candidate is not marked for review")
	}
}

// One organization runs one Test at a time.
func TestTest_OnePerOrganization_DB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// entered is buffered: the fetcher signals without blocking, so the signal
	// must wait for the receive below that may not have started yet.
	entered, unblock := make(chan struct{}, 1), make(chan struct{})
	e.svc.SetFetcher(func(c context.Context, req fetchers.GitRequest) (*fetchers.GitSnapshot, error) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-unblock
		return e.git.fetch(c, req)
	}, nil)
	e.git.set(sha('a'), map[string]string{"a.yaml": rulesFile("r1")})
	in := app.TestInput{Kind: "semgrep-rules", URL: "https://git.example.com/acme/rules.git", Ref: "main"}
	done := make(chan error, 1)
	go func() { _, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), in); done <- err }()
	<-entered
	in2 := in
	in2.URL = "https://git.example.com/acme/other.git"
	if _, err := e.svc.Test(ctx, e.actor(e.tenantA, e.user1), in2); !errors.Is(err, dom.ErrFetchBusy) {
		t.Fatalf("second Test of the same organization: %v", err)
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
