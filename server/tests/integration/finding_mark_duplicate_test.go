package integration

// The repository re-checks the duplicate rules under its row locks, so a
// caller (or a race) that skips the service checks still cannot merge across
// tenants or assets, into a tombstone, or around the approval rule.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestMarkDuplicateOf_RepositoryRechecksUnderLock(t *testing.T) {
	f := newMergeFixture(t, "markdup-repo")
	other := newMergeFixture(t, "markdup-repo-other")
	ctx := context.Background()
	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	now := time.Now()
	a := f.composite(f.keep, "base-a", "new", now.Add(-time.Hour))
	b := f.composite(f.keep, "base-b", "new", now)
	away := f.composite(f.away, "base-c", "new", now)
	accepted := f.composite(f.keep, "base-d", "accepted", now)
	foreign := other.composite(other.keep, "base-a", "new", now)

	cases := []struct {
		name     string
		dup, of  shared.ID
		approve  bool
		wantErr  error
		notFound bool
	}{
		{name: "another tenant's finding", dup: b, of: foreign, approve: true, notFound: true},
		{name: "into another tenant", dup: foreign, of: a, approve: true, notFound: true},
		{name: "other asset", dup: b, of: away, approve: true, wantErr: vulnerability.ErrDuplicateOtherAsset},
		{name: "approval disposition", dup: b, of: accepted, wantErr: vulnerability.ErrDuplicateCarriesDisposition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.MarkDuplicateOf(ctx, f.tenant, tc.dup, tc.of, f.user.String())
			switch {
			case tc.notFound && !errors.Is(err, shared.ErrNotFound):
				t.Fatalf("got %v, want not found", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
	for _, id := range []shared.ID{a, b, away, accepted} {
		if s := f.state(id); s.status == "duplicate" {
			t.Fatalf("finding %s was merged: %+v", id, s)
		}
	}
	if s := other.state(foreign); s.status == "duplicate" {
		t.Fatalf("the other tenant's finding was merged: %+v", s)
	}

	// The real merge, then a second one into the tombstone is refused.
	if err := repo.MarkDuplicateOf(ctx, f.tenant, b, a, f.user.String()); err != nil {
		t.Fatal(err)
	}
	if s := f.state(b); s.status != "duplicate" || s.duplicateOf.String != a.String() {
		t.Fatalf("not merged: %+v", s)
	}
	if err := repo.MarkDuplicateOf(ctx, f.tenant, a, b, f.user.String()); !errors.Is(err, vulnerability.ErrDuplicateAlreadyMerged) {
		t.Fatalf("folding into a tombstone: %v", err)
	}
}

// Watchers follow a merged finding to the survivor; a person who already has a
// row on the survivor keeps that one, so a stop on the survivor is not undone.
func TestMarkDuplicateOf_WatchersFollowTheSurvivor(t *testing.T) {
	f := newMergeFixture(t, "markdup-watchers")
	ctx := context.Background()
	repo := postgres.NewFindingRepository(&postgres.DB{DB: f.db})
	now := time.Now()
	survivor := f.composite(f.keep, "base-a", "new", now.Add(-time.Hour))
	loser := f.composite(f.keep, "base-b", "new", now)
	mk := func(label string) shared.ID {
		u := shared.NewID()
		if _, err := f.db.Exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, u.String(), "wd-"+u.String()+"@example.test", label); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM users WHERE id = $1`, u.String()) })
		return u
	}
	only, both, stopped := mk("only on the loser"), mk("on both"), mk("stopped on the loser")
	watch := func(finding, user shared.ID, state, reason string) {
		t.Helper()
		if _, err := f.db.Exec(`INSERT INTO work_item_subscriptions (tenant_id, finding_id, user_id, state, reason) VALUES ($1, $2, $3, $4, $5)`,
			f.tenant.String(), finding.String(), user.String(), state, reason); err != nil {
			t.Fatal(err)
		}
	}
	watch(loser, only, "subscribed", "manual")
	watch(loser, both, "subscribed", "commented")
	watch(survivor, both, "unsubscribed", "manual")
	watch(loser, stopped, "unsubscribed", "manual")

	if err := repo.MarkDuplicateOf(ctx, f.tenant, loser, survivor, f.user.String()); err != nil {
		t.Fatal(err)
	}
	row := func(finding, user shared.ID) string {
		var s string
		_ = f.db.QueryRow(`SELECT state||':'||reason FROM work_item_subscriptions WHERE tenant_id = $1 AND finding_id = $2 AND user_id = $3`,
			f.tenant.String(), finding.String(), user.String()).Scan(&s)
		return s
	}
	for name, c := range map[string]struct {
		user shared.ID
		want string
	}{
		"moved":              {only, "subscribed:manual"},
		"the survivor's own": {both, "unsubscribed:manual"},
		"a stop moves too":   {stopped, "unsubscribed:manual"},
	} {
		if got := row(survivor, c.user); got != c.want {
			t.Errorf("%s: survivor row = %q, want %q", name, got, c.want)
		}
		if got := row(loser, c.user); got != "" {
			t.Errorf("%s: the tombstone still has a row %q", name, got)
		}
	}
}
