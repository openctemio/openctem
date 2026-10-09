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
		{name: "approval disposition", dup: b, of: accepted, wantErr: vulnerability.ErrDuplicateNeedsApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.MarkDuplicateOf(ctx, f.tenant, tc.dup, tc.of, f.user.String(), tc.approve)
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
	if err := repo.MarkDuplicateOf(ctx, f.tenant, b, a, f.user.String(), false); err != nil {
		t.Fatal(err)
	}
	if s := f.state(b); s.status != "duplicate" || s.duplicateOf.String != a.String() {
		t.Fatalf("not merged: %+v", s)
	}
	if err := repo.MarkDuplicateOf(ctx, f.tenant, a, b, f.user.String(), true); !errors.Is(err, vulnerability.ErrDuplicateAlreadyMerged) {
		t.Fatalf("folding into a tombstone: %v", err)
	}
}
