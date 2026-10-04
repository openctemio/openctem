package easm

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeReviewStore struct {
	query     ReviewQuery
	scopeUser *shared.ID
	saved     []string
	prev      map[string]attribution.State
}

func (f *fakeReviewStore) ListForReview(_ context.Context, _ shared.ID, scopeUserID *shared.ID, q ReviewQuery) (*ReviewPage, error) {
	f.query, f.scopeUser = q, scopeUserID
	return &ReviewPage{Items: []ReviewItem{}}, nil
}

func (f *fakeReviewStore) SaveDecisions(_ context.Context, _ shared.ID, ids []string, _ attribution.State, _ string) (map[string]attribution.State, error) {
	f.saved = append(f.saved, ids...)
	out := map[string]attribution.State{}
	for _, id := range ids {
		if p, ok := f.prev[id]; ok {
			out[id] = p
		}
	}
	return out, nil
}

// scopeRepo is a data-scope repository: the member has scope rows for the
// assets in `in`; err makes every lookup fail.
type scopeRepo struct {
	in  map[shared.ID]bool
	err error
}

func (r *scopeRepo) HasAnyScopeAssignment(context.Context, shared.ID, shared.ID) (bool, error) {
	return true, r.err
}

func (r *scopeRepo) AssetIDsInScope(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if r.err != nil {
		return nil, r.err
	}
	var out []shared.ID
	for _, id := range ids {
		if r.in[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (r *scopeRepo) FindingAssetID(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return shared.ID{}, shared.ErrNotFound
}

func (r *scopeRepo) FindingIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

func memberEnforcer(repo datascope.Repository, user shared.ID) *datascope.Enforcer {
	return datascope.New(repo, nil, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: user.String()}
	}, nil)
}

func TestQueue_DefaultsAndScope(t *testing.T) {
	store := &fakeReviewStore{}
	user := shared.NewID()
	svc := NewReviewService(store, memberEnforcer(&scopeRepo{}, user))
	if _, err := svc.Queue(context.Background(), shared.NewID(), ReviewQuery{Limit: 5000}); err != nil {
		t.Fatal(err)
	}
	if len(store.query.States) != 2 || store.query.States[0] != attribution.StateNeedsReview || store.query.States[1] != attribution.StateCandidate {
		t.Errorf("default states = %v", store.query.States)
	}
	if store.query.Limit != 50 {
		t.Errorf("limit not clamped: %d", store.query.Limit)
	}
	if store.scopeUser == nil || *store.scopeUser != user {
		t.Fatal("a scoped member's queue must be narrowed to the member's data scope")
	}
	if _, err := svc.Queue(context.Background(), shared.NewID(), ReviewQuery{States: []attribution.State{"bogus"}}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bogus state: %v", err)
	}
}

// A data-scope failure denies the queue instead of showing everything.
func TestQueue_ScopeErrorFailsClosed(t *testing.T) {
	store := &fakeReviewStore{}
	svc := NewReviewService(store, memberEnforcer(&scopeRepo{err: errors.New("db down")}, shared.NewID()))
	if _, err := svc.Queue(context.Background(), shared.NewID(), ReviewQuery{}); err == nil {
		t.Fatal("scope error must fail the request")
	}
	if store.query.States != nil {
		t.Fatal("store reached despite scope error")
	}
}

// A member may decide only on assets in its data scope; the rest are
// reported not found and never reach the store. Assets the store did not
// write (another tenant's, deleted) are not found too.
func TestDecide_DataScopeAndNotFound(t *testing.T) {
	inScope, outOfScope, foreign := shared.NewID(), shared.NewID(), shared.NewID()
	store := &fakeReviewStore{prev: map[string]attribution.State{inScope.String(): attribution.StateNeedsReview}}
	repo := &scopeRepo{in: map[shared.ID]bool{inScope: true, foreign: true}}
	svc := NewReviewService(store, memberEnforcer(repo, shared.NewID()))

	res, err := svc.Decide(context.Background(), shared.NewID(),
		[]string{inScope.String(), outOfScope.String(), foreign.String(), inScope.String()},
		attribution.StateConfirmed, shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range store.saved {
		if id == outOfScope.String() {
			t.Fatal("an out-of-scope asset reached the store")
		}
	}
	if len(store.saved) != 2 {
		t.Errorf("duplicates not removed: saved %v", store.saved)
	}
	if len(res.Decided) != 1 || res.Decided[0].AssetID != inScope.String() ||
		res.Decided[0].From != "needs_review" || res.Decided[0].To != "confirmed" {
		t.Errorf("decided = %+v", res.Decided)
	}
	if len(res.NotFound) != 2 {
		t.Errorf("not found = %v", res.NotFound)
	}
}

func TestDecide_FailsClosedAndValidates(t *testing.T) {
	store := &fakeReviewStore{}
	svc := NewReviewService(store, memberEnforcer(&scopeRepo{err: errors.New("db down")}, shared.NewID()))
	if _, err := svc.Decide(context.Background(), shared.NewID(), []string{shared.NewID().String()}, attribution.StateRejected, ""); err == nil {
		t.Fatal("scope error must fail the decision")
	}
	if len(store.saved) != 0 {
		t.Fatal("store reached despite scope error")
	}

	open := NewReviewService(store, nil)
	tenant := shared.NewID()
	for name, tc := range map[string]struct {
		ids   []string
		state attribution.State
	}{
		"automatic-only state": {[]string{shared.NewID().String()}, attribution.StateCandidate},
		"unknown state":        {[]string{shared.NewID().String()}, "owned"},
		"no assets":            {nil, attribution.StateConfirmed},
		"bad id":               {[]string{"not-a-uuid"}, attribution.StateConfirmed},
		"too many":             {make([]string, MaxDecisionBatch+1), attribution.StateConfirmed},
	} {
		if _, err := open.Decide(context.Background(), tenant, tc.ids, tc.state, ""); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want validation", name, err)
		}
	}
}

// Without a scope (admin or unwired), the legacy previous state ("") is
// reported as confirmed, matching GET /assets/{id}/attribution.
func TestDecide_LegacyFromIsConfirmed(t *testing.T) {
	id := shared.NewID()
	store := &fakeReviewStore{prev: map[string]attribution.State{id.String(): ""}}
	res, err := NewReviewService(store, nil).Decide(context.Background(), shared.NewID(), []string{id.String()}, attribution.StateRejected, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Decided) != 1 || res.Decided[0].From != "confirmed" {
		t.Fatalf("decided = %+v", res.Decided)
	}
}
