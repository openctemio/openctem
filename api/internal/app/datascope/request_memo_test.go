package datascope

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// countingRepo counts the queries the enforcer makes.
type countingRepo struct {
	*fakeRepo
	n atomic.Int64
}

func (c *countingRepo) HasHiddenAssets(ctx context.Context, t, u shared.ID) (bool, error) {
	c.n.Add(1)
	return c.fakeRepo.HasHiddenAssets(ctx, t, u)
}

func (c *countingRepo) HasFullDataRole(ctx context.Context, t, u shared.ID) (bool, error) {
	c.n.Add(1)
	return c.fakeRepo.HasFullDataRole(ctx, t, u)
}

func (c *countingRepo) AssetIDsInScope(ctx context.Context, t, u shared.ID, ids []shared.ID) ([]shared.ID, error) {
	c.n.Add(1)
	return c.fakeRepo.AssetIDsInScope(ctx, t, u, ids)
}

func (c *countingRepo) AssetIDsVisible(ctx context.Context, t, u shared.ID, ids []shared.ID) ([]shared.ID, error) {
	c.n.Add(1)
	return c.fakeRepo.AssetIDsVisible(ctx, t, u, ids)
}

func (c *countingRepo) FindingIDsInScope(ctx context.Context, t, u shared.ID, ids []shared.ID) ([]shared.ID, error) {
	c.n.Add(1)
	return c.fakeRepo.FindingIDsInScope(ctx, t, u, ids)
}

func (c *countingRepo) FindingAssetID(ctx context.Context, t, f shared.ID) (shared.ID, error) {
	c.n.Add(1)
	return c.fakeRepo.FindingAssetID(ctx, t, f)
}

// memoFixture: a member scoped to assetA (findingA), a full-data member, and
// an admin who has a hidden asset (so their scope is Unrestricted, not nil).
type memoFixture struct {
	tenant, member, other, admin shared.ID
	assetA, assetB               shared.ID
	findingA, findingB           shared.ID
	repo                         *countingRepo
	e                            *Enforcer
}

func newMemoFixture() *memoFixture {
	f := &memoFixture{
		tenant: shared.NewID(), member: shared.NewID(), other: shared.NewID(), admin: shared.NewID(),
		assetA: shared.NewID(), assetB: shared.NewID(), findingA: shared.NewID(), findingB: shared.NewID(),
	}
	f.repo = &countingRepo{fakeRepo: &fakeRepo{
		rows:     map[shared.ID]map[shared.ID]bool{f.member: {f.assetA: true}, f.other: {f.assetB: true}},
		findings: map[shared.ID]shared.ID{f.findingA: f.assetA, f.findingB: f.assetB},
		hidden:   map[shared.ID]map[shared.ID]bool{f.admin: {shared.NewID(): true}},
	}}
	f.e = New(f.repo, ctxCaller, nil)
	return f
}

// requestSequence is what one finding sub-request does today: the route
// guard checks the finding, then the service resolves the caller's scope and
// checks the finding's asset (GetFindingWithScope), then checks the finding
// again (a comment or checklist path).
func (f *memoFixture) requestSequence(t *testing.T, ctx context.Context) {
	t.Helper()
	if err := f.e.AssertFinding(ctx, f.tenant, f.findingA); err != nil {
		t.Fatalf("guard check: %v", err)
	}
	scope, err := f.e.Resolve(ctx, f.tenant)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if ok, err := f.e.InScope(ctx, scope, f.assetA); err != nil || !ok {
		t.Fatalf("in scope = %v, %v", ok, err)
	}
	if err := f.e.AssertFinding(ctx, f.tenant, f.findingA); err != nil {
		t.Fatalf("service check: %v", err)
	}
}

func TestRequestMemo_QueriesPerRequest(t *testing.T) {
	for _, tc := range []struct {
		name          string
		caller        func(f *memoFixture) Caller
		before, after int64
	}{
		{"member", func(f *memoFixture) Caller { return Caller{UserID: f.member.String()} }, 6, 3},
		{"admin with hidden assets", func(f *memoFixture) Caller { return Caller{UserID: f.admin.String(), IsAdmin: true} }, 8, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMemoFixture()
			ctx := withCaller(tc.caller(f))
			f.requestSequence(t, ctx)
			if got := f.repo.n.Load(); got != tc.before {
				t.Fatalf("without memo: %d queries, want %d", got, tc.before)
			}
			f.repo.n.Store(0)
			f.requestSequence(t, WithRequestMemo(ctx))
			if got := f.repo.n.Load(); got != tc.after {
				t.Fatalf("with memo: %d queries, want %d", got, tc.after)
			}
			t.Logf("%s: %d queries per request before, %d after", tc.name, tc.before, tc.after)
		})
	}
}

func TestRequestMemo_NeverCrossesCallerOrTenant(t *testing.T) {
	f := newMemoFixture()
	memo := WithRequestMemo(context.Background())
	asMember := context.WithValue(memo, callerKey{}, Caller{UserID: f.member.String()})
	asOther := context.WithValue(memo, callerKey{}, Caller{UserID: f.other.String()})

	if err := f.e.AssertFinding(asMember, f.tenant, f.findingA); err != nil {
		t.Fatalf("member on own finding: %v", err)
	}
	// Same memo, another caller: the member's "allowed" must not leak.
	if err := f.e.AssertFinding(asOther, f.tenant, f.findingA); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other caller got the member's verdict: %v", err)
	}
	if err := f.e.AssertAsset(asOther, f.tenant, f.assetA); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other caller on member's asset: %v", err)
	}
	// Same caller, another tenant: answered afresh, never from the memo.
	otherTenant := shared.NewID()
	before := f.repo.n.Load()
	if _, err := f.e.Resolve(asMember, otherTenant); err != nil {
		t.Fatalf("resolve other tenant: %v", err)
	}
	if f.repo.n.Load() == before {
		t.Fatal("other tenant's scope came from the memo")
	}
	// An admin flag is part of the key: the same user as admin is a new question.
	asMemberAdmin := context.WithValue(memo, callerKey{}, Caller{UserID: f.member.String(), IsAdmin: true})
	before = f.repo.n.Load()
	if _, err := f.e.Resolve(asMemberAdmin, f.tenant); err != nil {
		t.Fatalf("resolve as admin: %v", err)
	}
	if f.repo.n.Load() == before {
		t.Fatal("admin caller reused the member's scope")
	}
}

func TestRequestMemo_RefusalsAndErrorsAreNotKept(t *testing.T) {
	f := newMemoFixture()
	ctx := WithRequestMemo(withCaller(Caller{UserID: f.member.String()}))
	if err := f.e.AssertFinding(ctx, f.tenant, f.findingB); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("out-of-scope finding: %v", err)
	}
	// The member is granted assetB within the request: the refusal was not
	// remembered, so the next check sees the new row.
	f.repo.rows[f.member][f.assetB] = true
	if err := f.e.AssertFinding(ctx, f.tenant, f.findingB); err != nil {
		t.Fatalf("refusal was memoized: %v", err)
	}

	// A lookup error is not remembered either (fail closed, then asked again).
	g := newMemoFixture()
	g.repo.err = errors.New("db down")
	gctx := WithRequestMemo(withCaller(Caller{UserID: g.member.String()}))
	if _, err := g.e.Resolve(gctx, g.tenant); err == nil {
		t.Fatal("want the lookup error")
	}
	g.repo.err = nil
	if s, err := g.e.Resolve(gctx, g.tenant); err != nil || s == nil || s.UserID != g.member {
		t.Fatalf("resolve after error = %+v, %v", s, err)
	}
}

func TestRequestMemo_ScopeCopiesAndExpiry(t *testing.T) {
	f := newMemoFixture()
	ctx := WithRequestMemo(withCaller(Caller{UserID: f.member.String()}))
	s1, err := f.e.Resolve(ctx, f.tenant)
	if err != nil || s1 == nil {
		t.Fatalf("resolve: %+v, %v", s1, err)
	}
	s1.Unrestricted = true // a caller scribbling on its copy
	s2, _ := f.e.Resolve(ctx, f.tenant)
	if s2.Unrestricted {
		t.Fatal("a caller's change reached the memo")
	}

	// A context that outlives its request stops using the memo.
	m := memoOf(ctx)
	m.created = time.Now().Add(-2 * memoMaxAge)
	before := f.repo.n.Load()
	if _, err := f.e.Resolve(ctx, f.tenant); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if f.repo.n.Load() == before {
		t.Fatal("expired memo still answered")
	}
	// Installing again on a context that has one keeps it.
	if memoOf(WithRequestMemo(withCaller(Caller{}))) == nil {
		t.Fatal("fresh memo missing")
	}
	inner := WithRequestMemo(ctx)
	if inner != ctx {
		t.Fatal("nested install replaced the request's memo")
	}
}
