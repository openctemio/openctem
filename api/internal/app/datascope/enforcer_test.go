package datascope

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeRepo struct {
	rows     map[shared.ID]map[shared.ID]bool // user -> asset -> in scope
	findings map[shared.ID]shared.ID          // finding -> asset
	err      error
}

func (f *fakeRepo) HasAnyScopeAssignment(_ context.Context, _, userID shared.ID) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return len(f.rows[userID]) > 0, nil
}

func (f *fakeRepo) AssetIDsInScope(_ context.Context, _, userID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []shared.ID
	for _, id := range ids {
		if f.rows[userID][id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakeRepo) FindingAssetID(_ context.Context, _, findingID shared.ID) (shared.ID, error) {
	a, ok := f.findings[findingID]
	if !ok {
		return shared.ID{}, shared.ErrNotFound
	}
	return a, nil
}

func (f *fakeRepo) FindingIDsInScope(_ context.Context, _, userID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	var out []shared.ID
	for _, id := range ids {
		if f.rows[userID][f.findings[id]] {
			out = append(out, id)
		}
	}
	return out, nil
}

type policy bool

func (p policy) RestrictedDataScope(context.Context, string) bool { return bool(p) }

type callerKey struct{}

func withCaller(c Caller) context.Context {
	return context.WithValue(context.Background(), callerKey{}, c)
}

func ctxCaller(ctx context.Context) Caller {
	c, _ := ctx.Value(callerKey{}).(Caller)
	return c
}

func TestEnforcer(t *testing.T) {
	tenant := shared.NewID()
	scoped, free := shared.NewID(), shared.NewID()
	assetA, assetB := shared.NewID(), shared.NewID()
	findingA, findingB := shared.NewID(), shared.NewID()
	repo := &fakeRepo{
		rows:     map[shared.ID]map[shared.ID]bool{scoped: {assetA: true}},
		findings: map[shared.ID]shared.ID{findingA: assetA, findingB: assetB},
	}

	cases := []struct {
		name    string
		strict  bool
		caller  Caller
		asset   shared.ID
		finding shared.ID
		wantErr bool
	}{
		{"admin sees out-of-scope", false, Caller{UserID: scoped.String(), IsAdmin: true}, assetB, findingB, false},
		{"internal call (no user) unrestricted", false, Caller{}, assetB, findingB, false},
		{"scoped member in scope", false, Caller{UserID: scoped.String()}, assetA, findingA, false},
		{"scoped member out of scope", false, Caller{UserID: scoped.String()}, assetB, findingB, true},
		{"member without group, fail-open", false, Caller{UserID: free.String()}, assetB, findingB, false},
		{"member without group, fail-closed tenant", true, Caller{UserID: free.String()}, assetA, findingA, true},
		{"admin in fail-closed tenant", true, Caller{UserID: free.String(), IsAdmin: true}, assetA, findingA, false},
		{"unparseable user fails closed", false, Caller{UserID: "not-a-uuid"}, assetA, findingA, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(repo, policy(tc.strict), ctxCaller, nil)
			ctx := withCaller(tc.caller)
			if err := e.AssertAsset(ctx, tenant, tc.asset); (err != nil) != tc.wantErr {
				t.Errorf("AssertAsset err=%v, wantErr=%v", err, tc.wantErr)
			} else if err != nil && !errors.Is(err, shared.ErrNotFound) {
				t.Errorf("AssertAsset must deny with ErrNotFound, got %v", err)
			}
			if err := e.AssertFinding(ctx, tenant, tc.finding); (err != nil) != tc.wantErr {
				t.Errorf("AssertFinding err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestEnforcer_NilAndErrors(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	var nilEnforcer *Enforcer
	ctx := withCaller(Caller{UserID: user.String()})
	if err := nilEnforcer.AssertAsset(ctx, tenant, shared.NewID()); err != nil {
		t.Errorf("nil enforcer must not restrict: %v", err)
	}
	if s, err := nilEnforcer.Resolve(ctx, tenant); s != nil || err != nil {
		t.Errorf("nil enforcer Resolve = %v, %v", s, err)
	}

	broken := New(&fakeRepo{err: errors.New("db down")}, nil, ctxCaller, nil)
	if err := broken.AssertAsset(ctx, tenant, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a failing scope lookup must deny (fail closed), got %v", err)
	}
	if _, err := broken.Resolve(ctx, tenant); err == nil {
		t.Error("Resolve must surface a lookup error so lists fail instead of leaking")
	}

	// Unknown finding: not found, never "allowed".
	e := New(&fakeRepo{rows: map[shared.ID]map[shared.ID]bool{user: {shared.NewID(): true}}}, nil, ctxCaller, nil)
	if err := e.AssertFinding(ctx, tenant, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("unknown finding = %v, want ErrNotFound", err)
	}
}

func TestEnforcer_Filters(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	in, out := shared.NewID(), shared.NewID()
	fIn, fOut := shared.NewID(), shared.NewID()
	repo := &fakeRepo{
		rows:     map[shared.ID]map[shared.ID]bool{user: {in: true}},
		findings: map[shared.ID]shared.ID{fIn: in, fOut: out},
	}
	e := New(repo, nil, ctxCaller, nil)
	ctx := withCaller(Caller{UserID: user.String()})

	keep, err := e.FilterForCaller(ctx, tenant, []shared.ID{in, out, in})
	if err != nil || !keep(in) || keep(out) {
		t.Errorf("FilterForCaller: in=%v out=%v err=%v", keep(in), keep(out), err)
	}
	scope, _ := e.Resolve(ctx, tenant)
	keepF, err := e.FilterFindings(ctx, scope, []shared.ID{fIn, fOut})
	if err != nil || !keepF(fIn) || keepF(fOut) {
		t.Errorf("FilterFindings: in=%v out=%v err=%v", keepF(fIn), keepF(fOut), err)
	}
	all, _ := e.Filter(ctx, nil, nil)
	if !all(out) {
		t.Error("a nil scope must admit everything")
	}
}

func TestEnforcer_ForUserUsesAdminLookup(t *testing.T) {
	tenant, user := shared.NewID(), shared.NewID()
	asset := shared.NewID()
	finding := shared.NewID()
	repo := &fakeRepo{
		rows:     map[shared.ID]map[shared.ID]bool{user: {shared.NewID(): true}},
		findings: map[shared.ID]shared.ID{finding: asset},
	}
	e := New(repo, nil, nil, nil)
	if err := e.AssertFindingForUser(context.Background(), tenant, user, finding); err == nil {
		t.Error("restricted user without admin lookup must be denied")
	}
	e.SetAdminLookup(func(context.Context, shared.ID, shared.ID) (bool, error) { return true, nil })
	if err := e.AssertFindingForUser(context.Background(), tenant, user, finding); err != nil {
		t.Errorf("admin must be allowed: %v", err)
	}
	e.SetAdminLookup(func(context.Context, shared.ID, shared.ID) (bool, error) { return false, errors.New("x") })
	if err := e.AssertFindingForUser(context.Background(), tenant, user, finding); err == nil {
		t.Error("admin lookup error must deny")
	}
}

// CanActOnAssets: the request caller acts; with no user in the context the
// fallback user (a scheduled scan owner) acts; with neither the system acts,
// unrestricted. A lookup error is returned (the caller refuses).
func TestEnforcer_CanActOnAssets(t *testing.T) {
	tenant := shared.NewID()
	scoped, admin := shared.NewID(), shared.NewID()
	assetA, assetB := shared.NewID(), shared.NewID()
	repo := &fakeRepo{rows: map[shared.ID]map[shared.ID]bool{scoped: {assetA: true}}}
	e := New(repo, policy(false), ctxCaller, nil)
	e.SetAdminLookup(func(_ context.Context, _, user shared.ID) (bool, error) { return user == admin, nil })
	ids := []shared.ID{assetA, assetB}

	type want struct{ a, b, unrestricted bool }
	cases := []struct {
		name     string
		ctx      context.Context
		fallback *shared.ID
		want     want
	}{
		{"restricted caller", withCaller(Caller{UserID: scoped.String()}), nil, want{true, false, false}},
		{"admin caller", withCaller(Caller{UserID: admin.String(), IsAdmin: true}), &scoped, want{true, true, true}},
		{"no caller, restricted owner", context.Background(), &scoped, want{true, false, false}},
		{"no caller, admin owner", context.Background(), &admin, want{true, true, true}},
		{"system", context.Background(), nil, want{true, true, true}},
		// The caller wins over the owner: a restricted member triggering an
		// admin scan acts with their own scope.
		{"restricted caller, admin owner", withCaller(Caller{UserID: scoped.String()}), &admin, want{true, false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			can, unrestricted, err := e.CanActOnAssets(tc.ctx, tenant, tc.fallback, ids)
			if err != nil {
				t.Fatal(err)
			}
			if got := (want{can(assetA), can(assetB), unrestricted}); got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}

	failing := New(&fakeRepo{err: errors.New("db down")}, policy(false), ctxCaller, nil)
	if _, _, err := failing.CanActOnAssets(withCaller(Caller{UserID: scoped.String()}), tenant, nil, ids); err == nil {
		t.Fatal("a failed scope lookup must be returned")
	}
}
