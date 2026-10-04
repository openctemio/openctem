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
	tenant   map[shared.ID]shared.ID          // asset -> tenant (live assets)
	fullData map[shared.ID]bool               // user -> holds a full-data role
	err      error
}

func (f *fakeRepo) HasFullDataRole(_ context.Context, _, userID shared.ID) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.fullData[userID], nil
}

func (f *fakeRepo) AssetIDsInTenant(_ context.Context, tenantID shared.ID, ids []shared.ID) ([]shared.ID, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []shared.ID
	for _, id := range ids {
		if t, ok := f.tenant[id]; ok && t == tenantID {
			out = append(out, id)
		}
	}
	return out, nil
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
		caller  Caller
		asset   shared.ID
		finding shared.ID
		wantErr bool
	}{
		{"admin sees out-of-scope", Caller{UserID: scoped.String(), IsAdmin: true}, assetB, findingB, false},
		{"internal call (no user) unrestricted", Caller{}, assetB, findingB, false},
		{"scoped member in scope", Caller{UserID: scoped.String()}, assetA, findingA, false},
		{"scoped member out of scope", Caller{UserID: scoped.String()}, assetB, findingB, true},
		// No scope row means nothing, in every organization: there is no
		// "see everything" mode (owner decision D2, research doc 15 L-04).
		{"member without scope row sees nothing", Caller{UserID: free.String()}, assetA, findingA, true},
		{"member without scope row, other asset", Caller{UserID: free.String()}, assetB, findingB, true},
		{"admin without scope row", Caller{UserID: free.String(), IsAdmin: true}, assetA, findingA, false},
		{"unparseable user fails closed", Caller{UserID: "not-a-uuid"}, assetA, findingA, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(repo, ctxCaller, nil)
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

	broken := New(&fakeRepo{err: errors.New("db down")}, ctxCaller, nil)
	if err := broken.AssertAsset(ctx, tenant, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a failing scope lookup must deny (fail closed), got %v", err)
	}
	if _, err := broken.Resolve(ctx, tenant); err == nil {
		t.Error("Resolve must surface a lookup error so lists fail instead of leaking")
	}

	// Unknown finding: not found, never "allowed".
	e := New(&fakeRepo{rows: map[shared.ID]map[shared.ID]bool{user: {shared.NewID(): true}}}, ctxCaller, nil)
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
	e := New(repo, ctxCaller, nil)
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
	e := New(repo, nil, nil)
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
	scoped, admin, scopeless := shared.NewID(), shared.NewID(), shared.NewID()
	assetA, assetB := shared.NewID(), shared.NewID()
	repo := &fakeRepo{rows: map[shared.ID]map[shared.ID]bool{scoped: {assetA: true}}}
	e := New(repo, ctxCaller, nil)
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
		// A member with no scope row acts on nothing, never on everything.
		{"scopeless caller", withCaller(Caller{UserID: shared.NewID().String()}), nil, want{false, false, false}},
		{"no caller, scopeless owner", context.Background(), &scopeless, want{false, false, false}},
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

	failing := New(&fakeRepo{err: errors.New("db down")}, ctxCaller, nil)
	if _, _, err := failing.CanActOnAssets(withCaller(Caller{UserID: scoped.String()}), tenant, nil, ids); err == nil {
		t.Fatal("a failed scope lookup must be returned")
	}
}

func TestEnforcer_AssertAssetRef(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	scoped := shared.NewID()
	inScope, outScope, foreign := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &fakeRepo{
		rows:   map[shared.ID]map[shared.ID]bool{scoped: {inScope: true, foreign: true}},
		tenant: map[shared.ID]shared.ID{inScope: tenant, outScope: tenant, foreign: other},
	}
	admin := Caller{UserID: shared.NewID().String(), IsAdmin: true}
	member := Caller{UserID: scoped.String()}
	cases := []struct {
		name    string
		caller  Caller
		asset   shared.ID
		wantErr bool
	}{
		{"admin, own tenant", admin, outScope, false},
		{"admin, foreign tenant", admin, foreign, true},
		{"admin, unknown id", admin, shared.NewID(), true},
		{"internal call, foreign tenant", Caller{}, foreign, true},
		{"member, in scope", member, inScope, false},
		{"member, out of scope", member, outScope, true},
		// A scope row pointing at another tenant's asset does not help.
		{"member, foreign asset with a stray scope row", member, foreign, true},
		{"zero id", admin, shared.ID{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(repo, ctxCaller, nil)
			err := e.AssertAssetRef(withCaller(tc.caller), tenant, tc.asset)
			if (err != nil) != tc.wantErr {
				t.Fatalf("AssertAssetRef err=%v, wantErr=%v", err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, shared.ErrNotFound) {
				t.Errorf("AssertAssetRef must deny with ErrNotFound, got %v", err)
			}
		})
	}

	var nilEnforcer *Enforcer
	if err := nilEnforcer.AssertAssetRef(withCaller(admin), tenant, inScope); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("nil enforcer must fail closed for an asset reference, got %v", err)
	}
	repo.err = errors.New("db down")
	if err := New(repo, ctxCaller, nil).AssertAssetRef(withCaller(admin), tenant, inScope); !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("a lookup error must fail closed, got %v", err)
	}
}

// FilterAssetRefs is the batch AssertAssetRef: same answers per id.
func TestEnforcer_FilterAssetRefs(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	scoped := shared.NewID()
	inScope, outScope, foreign, unknown := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	repo := &fakeRepo{
		rows:   map[shared.ID]map[shared.ID]bool{scoped: {inScope: true, foreign: true}},
		tenant: map[shared.ID]shared.ID{inScope: tenant, outScope: tenant, foreign: other},
	}
	all := []shared.ID{inScope, outScope, foreign, unknown, {}}
	cases := []struct {
		name   string
		caller Caller
		admit  []shared.ID
	}{
		{"admin", Caller{UserID: shared.NewID().String(), IsAdmin: true}, []shared.ID{inScope, outScope}},
		{"internal call", Caller{}, []shared.ID{inScope, outScope}},
		{"scoped member", Caller{UserID: scoped.String()}, []shared.ID{inScope}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(repo, ctxCaller, nil)
			admit, err := e.FilterAssetRefs(withCaller(tc.caller), tenant, all)
			if err != nil {
				t.Fatal(err)
			}
			want := map[shared.ID]bool{}
			for _, id := range tc.admit {
				want[id] = true
			}
			for _, id := range all {
				if admit(id) != want[id] {
					t.Errorf("admit(%s) = %v, want %v", id, admit(id), want[id])
				}
			}
		})
	}

	var nilEnforcer *Enforcer
	if admit, err := nilEnforcer.FilterAssetRefs(context.Background(), tenant, all); err != nil || admit(inScope) {
		t.Errorf("nil enforcer must admit nothing (err=%v)", err)
	}
	repo.err = errors.New("db down")
	if _, err := New(repo, ctxCaller, nil).FilterAssetRefs(context.Background(), tenant, all); err == nil {
		t.Error("a lookup error must be returned")
	}
}

// A has_full_data_access role is the Layer 2 bypass (owner decision D3),
// except through an API key; a lookup error restricts.
func TestEnforcer_FullDataRole(t *testing.T) {
	tenant := shared.NewID()
	reader, member := shared.NewID(), shared.NewID()
	asset := shared.NewID()
	repo := &fakeRepo{
		rows:     map[shared.ID]map[shared.ID]bool{reader: {}, member: {shared.NewID(): true}},
		fullData: map[shared.ID]bool{reader: true},
	}
	cases := []struct {
		name       string
		caller     Caller
		wantScoped bool
	}{
		{"full-data role without scope rows", Caller{UserID: reader.String()}, false},
		{"full-data role through an API key", Caller{UserID: reader.String(), APIKey: true}, true},
		{"member without the role", Caller{UserID: member.String()}, true},
		{"member without the role or scope rows", Caller{UserID: shared.NewID().String()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(repo, ctxCaller, nil)
			scope, err := e.ResolveFor(context.Background(), tenant, tc.caller)
			if err != nil {
				t.Fatal(err)
			}
			if (scope != nil) != tc.wantScoped {
				t.Fatalf("scope = %v, want scoped=%v", scope, tc.wantScoped)
			}
			full, err := e.FullData(withCaller(tc.caller), tenant, tc.caller.UserID)
			if err != nil {
				t.Fatal(err)
			}
			if full == tc.wantScoped {
				t.Errorf("FullData = %v, want %v", full, !tc.wantScoped)
			}
			if !tc.wantScoped {
				if err := e.AssertAsset(withCaller(tc.caller), tenant, asset); err != nil {
					t.Errorf("full-data caller refused an asset: %v", err)
				}
			}
		})
	}
	repo.err = errors.New("db down")
	if _, err := New(repo, ctxCaller, nil).ResolveFor(context.Background(), tenant, Caller{UserID: reader.String()}); err == nil {
		t.Error("a failed full-data lookup must not resolve to unrestricted")
	}
}
