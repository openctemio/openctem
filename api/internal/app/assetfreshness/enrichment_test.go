package assetfreshness

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scan"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeRequests struct {
	pending   []shared.ID
	used      int
	claimMax  int
	requested []shared.ID
	settled   map[freshdom.Outcome][]shared.ID
	runs      map[shared.ID]shared.ID
}

func (f *fakeRequests) Request(_ context.Context, _ shared.ID, ids []shared.ID, _ freshdom.Reason, _ time.Duration) (int, error) {
	f.requested = append(f.requested, ids...)
	return len(ids), nil
}
func (f *fakeRequests) TenantsDue(context.Context, time.Duration, int) ([]shared.ID, error) {
	return []shared.ID{shared.NewID()}, nil
}
func (f *fakeRequests) DispatchedSince(context.Context, shared.ID, time.Time) (int, error) {
	return f.used, nil
}
func (f *fakeRequests) Claim(_ context.Context, _ shared.ID, limit int) ([]shared.ID, error) {
	f.claimMax = limit
	n := min(limit, len(f.pending))
	out := f.pending[:n]
	f.pending = f.pending[n:]
	return out, nil
}
func (f *fakeRequests) Settle(_ context.Context, _ shared.ID, ids []shared.ID, o freshdom.Outcome, run *shared.ID) error {
	if f.settled == nil {
		f.settled = map[freshdom.Outcome][]shared.ID{}
		f.runs = map[shared.ID]shared.ID{}
	}
	f.settled[o] = append(f.settled[o], ids...)
	if run != nil {
		for _, id := range ids {
			f.runs[id] = *run
		}
	}
	return nil
}
func (f *fakeRequests) Get(context.Context, shared.ID, shared.ID) (*freshdom.Request, error) {
	return nil, nil
}

type fakeAssets map[string]*assetdom.Asset

func (f fakeAssets) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) (map[string]*assetdom.Asset, error) {
	out := map[string]*assetdom.Asset{}
	for _, id := range ids {
		if a, ok := f[id.String()]; ok {
			out[id.String()] = a
		}
	}
	return out, nil
}

type fakeSettings struct {
	disabled bool
	err      error
}

func (f fakeSettings) GetEASMSettings(context.Context, string) (*tenant.EASMSettings, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &tenant.EASMSettings{EnrichmentDisabled: f.disabled}, nil
}

type fakeStarter struct {
	calls []scan.EnrichmentInput
	drop  map[string]bool
	err   error
}

func (f *fakeStarter) StartEnrichment(_ context.Context, in scan.EnrichmentInput) (*scan.EnrichmentResult, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	res := &scan.EnrichmentResult{}
	for _, t := range in.Targets {
		if f.drop[t] {
			res.Dropped = append(res.Dropped, t)
		} else {
			res.Kept = append(res.Kept, t)
		}
	}
	if len(res.Kept) > 0 {
		id := shared.NewID()
		res.RunID = &id
	}
	return res, nil
}

func seed(t *testing.T, as fakeAssets, name string, typ assetdom.AssetType) shared.ID {
	t.Helper()
	a := mustAsset(t, name, typ)
	as[a.ID().String()] = a
	return a.ID()
}

func TestEnricher_GroupsByProfileAndSettles(t *testing.T) {
	as := fakeAssets{}
	dom := seed(t, as, "example.com", assetdom.AssetTypeDomain)
	sub := seed(t, as, "a.example.com", assetdom.AssetTypeSubdomain)
	out := seed(t, as, "b.example.net", assetdom.AssetTypeSubdomain)
	ip := seed(t, as, "192.0.2.1", assetdom.AssetTypeIPAddress)
	repo := seed(t, as, "github.com/acme/x", assetdom.AssetTypeRepository)
	gone := shared.NewID()
	reqs := &fakeRequests{pending: []shared.ID{dom, sub, out, ip, repo, gone}}
	st := &fakeStarter{drop: map[string]bool{"b.example.net": true}}
	e := NewEnricher(reqs, as, fakeSettings{}, st, EnricherConfig{}, logger.NewNop())

	if n, err := e.Run(context.Background()); err != nil || n != 6 {
		t.Fatalf("run = %d %v", n, err)
	}
	if len(st.calls) != 3 {
		t.Fatalf("runs started = %d, want one per profile", len(st.calls))
	}
	for _, c := range st.calls {
		p, _ := freshdom.ProfileFor(as[firstID(t, as, c.Targets[0])].Type())
		if c.WorkflowID != p.WorkflowID {
			t.Fatalf("targets %v went to workflow %s", c.Targets, c.WorkflowID)
		}
	}
	if got := reqs.settled[freshdom.OutcomeDispatched]; len(got) != 3 {
		t.Fatalf("dispatched = %v", got)
	}
	if got := reqs.settled[freshdom.OutcomeRefused]; len(got) != 1 || got[0] != out {
		t.Fatalf("refused = %v", got)
	}
	if got := reqs.settled[freshdom.OutcomeNoProfile]; len(got) != 2 {
		t.Fatalf("no profile = %v (repository and missing asset)", got)
	}
	if _, ok := reqs.runs[sub]; !ok {
		t.Fatal("dispatched request has no run")
	}
}

func firstID(t *testing.T, as fakeAssets, name string) string {
	t.Helper()
	for id, a := range as {
		if a.Name() == name {
			return id
		}
	}
	t.Fatalf("no asset %s", name)
	return ""
}

func TestEnricher_BudgetCapsTheClaim(t *testing.T) {
	as := fakeAssets{}
	ids := []shared.ID{seed(t, as, "a.example.com", assetdom.AssetTypeSubdomain), seed(t, as, "b.example.com", assetdom.AssetTypeSubdomain)}
	reqs := &fakeRequests{pending: ids, used: 99}
	st := &fakeStarter{}
	e := NewEnricher(reqs, as, fakeSettings{}, st, EnricherConfig{DailyBudget: 100}, logger.NewNop())
	if _, err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reqs.claimMax != 1 || len(st.calls) != 1 || len(st.calls[0].Targets) != 1 {
		t.Fatalf("claim limit %d, calls %+v", reqs.claimMax, st.calls)
	}

	// Budget spent: nothing claimed, nothing started.
	reqs.used, st.calls = 100, nil
	if _, err := e.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.calls) != 0 || len(reqs.pending) != 1 {
		t.Fatalf("over budget: calls %d pending %d", len(st.calls), len(reqs.pending))
	}
}

func TestEnricher_SettingsUnreadableOrStartFails(t *testing.T) {
	as := fakeAssets{}
	id := seed(t, as, "a.example.com", assetdom.AssetTypeSubdomain)

	// Settings unreadable: fail closed, nothing claimed.
	reqs := &fakeRequests{pending: []shared.ID{id}}
	st := &fakeStarter{}
	e := NewEnricher(reqs, as, fakeSettings{err: errors.New("db down")}, st, EnricherConfig{}, logger.NewNop())
	_, _ = e.Run(context.Background())
	if len(reqs.pending) != 1 || len(st.calls) != 0 {
		t.Fatalf("claimed without settings: pending %d calls %d", len(reqs.pending), len(st.calls))
	}

	// The run cannot start: the requests are settled failed.
	st = &fakeStarter{err: errors.New("no tool")}
	e = NewEnricher(reqs, as, fakeSettings{}, st, EnricherConfig{}, logger.NewNop())
	_, _ = e.Run(context.Background())
	if got := reqs.settled[freshdom.OutcomeFailed]; len(got) != 1 || got[0] != id {
		t.Fatalf("failed = %v", got)
	}
}

func TestEnricher_RequestAssetsOnlyProfiledTypes(t *testing.T) {
	reqs := &fakeRequests{}
	e := NewEnricher(reqs, fakeAssets{}, fakeSettings{}, &fakeStarter{}, EnricherConfig{}, logger.NewNop())
	sub := mustAsset(t, "a.example.com", assetdom.AssetTypeSubdomain)
	repo := mustAsset(t, "github.com/acme/x", assetdom.AssetTypeRepository)
	e.RequestAssets(context.Background(), shared.NewID(), []*assetdom.Asset{sub, repo, nil}, freshdom.ReasonNewAsset)
	if len(reqs.requested) != 1 || reqs.requested[0] != sub.ID() {
		t.Fatalf("requested %v", reqs.requested)
	}
}
