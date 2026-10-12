package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// assetGate is a stubGate that also names the tenant's assets (the dry
// run's asset_ids): only the ids in names are the tenant's.
type assetGate struct {
	stubGate
	tenant shared.ID
	names  map[shared.ID][]string
	err    error
	asked  []shared.ID
}

func (g *assetGate) AssetTargets(_ context.Context, tenant shared.ID, ids []shared.ID) (map[shared.ID][]string, error) {
	g.asked = append(g.asked, ids...)
	if g.err != nil {
		return nil, g.err
	}
	out := map[shared.ID][]string{}
	if !tenant.Equals(g.tenant) {
		return out, nil
	}
	for _, id := range ids {
		if v, ok := g.names[id]; ok {
			out[id] = v
		}
	}
	return out, nil
}

func resultsByTarget(rs []DryRunResult) map[string]DryRunResult {
	m := map[string]DryRunResult{}
	for _, r := range rs {
		m[r.Target] = r
	}
	return m
}

// POST /scope/check with asset_ids (RFC-054 §6.4): an asset is checked by
// its name, through the same gate a scan of it goes through; an asset the
// caller may not see is answered by its id alone, identically whether it is
// outside the caller's data scope or not the organization's at all.
func TestDryRunTargets_AssetIDs(t *testing.T) {
	tenant := shared.NewID()
	mine, review, hidden, foreign, excluded := shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()
	gate := &assetGate{
		stubGate: stubGate{blocked: map[string]attribution.State{review.String(): attribution.StateNeedsReview}},
		tenant:   tenant,
		names: map[shared.ID][]string{
			mine:     {"app.example.com"},
			review:   {"review.example.com"},
			hidden:   {"secret.example.com"},
			excluded: {"api.example.com", "203.0.113.9"},
		},
	}
	act := &stubActScope{assets: map[shared.ID]bool{hidden: true}}
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{"203.0.113.9": true}},
		attributionGate: gate,
		actScope:        act,
		logger:          logger.NewNop(),
	}

	got, err := svc.DryRunTargets(context.Background(), DryRunInput{
		TenantID: tenant,
		Targets:  []string{"typed.example.com", "APP.example.com"},
		AssetIDs: []shared.ID{mine, review, hidden, foreign, excluded, mine},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 7 { // 2 typed + 5 distinct assets
		t.Fatalf("results = %+v", got)
	}
	by := resultsByTarget(got)

	if r := by["review.example.com"]; r.Allowed || r.Code != scopedom.RefusalNeedsReview || r.AssetID != review.String() {
		t.Fatalf("review asset = %+v, want needs_review checked by its id", r)
	}
	if r := by["api.example.com"]; r.Allowed || r.Code != scopedom.RefusalExcluded {
		t.Fatalf("asset excluded through its address = %+v, want excluded", r)
	}
	// The typed name and the asset share one answer.
	if r := by["APP.example.com"]; !r.Allowed {
		t.Fatalf("typed name of an allowed asset = %+v", r)
	}
	for _, r := range got {
		if r.AssetID == mine.String() && (!r.Allowed || r.Target != "app.example.com") {
			t.Fatalf("own asset = %+v", r)
		}
	}
	// Hidden (outside the data scope) and foreign (another tenant's) get the
	// same answer, by id, and the hidden asset's name never appears.
	h, f := by[hidden.String()], by[foreign.String()]
	for _, r := range []DryRunResult{h, f} {
		if r.Allowed || r.Code != scopedom.RefusalOutOfDataScope || r.Target != r.AssetID || r.ZoneID != "" {
			t.Fatalf("hidden/foreign asset = %+v, want out_of_data_scope by id", r)
		}
	}
	if h.Reason != f.Reason {
		t.Fatalf("hidden %q and foreign %q answers differ (existence oracle)", h.Reason, f.Reason)
	}
	for _, r := range got {
		if strings.Contains(r.Target, "secret") || strings.Contains(r.Reason, "secret") {
			t.Fatalf("the name of an asset outside the data scope leaked: %+v", r)
		}
	}
	// The act scope saw every asset; the hidden one was never looked up.
	if len(act.got) != 1 || len(act.got[0].AssetIDs) != 5 {
		t.Fatalf("act-scope input = %+v", act.got)
	}
	for _, id := range gate.asked {
		if id.Equals(hidden) {
			t.Fatal("an asset outside the data scope was looked up")
		}
	}

	// Another tenant asking for the same ids learns nothing.
	other, err := svc.DryRunTargets(context.Background(), DryRunInput{TenantID: shared.NewID(), AssetIDs: []shared.ID{mine}})
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 1 || other[0].Code != scopedom.RefusalOutOfDataScope || other[0].Target != mine.String() {
		t.Fatalf("cross-tenant asset = %+v, want out_of_data_scope by id", other)
	}
}

func TestDryRunTargets_AssetIDsFailClosed(t *testing.T) {
	tenant, id := shared.NewID(), shared.NewID()
	in := DryRunInput{TenantID: tenant, AssetIDs: []shared.ID{id}}

	// A gate that cannot name assets answers nothing.
	svc := &Service{scopeExclusions: &stubExclusions{}, attributionGate: &stubGate{}, logger: logger.NewNop()}
	if _, err := svc.DryRunTargets(context.Background(), in); !errors.Is(err, ErrAttributionGateUnavailable) {
		t.Fatalf("err = %v, want ErrAttributionGateUnavailable", err)
	}
	svc.attributionGate = &assetGate{tenant: tenant, err: errors.New("db down")}
	if _, err := svc.DryRunTargets(context.Background(), in); err == nil {
		t.Fatal("a failed asset lookup must fail the check")
	}
	svc.attributionGate = &assetGate{tenant: tenant}
	svc.actScope = &stubActScope{err: errors.New("db down")}
	if _, err := svc.DryRunTargets(context.Background(), in); err == nil {
		t.Fatal("a failed act-scope check must fail the check")
	}

	// 200 together at most.
	ids := make([]shared.ID, 150)
	for i := range ids {
		ids[i] = shared.NewID()
	}
	targets := make([]string, 51)
	for i := range targets {
		targets[i] = strings.Repeat("a", i+1) + ".example.com"
	}
	svc.actScope = &stubActScope{}
	if _, err := svc.DryRunTargets(context.Background(), DryRunInput{TenantID: tenant, Targets: targets, AssetIDs: ids}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("201 entries: err = %v, want ErrValidation", err)
	}
}
