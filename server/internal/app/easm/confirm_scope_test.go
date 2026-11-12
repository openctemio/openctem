package easm

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeConfirmTargets struct {
	mode  scangov.Mode
	calls []scope.BulkTargetsInput
	err   error
	// outcome per pattern: nil = created active
	itemErr map[string]error
}

func (f *fakeConfirmTargets) ApprovalPolicy(context.Context, string) (scangov.Mode, string) {
	return f.mode, scangov.SourceOrganization
}

func (f *fakeConfirmTargets) CreateTargets(_ context.Context, in scope.BulkTargetsInput) ([]scope.BulkTargetOutcome, error) {
	f.calls = append(f.calls, in)
	if f.err != nil {
		return nil, f.err
	}
	tid, _ := shared.IDFromString(in.TenantID)
	out := make([]scope.BulkTargetOutcome, 0, len(in.Items))
	for _, it := range in.Items {
		o := scope.BulkTargetOutcome{Item: it}
		if e, ok := f.itemErr[it.Pattern]; ok {
			o.Err = e
		} else {
			t, err := scopedom.NewTarget(tid, scopedom.TargetType(it.TargetType), it.Pattern, "", in.CreatedBy)
			o.Target, o.Err = t, err
		}
		out = append(out, o)
	}
	return out, nil
}

type fakeConfirmSettings struct {
	st  *tenant.ScopeSettings
	err error
}

func (f fakeConfirmSettings) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	return f.st, f.err
}

// confirmAssets is one tenant's assets by id.
type confirmAssets struct {
	tenant shared.ID
	byID   map[string]*asset.Asset
}

func (c *confirmAssets) GetByIDs(_ context.Context, t shared.ID, ids []shared.ID) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	if !t.Equals(c.tenant) {
		return out, nil
	}
	for _, id := range ids {
		if a, ok := c.byID[id.String()]; ok {
			out[id.String()] = a
		}
	}
	return out, nil
}

func (c *confirmAssets) GetByNames(context.Context, shared.ID, []string) (map[string]*asset.Asset, error) {
	return map[string]*asset.Asset{}, nil
}

func (c *confirmAssets) add(t *testing.T, name string, typ asset.AssetType) string {
	t.Helper()
	a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	c.byID[a.ID().String()] = a
	return a.ID().String()
}

func writer() ScopeActor {
	return ScopeActor{Actor: scope.Actor{UserID: shared.NewID().String()}, CanWriteScope: true}
}

func TestConfirmScope_AddsExactEntries(t *testing.T) {
	tenantID := shared.NewID()
	assets := &confirmAssets{tenant: tenantID, byID: map[string]*asset.Asset{}}
	name := assets.add(t, "App.Mine.example.", asset.AssetTypeSubdomain)
	apex := assets.add(t, "mine.example", asset.AssetTypeDomain)
	ip := assets.add(t, "203.0.113.10", asset.AssetTypeIPAddress)
	svc := assets.add(t, "203.0.113.10:443", asset.AssetTypeService)
	private := assets.add(t, "10.0.0.8", asset.AssetTypeIPAddress)
	covered := assets.add(t, "a.ours.example", asset.AssetTypeSubdomain)
	refused := assets.add(t, "deny.example", asset.AssetTypeDomain)
	dup := assets.add(t, "old.example", asset.AssetTypeDomain)
	existing := shared.NewID()
	targets := &fakeConfirmTargets{mode: scangov.ModeOff, itemErr: map[string]error{
		"deny.example": shared.NewDomainError("DENY_LIST", "denied", shared.ErrValidation),
		"old.example":  scopedom.NewTargetDuplicate(scopedom.Existing{ID: existing, Status: scopedom.StatusActive}),
	}}
	c := NewConfirmScope(targets, fakeConfirmSettings{st: &tenant.ScopeSettings{}}, assets, fakeCover{})
	actor := writer()
	res, err := c.Add(context.Background(), tenantID, []string{name, apex, ip, svc, private, covered, refused, dup, shared.NewID().String()}, actor, ConfirmReason)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets.calls) != 1 {
		t.Fatalf("CreateTargets calls = %d, want one batch", len(targets.calls))
	}
	in := targets.calls[0]
	if in.Origin != scopedom.OriginConfirmed || in.CreatedBy != actor.UserID || in.Actor.UserID != actor.UserID || in.Reason == "" {
		t.Fatalf("batch input %+v", in)
	}
	want := map[string]string{"app.mine.example": "domain", "mine.example": "domain", "203.0.113.10": "ip_address",
		"deny.example": "domain", "old.example": "domain"}
	if len(in.Items) != len(want) {
		t.Fatalf("items %+v", in.Items)
	}
	for _, it := range in.Items {
		if want[it.Pattern] != it.TargetType {
			t.Fatalf("unexpected item %+v (never wider than the name, never a service or private address)", it)
		}
	}
	got := map[string]ConfirmedEntry{}
	for _, e := range res.Entries {
		got[e.AssetID] = e
	}
	if got[name].Outcome != EntryAdded || got[name].TargetID == "" || got[ip].Outcome != EntryAdded {
		t.Fatalf("added: %+v %+v", got[name], got[ip])
	}
	if got[covered].Outcome != EntryCovered {
		t.Fatalf("covered: %+v", got[covered])
	}
	if got[refused].Outcome != EntryRefused || got[refused].Code != "DENY_LIST" {
		t.Fatalf("refused: %+v", got[refused])
	}
	if got[dup].Outcome != EntryExists || got[dup].TargetID != existing.String() {
		t.Fatalf("exists: %+v", got[dup])
	}
	for _, id := range []string{svc, private} {
		if _, ok := got[id]; ok {
			t.Fatalf("%s got an entry", id)
		}
	}

	// Another tenant asking with these ids adds nothing.
	targets.calls = nil
	res, err = c.Add(context.Background(), shared.NewID(), []string{name, ip}, actor, ConfirmReason)
	if err != nil || len(res.Entries) != 0 || len(targets.calls) != 0 {
		t.Fatalf("another tenant: %+v %v calls=%d", res, err, len(targets.calls))
	}
}

func TestConfirmScope_Skipped(t *testing.T) {
	tenantID := shared.NewID()
	assets := &confirmAssets{tenant: tenantID, byID: map[string]*asset.Asset{}}
	id := assets.add(t, "x.example", asset.AssetTypeDomain)
	cases := []struct {
		name     string
		mode     scangov.Mode
		settings fakeConfirmSettings
		actor    ScopeActor
		want     string
	}{
		{"strict", scangov.ModeStrict, fakeConfirmSettings{st: &tenant.ScopeSettings{}}, writer(), ConfirmSkippedStrict},
		{"unknown mode is off", "", fakeConfirmSettings{st: &tenant.ScopeSettings{}}, writer(), ""},
		{"setting off", scangov.ModeOn, fakeConfirmSettings{st: &tenant.ScopeSettings{ConfirmAddsToScopeDisabled: true}}, writer(), ConfirmSkippedDisabled},
		{"settings unreadable", scangov.ModeOff, fakeConfirmSettings{err: errors.New("db down")}, writer(), ConfirmSkippedDisabled},
		{"no scope write", scangov.ModeOff, fakeConfirmSettings{st: &tenant.ScopeSettings{}},
			ScopeActor{Actor: scope.Actor{UserID: shared.NewID().String()}}, ConfirmSkippedNoPermission},
		{"system caller", scangov.ModeOff, fakeConfirmSettings{st: &tenant.ScopeSettings{}}, ScopeActor{CanWriteScope: true}, ConfirmSkippedNoPermission},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			targets := &fakeConfirmTargets{mode: tc.mode}
			res, err := NewConfirmScope(targets, tc.settings, assets, fakeCover{}).Add(context.Background(), tenantID, []string{id}, tc.actor, ConfirmReason)
			if err != nil {
				t.Fatal(err)
			}
			if res.Skipped != tc.want {
				t.Fatalf("skipped = %q, want %q", res.Skipped, tc.want)
			}
			if tc.want != "" && len(targets.calls) != 0 {
				t.Fatal("entries were requested although skipped")
			}
		})
	}
	// Unwired: nothing added.
	if res, _ := (*ConfirmScope)(nil).Add(context.Background(), tenantID, []string{id}, writer(), ""); res.Skipped != ConfirmSkippedDisabled {
		t.Fatalf("nil: %+v", res)
	}
}

// A missing re-authentication refuses the whole decision: no entry and no
// decision is saved.
func TestDecideAs_StepUpSavesNothing(t *testing.T) {
	tenantID := shared.NewID()
	assets := &confirmAssets{tenant: tenantID, byID: map[string]*asset.Asset{}}
	id := assets.add(t, "y.example", asset.AssetTypeDomain)
	stepUp := errors.New("step-up required")
	store := &fakeReviewStore{prev: map[string]attribution.State{id: attribution.StateNeedsReview}}
	svc := NewReviewService(store, nil)
	svc.SetConfirmScope(NewConfirmScope(&fakeConfirmTargets{mode: scangov.ModeOff, err: stepUp},
		fakeConfirmSettings{st: &tenant.ScopeSettings{}}, assets, fakeCover{}))
	if _, err := svc.DecideAs(context.Background(), tenantID, []string{id}, attribution.StateConfirmed, writer()); !errors.Is(err, stepUp) {
		t.Fatalf("err = %v, want the step-up error", err)
	}
	if len(store.saved) != 0 {
		t.Fatalf("decisions saved before step-up: %v", store.saved)
	}
	// Any other decision never touches scope.
	res, err := svc.DecideAs(context.Background(), tenantID, []string{id}, attribution.StateRejected, writer())
	if err != nil || res.Scope != nil || len(store.saved) != 1 {
		t.Fatalf("reject: %+v %v %v", res, err, store.saved)
	}
	// Decide (automation, rules that reject) never adds an entry.
	res, err = svc.Decide(context.Background(), tenantID, []string{id}, attribution.StateConfirmed, shared.NewID().String())
	if err != nil || res.Scope != nil {
		t.Fatalf("Decide added scope: %+v %v", res, err)
	}
}
