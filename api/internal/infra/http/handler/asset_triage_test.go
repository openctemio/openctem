package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type triageFake struct {
	tenant   shared.ID
	recs     map[string]attribution.Record
	blocked  map[string]attribution.State
	excluded map[shared.ID]bool
	err      error
}

func (f *triageFake) Records(_ context.Context, t shared.ID, _ []string) (map[string]attribution.Record, error) {
	if !t.Equals(f.tenant) {
		return map[string]attribution.Record{}, nil
	}
	return f.recs, f.err
}

func (f *triageFake) ActiveCheckBlocked(_ context.Context, t shared.ID, ids []string) (map[string]attribution.State, error) {
	if f.err != nil {
		return nil, f.err
	}
	if !t.Equals(f.tenant) {
		out := map[string]attribution.State{}
		for _, id := range ids {
			out[id] = attribution.StateUnattributed
		}
		return out, nil
	}
	return f.blocked, nil
}

func (f *triageFake) ExcludedTargets(_ context.Context, t string, _ []scopeapp.ExclusionCandidate) (map[shared.ID]bool, error) {
	if t != f.tenant.String() {
		return map[shared.ID]bool{}, nil
	}
	return f.excluded, nil
}

// Triage fields come from the checks the dispatcher runs (the gate, then
// the exclusions), only when asked, and are left out (never shown as
// scannable) when a read fails.
func TestAssetTriageFields(t *testing.T) {
	tenant := shared.NewID()
	mk := func(name string) *asset.Asset {
		a, err := asset.NewAsset(name, asset.AssetTypeSubdomain, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	a, b, c := mk("a.example.com"), mk("b.example.com"), mk("c.example.com")
	assets := []*asset.Asset{a, b, c}
	f := &triageFake{tenant: tenant,
		recs:     map[string]attribution.Record{a.ID().String(): {State: "discovered", Confidence: 60}},
		blocked:  map[string]attribution.State{a.ID().String(): "discovered"},
		excluded: map[shared.ID]bool{c.ID(): true}}
	h := &AssetHandler{logger: logger.NewNop()}
	h.SetTriage(f, f, f)
	rows := func() []*AssetResponse {
		return []*AssetResponse{{ID: a.ID().String()}, {ID: b.ID().String()}, {ID: c.ID().String()}}
	}

	out := rows()
	h.addTriage(httptest.NewRequest("GET", "/api/v1/assets", nil), tenant.String(), out, assets)
	if out[0].Triage != nil {
		t.Fatal("triage without with_triage")
	}
	req := httptest.NewRequest("GET", "/api/v1/assets?with_triage=true", nil)
	h.addTriage(req, tenant.String(), out, assets)
	ta, tb, tc := out[0].Triage, out[1].Triage, out[2].Triage
	if ta == nil || ta.AttributionState != "discovered" || ta.Confidence != 60 || ta.ScanAllowed || ta.ScanRefusalCode != "no_entry" {
		t.Fatalf("a = %+v", ta)
	}
	if tb == nil || tb.AttributionState != "confirmed" || !tb.ScanAllowed {
		t.Fatalf("b = %+v", tb)
	}
	if tc == nil || tc.ScanAllowed || tc.ScanRefusalCode != "excluded" {
		t.Fatalf("an excluded asset reads as scannable: %+v", tc)
	}
	// Another tenant: the gate refuses, nothing of this tenant shows.
	out = rows()
	h.addTriage(req, shared.NewID().String(), out, assets)
	if out[0].Triage == nil || out[0].Triage.ScanAllowed || out[0].Triage.AttributionState != "confirmed" {
		t.Fatalf("cross-tenant = %+v", out[0].Triage)
	}
	// A failed read leaves the fields out.
	f.err = errors.New("db down")
	out = rows()
	h.addTriage(req, tenant.String(), out, assets)
	if out[0].Triage != nil {
		t.Fatal("triage shown after a failed read")
	}
}
