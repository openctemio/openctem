package handler

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type triageFake struct {
	tenant  shared.ID
	recs    map[string]attribution.Record
	blocked map[string]attribution.State
	err     error
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

// Triage fields come from the gate the dispatcher uses, only when asked,
// and are left out (never shown as scannable) when a read fails.
func TestAssetTriageFields(t *testing.T) {
	tenant := shared.NewID()
	f := &triageFake{tenant: tenant,
		recs:    map[string]attribution.Record{"a": {State: "discovered", Confidence: 60}},
		blocked: map[string]attribution.State{"a": "discovered"}}
	h := &AssetHandler{logger: logger.NewNop()}
	h.SetTriage(f, f)
	rows := func() []*AssetResponse { return []*AssetResponse{{ID: "a"}, {ID: "b"}} }

	out := rows()
	h.addTriage(httptest.NewRequest("GET", "/api/v1/assets", nil), tenant.String(), out)
	if out[0].Triage != nil {
		t.Fatal("triage without with_triage")
	}
	req := httptest.NewRequest("GET", "/api/v1/assets?with_triage=true", nil)
	h.addTriage(req, tenant.String(), out)
	a, b := out[0].Triage, out[1].Triage
	if a == nil || a.AttributionState != "discovered" || a.Confidence != 60 || a.ScanAllowed || a.ScanRefusalCode != "no_entry" {
		t.Fatalf("a = %+v", a)
	}
	if b == nil || b.AttributionState != "confirmed" || !b.ScanAllowed {
		t.Fatalf("b = %+v", b)
	}
	// Another tenant: the gate refuses, nothing of this tenant shows.
	out = rows()
	h.addTriage(req, shared.NewID().String(), out)
	if out[0].Triage == nil || out[0].Triage.ScanAllowed || out[0].Triage.AttributionState != "confirmed" {
		t.Fatalf("cross-tenant = %+v", out[0].Triage)
	}
	// A failed read leaves the fields out.
	f.err = errors.New("db down")
	out = rows()
	h.addTriage(req, tenant.String(), out)
	if out[0].Triage != nil {
		t.Fatal("triage shown after a failed read")
	}
}
