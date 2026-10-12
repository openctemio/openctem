package easm

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeReader struct {
	data      *SummaryData
	scopeUser *shared.DataScope
}

func (f *fakeReader) Summary(_ context.Context, _ shared.ID, scopeUserID *shared.DataScope, _ time.Time, _ int) (*SummaryData, error) {
	f.scopeUser = scopeUserID
	return f.data, nil
}

func TestSummary_Build(t *testing.T) {
	r := &fakeReader{data: &SummaryData{
		AssetsByType:       map[string]int{"domain": 2, "subdomain": 5},
		AttributionByState: map[string]int{"": 4, "confirmed": 1, "needs_review": 2},
		OpenBySeverity:     map[string]int{"high": 1, "info": 6},
		OpenByType:         map[string]int{"subdomain_discovered": 6, "certificate_expiring": 1},
		NewSince7d:         3, NewSince30d: 4, NewSinceCycle: 9,
	}}
	s, err := NewService(r, nil).Summary(context.Background(), shared.NewID())
	if err != nil {
		t.Fatal(err)
	}
	if r.scopeUser != nil {
		t.Fatal("no enforcer must mean unrestricted")
	}
	if s.Surface.Total != 7 || s.Attribution.Confirmed != 5 || s.Attribution.Legacy != 4 || s.Attribution.NeedsReview != 2 {
		t.Errorf("surface/attribution = %+v %+v", s.Surface, s.Attribution)
	}
	if s.Exposures.Open != 7 || s.Exposures.ByType[0].Type != "subdomain_discovered" {
		t.Errorf("exposures = %+v", s.Exposures)
	}
	// No CTEM cycle: since_cycle is absent, not a misleading 0 or 9.
	if s.New.SinceCycle != nil || s.New.CycleStart != nil {
		t.Errorf("since cycle without a cycle = %v", *s.New.SinceCycle)
	}
	if s.TopRisks == nil {
		t.Error("top_risks must be an empty list, not null")
	}

	start := time.Now().Add(-48 * time.Hour)
	r.data.CycleStart = &start
	s, _ = NewService(r, nil).Summary(context.Background(), shared.NewID())
	if s.New.SinceCycle == nil || *s.New.SinceCycle != 9 {
		t.Errorf("since cycle = %v", s.New.SinceCycle)
	}
}
