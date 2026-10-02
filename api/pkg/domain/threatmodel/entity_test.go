package threatmodel

import (
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestNewThreatModel_Validation(t *testing.T) {
	tenant := shared.NewID()

	if _, err := NewThreatModel(tenant, "bogus_scope", nil, "x"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error for bad scope, got %v", err)
	}
	if _, err := NewThreatModel(tenant, ScopeTenant, nil, ""); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error for empty name, got %v", err)
	}
	m, err := NewThreatModel(tenant, ScopeCrownJewel, nil, "ok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.ID.IsZero() || !m.TenantID.Equals(tenant) || m.Name != "ok" {
		t.Errorf("constructor did not populate model: %+v", m)
	}
}

func TestNewThreatModelThreat_Validation(t *testing.T) {
	tenant, model := shared.NewID(), shared.NewID()
	if _, err := NewThreatModelThreat(tenant, model, "nonsense"); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("expected validation error for bad status, got %v", err)
	}
	th, err := NewThreatModelThreat(tenant, model, StatusOpen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if th.ID.IsZero() || th.Status != StatusOpen {
		t.Errorf("constructor did not populate threat: %+v", th)
	}
}

func TestRecomputeRollups(t *testing.T) {
	tenant := shared.NewID()
	m, _ := NewThreatModel(tenant, ScopeTenant, nil, "rollup")

	mk := func(s ThreatStatus) *ThreatModelThreat {
		th, _ := NewThreatModelThreat(tenant, m.ID, s)
		return th
	}
	threats := []*ThreatModelThreat{
		mk(StatusOpen), mk(StatusOpen),
		mk(StatusMitigated),
		mk(StatusCovered),
		mk(StatusAccepted),
		mk(StatusTheoretical),
		nil, // must be ignored
	}
	m.RecomputeRollups(threats)

	if m.ThreatsTotal != 6 {
		t.Errorf("total: want 6, got %d", m.ThreatsTotal)
	}
	if m.ThreatsOpen != 2 || m.ThreatsMitigated != 1 || m.ThreatsCovered != 1 {
		t.Errorf("counters wrong: open=%d mit=%d cov=%d", m.ThreatsOpen, m.ThreatsMitigated, m.ThreatsCovered)
	}
	// addressed = mitigated+covered+accepted = 3; denom = open+addressed = 5 → 60%.
	if m.CoveragePct != 60 {
		t.Errorf("coverage: want 60, got %.2f", m.CoveragePct)
	}

	// All theoretical → coverage 0, denom 0 guard.
	m.RecomputeRollups([]*ThreatModelThreat{mk(StatusTheoretical)})
	if m.CoveragePct != 0 || m.ThreatsTotal != 1 {
		t.Errorf("all-theoretical rollup wrong: cov=%.2f total=%d", m.CoveragePct, m.ThreatsTotal)
	}
}
