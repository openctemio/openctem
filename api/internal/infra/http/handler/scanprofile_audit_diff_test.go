package handler

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A quality-gate change, an update and a new default record what changed.
func TestScanProfileChangeEvent_CarriesBeforeAfter(t *testing.T) {
	before := &scanprofile.ScanProfile{ID: shared.NewID(), Name: "Gate", QualityGate: scanprofile.QualityGate{Enabled: true, FailOnCritical: true, MaxHigh: 5}}
	after := *before
	after.QualityGate.FailOnCritical = false
	after.QualityGate.MaxHigh = 50
	after.IsDefault = true

	ev := scanProfileChangeEvent(audit.ActionScanProfileQualityGateUpdated, before, &after, "changed")
	if ev.Changes == nil {
		t.Fatal("no changes recorded")
	}
	keys := map[string]bool{}
	for k := range ev.Changes.After {
		keys[k] = true
	}
	for _, want := range []string{"quality_gate.fail_on_critical", "quality_gate.max_high", "is_default"} {
		if !keys[want] {
			t.Errorf("diff misses %s: %+v", want, ev.Changes.After)
		}
	}
	if keys["name"] {
		t.Error("unchanged name is in the diff")
	}
	if got := scanProfileChangeEvent(audit.ActionScanProfileUpdated, nil, &after, "x"); got.Changes != nil {
		t.Error("no before must leave the diff out")
	}
}
