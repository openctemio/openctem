package scan

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A connector scan run records the gate its targets passed (full gate at t1,
// outside every zone) with the act scope of who triggered it, else the
// scan owner; the claim re-checks it with that record.
func TestConnectorDispatchGate(t *testing.T) {
	owner, caller := shared.NewID(), shared.NewID()
	sc := &scan.Scan{CreatedBy: &owner}
	want := command.DispatchGate{Tier: 1, Validated: true, NoZoneRouting: true, ActScope: true}

	want.Actor = caller.String()
	if g := connectorDispatchGate(sc, caller.String()); *g != want {
		t.Fatalf("manual run: %+v", g)
	}
	want.Actor = owner.String()
	if g := connectorDispatchGate(sc, "scheduler"); *g != want {
		t.Fatalf("scheduled run: %+v", g)
	}
	want.Actor = ""
	if g := connectorDispatchGate(&scan.Scan{}, ""); *g != want {
		t.Fatalf("system run: %+v", g)
	}
}
