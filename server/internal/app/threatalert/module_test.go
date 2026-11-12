package threatalert

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type oneTenant struct{ t *tenant.Tenant }

func (o oneTenant) GetByID(context.Context, shared.ID) (*tenant.Tenant, error) { return o.t, nil }

type modulesOff map[string]bool

func (m modulesOff) IsEnabled(_ context.Context, _, moduleID string) bool { return !m[moduleID] }

// A tenant with the threat_intel module off has an inactive policy, and every
// step of the planner (baseline, plan, send, digest) returns early for an
// inactive policy. The same tenant with the module on is active.
func TestPolicy_InactiveWhenThreatIntelOff(t *testing.T) {
	tn, err := tenant.NewTenant("Acme", "acme", "u")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPlanner(nil, oneTenant{tn}, logger.NewNop())
	id := shared.NewID()

	p.SetModules(modulesOff{"threat_intel": true})
	if pol := p.policyOf(context.Background(), &runState{policies: map[shared.ID]*policy{}}, id); pol.active {
		t.Fatal("a tenant with threat_intel off must not get alerts")
	}
	p.SetModules(modulesOff{})
	if pol := p.policyOf(context.Background(), &runState{policies: map[shared.ID]*policy{}}, id); !pol.active {
		t.Fatal("a tenant with threat_intel on gets alerts")
	}
}
