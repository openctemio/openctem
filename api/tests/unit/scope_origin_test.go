package unit

// The origin each creating path records (research/53 §4.6).

import (
	"context"
	"testing"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestScopeOrigin_SetByThePath(t *testing.T) {
	svc, _, _ := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	one := func(in *scope.CreateTargetInput) { in.ExpiresInDays, in.Reason = days(7), "campaign" }

	manual, err := create(svc, tenantID, approverA, "*.manual.example", nil)
	if err != nil || manual.Origin() != scopedom.OriginManual {
		t.Fatalf("approver: %v %v", manual, err)
	}
	req, err := create(svc, tenantID, member, "promo.example", one)
	if err != nil || req.Origin() != scopedom.OriginRequest {
		t.Fatalf("member request: %v %v", req, err)
	}
	fix, err := create(svc, tenantID, approverA, "fix.example", func(in *scope.CreateTargetInput) {
		in.Origin = scopedom.OriginRefusalFix
	})
	if err != nil || fix.Origin() != scopedom.OriginRefusalFix {
		t.Fatalf("refusal fix: %v %v", fix, err)
	}
	sys, err := create(svc, tenantID, scope.Actor{}, "sys.example", nil)
	if err != nil || sys.Origin() != scopedom.OriginSystem {
		t.Fatalf("system: %v %v", sys, err)
	}
	// An unknown origin is never recorded (manual).
	odd, err := create(svc, tenantID, approverA, "odd.example", func(in *scope.CreateTargetInput) { in.Origin = "hacker" })
	if err != nil || odd.Origin() != scopedom.OriginManual {
		t.Fatalf("unknown origin: %v %v", odd, err)
	}

	seeds, _, _, _, _ := seedService(t, 1, tenant.ScopeSettings{})
	seed, err := seeds.Create(context.Background(), tenantID, easmapp.CreateSeedInput{
		Kind: "root_domain", Value: "seeded-origin.com", Attested: true, Actor: approverA,
	})
	if err != nil || seed.Origin() != scopedom.OriginSeed {
		t.Fatalf("seed: %v %v", seed, err)
	}
}
