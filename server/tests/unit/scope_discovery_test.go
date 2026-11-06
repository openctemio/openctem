package unit

// Discovery on a scope entry (research/53 SC1): turning it on widens what is
// discovered, so it needs an approver with step-up; turning it off narrows.
// A one-off entry never discovers.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestScopeDiscovery_Switch(t *testing.T) {
	svc, _, notes := entryService(t, 1, tenant.ScopeSettings{})
	tenantID := shared.NewID()
	off := false
	on := true
	e, err := create(svc, tenantID, approverA, "*.disc.example", func(in *scope.CreateTargetInput) { in.Discovery = &off })
	if err != nil || e.Discovery() {
		t.Fatalf("created with discovery off: %v %v", e, err)
	}
	update := func(actor scope.Actor, v *bool) error {
		_, err := svc.UpdateTarget(context.Background(), e.ID().String(), tenantID.String(), scope.UpdateTargetInput{Discovery: v, Actor: actor})
		return err
	}
	if err := update(member, &on); !errors.Is(err, scope.ErrWideningNeedsApprove) {
		t.Fatalf("a member turned discovery on: %v", err)
	}
	svc.SetStepUpGate(staleGate{})
	if err := update(approverA, &on); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("discovery on without step-up: %v", err)
	}
	svc.SetStepUpGate(passGate{})
	before := len(notes.titles)
	if err := update(approverA, &on); err != nil {
		t.Fatal(err)
	}
	got, _ := svc.GetTarget(context.Background(), tenantID.String(), e.ID().String())
	if !got.Discovery() || len(notes.titles) == before {
		t.Fatalf("discovery on: %v, notices %d", got.Discovery(), len(notes.titles)-before)
	}
	// Turning it off is a narrowing anyone with scope:write may make.
	if err := update(member, &off); err != nil {
		t.Fatalf("discovery off: %v", err)
	}

	// A one-off entry never discovers, whatever the switch says.
	one, err := create(svc, tenantID, approverA, "promo.disc.example", func(in *scope.CreateTargetInput) {
		in.ExpiresInDays, in.Reason, in.Discovery = days(3), "campaign", &on
	})
	if err != nil || one.Discovery() {
		t.Fatalf("one-off discovers: %v %v", one, err)
	}
	// An IP entry never discovers.
	ip, err := svc.CreateTarget(context.Background(), scope.CreateTargetInput{TenantID: tenantID.String(), TargetType: "ip_address",
		Pattern: "203.0.113.9", CreatedBy: approverA.UserID, Actor: approverA})
	if err != nil || ip.Discovery() {
		t.Fatalf("ip entry discovers: %v %v", ip, err)
	}
}
