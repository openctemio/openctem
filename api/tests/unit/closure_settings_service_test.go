package unit

import (
	"context"
	"errors"
	"testing"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// closureSettingsCase is an organization (closing mode unset = review) with an owner
// and an admin, a step-up gate that refuses, and a recorded audit trail.
func closureSettingsCase(t *testing.T) (svc *tenantapp.TenantService, tn *tenant.Tenant, owner, admin shared.ID, gate *recordingGate, auditRepo *mockAuditRepo) {
	t.Helper()
	auditRepo = newMockAuditRepo()
	svc, repo := newTestTenantServiceWithOptions(tenantapp.WithTenantAuditService(auditsvc.NewAuditService(auditRepo, logger.NewNop())))
	tn = seedTenant(repo, "Closure", "closure-"+shared.NewID().String()[:8])
	owner, admin = shared.NewID(), shared.NewID()
	seedMembershipInRepo(repo, owner, tn.ID(), tenant.RoleOwner)
	seedMembershipInRepo(repo, admin, tn.ID(), tenant.RoleAdmin)
	gate = refusingGate()
	svc.SetStepUpGate(gate)
	return svc, tn, owner, admin, gate, auditRepo
}

// closureEntries returns the closing-mode audit entries (the mock stores them
// in a map: no order).
func closureEntries(r *mockAuditRepo) []*audit.AuditLog {
	var out []*audit.AuditLog
	for _, l := range r.logs {
		if l.Action() == audit.ActionTenantClosureUpdated {
			out = append(out, l)
		}
	}
	return out
}

func TestClosureSettings_LooseningNeedsStepUpAndIsAuditedHigh(t *testing.T) {
	ctx := context.Background()
	svc, tn, _, admin, gate, auditRepo := closureSettingsCase(t)
	id := tn.ID().String()
	actx := auditsvc.AuditContext{ActorID: admin.String(), TenantID: id}

	// review (unset) -> auto without a recent sign-in: refused, unchanged.
	_, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeAuto}, actx)
	wantStepUp(t, "review to auto", err)
	if cs, _ := svc.GetClosureSettings(ctx, id); cs.EffectiveMode() != tenant.ClosingModeReview {
		t.Fatalf("mode changed without step-up: %+v", cs)
	}
	if n := len(closureEntries(auditRepo)); n != 0 {
		t.Fatalf("a refused change was audited %d times", n)
	}

	// Tightening (review -> off) needs no step-up and is audited at medium.
	if _, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeOff}, actx); err != nil {
		t.Fatalf("tighten: %v", err)
	}
	if len(gate.actors) != 1 {
		t.Fatalf("tightening asked for step-up: %v", gate.actors)
	}
	got := closureEntries(auditRepo)
	if len(got) != 1 || got[0].Severity() != audit.SeverityMedium || got[0].Metadata()["mode_after"] != "off" {
		t.Fatalf("tighten audit: %+v", got)
	}

	// off -> review is loosening as well.
	_, err = svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeReview}, actx)
	wantStepUp(t, "off to review", err)

	// Inside the step-up window the admin may loosen to auto: audited high.
	gate.err = nil
	cs, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeAuto}, actx)
	if err != nil || cs.Mode != tenant.ClosingModeAuto {
		t.Fatalf("loosen inside the window: %+v, %v", cs, err)
	}
	got = closureEntries(auditRepo)
	high := 0
	for _, l := range got {
		if l.Severity() == audit.SeverityHigh && l.Metadata()["loosened"] == true && l.Metadata()["mode_after"] == "auto" {
			high++
		}
	}
	if len(got) != 2 || high != 1 {
		t.Fatalf("loosen audit: %d entries, %d high", len(got), high)
	}
}

func TestClosureSettings_CriticalAutoCloseIsOwnerOnly(t *testing.T) {
	ctx := context.Background()
	svc, tn, owner, admin, gate, auditRepo := closureSettingsCase(t)
	id := tn.ID().String()
	gate.err = nil // even with a fresh sign-in, an admin may not
	crit := tenant.ClosureSettings{Mode: tenant.ClosingModeAuto, CriticalAutoClose: true}

	_, err := svc.UpdateClosureSettings(ctx, id, crit, auditsvc.AuditContext{ActorID: admin.String(), TenantID: id})
	if !errors.Is(err, tenantapp.ErrCriticalAutoCloseOwnerOnly) || !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("admin turning critical auto-close on: err = %v, want owner-only forbidden", err)
	}
	if cs, _ := svc.GetClosureSettings(ctx, id); cs.CriticalAutoClose {
		t.Fatal("an admin turned critical auto-close on")
	}
	// No human actor (a system path) is refused too.
	if _, err := svc.UpdateClosureSettings(ctx, id, crit, auditsvc.AuditContext{TenantID: id}); !errors.Is(err, tenantapp.ErrCriticalAutoCloseOwnerOnly) {
		t.Fatalf("system actor: err = %v", err)
	}

	// The owner still needs a recent sign-in.
	gate.err = middleware.ErrStepUpRequired
	_, err = svc.UpdateClosureSettings(ctx, id, crit, auditsvc.AuditContext{ActorID: owner.String(), TenantID: id})
	wantStepUp(t, "owner critical auto-close", err)

	gate.err = nil
	if _, err := svc.UpdateClosureSettings(ctx, id, crit, auditsvc.AuditContext{ActorID: owner.String(), TenantID: id}); err != nil {
		t.Fatalf("owner inside the window: %v", err)
	}
	got := closureEntries(auditRepo)
	if len(got) != 1 || got[0].Severity() != audit.SeverityHigh || got[0].Metadata()["critical_auto_close_after"] != true {
		t.Fatalf("owner audit: %+v", got)
	}

	// Putting critical findings back in review is tightening: any admin,
	// no step-up.
	gate.err = middleware.ErrStepUpRequired
	if _, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeAuto},
		auditsvc.AuditContext{ActorID: admin.String(), TenantID: id}); err != nil {
		t.Fatalf("admin putting critical back in review: %v", err)
	}
	if _, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: "sometimes"},
		auditsvc.AuditContext{ActorID: admin.String(), TenantID: id}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad mode: %v", err)
	}
}
