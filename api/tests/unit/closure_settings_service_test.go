package unit

import (
	"context"
	"errors"
	"testing"
	"time"

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
	// The loosening waits 24 hours: off stays in force, auto is pending.
	if err != nil || cs.EffectiveMode() != tenant.ClosingModeOff || cs.PendingMode != tenant.ClosingModeAuto ||
		cs.PendingAt == nil || time.Until(*cs.PendingAt) < 23*time.Hour {
		t.Fatalf("loosen inside the window: %+v, %v", cs, err)
	}
	if got, _ := svc.GetClosureSettings(ctx, id); got.EffectiveMode() != tenant.ClosingModeOff || got.PendingMode != tenant.ClosingModeAuto {
		t.Fatalf("read after loosening: %+v", got)
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

	// The owner's loosening waits; until then review stays in force.
	if cs, _ := svc.GetClosureSettings(ctx, id); cs.CriticalAutoClose || cs.PendingCriticalAutoClose == nil || !*cs.PendingCriticalAutoClose {
		t.Fatalf("critical auto-close must wait 24 hours: %+v", cs)
	}
	// Keeping the policy in force (review, critical in review) is not a
	// loosening: any admin, no step-up, and it drops the waiting change.
	gate.err = middleware.ErrStepUpRequired
	cs, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeReview},
		auditsvc.AuditContext{ActorID: admin.String(), TenantID: id})
	if err != nil || cs.PendingAt != nil || cs.CriticalAutoClose {
		t.Fatalf("admin putting critical back in review: %+v, %v", cs, err)
	}
	if _, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: "sometimes"},
		auditsvc.AuditContext{ActorID: admin.String(), TenantID: id}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("bad mode: %v", err)
	}
}

// A waiting loosening is canceled by any tightening choice and by the
// cancel call (audited); a request cannot set the pending fields itself.
func TestClosureSettings_PendingLooseningCancel(t *testing.T) {
	ctx := context.Background()
	svc, tn, _, admin, gate, auditRepo := closureSettingsCase(t)
	id := tn.ID().String()
	actx := auditsvc.AuditContext{ActorID: admin.String(), TenantID: id}
	gate.err = nil

	// A forged pending value in the request is ignored (off is a tightening).
	soon := time.Now().Add(-time.Hour)
	forged := tenant.ClosureSettings{Mode: tenant.ClosingModeOff, PendingMode: tenant.ClosingModeAuto, PendingAt: &soon}
	cs, err := svc.UpdateClosureSettings(ctx, id, forged, actx)
	if err != nil || cs.PendingAt != nil || cs.EffectiveMode() != tenant.ClosingModeOff {
		t.Fatalf("forged pending: %+v, %v", cs, err)
	}

	if cs, err = svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeAuto}, actx); err != nil || cs.PendingAt == nil {
		t.Fatalf("loosen: %+v, %v", cs, err)
	}
	before := len(closureEntries(auditRepo))
	cs, err = svc.CancelPendingClosureSettings(ctx, id, actx)
	if err != nil || cs.PendingAt != nil || cs.EffectiveMode() != tenant.ClosingModeOff {
		t.Fatalf("cancel: %+v, %v", cs, err)
	}
	if len(closureEntries(auditRepo)) != before+1 {
		t.Fatal("cancel not audited")
	}
	// Nothing waits: cancel is a no-op, not audited.
	if _, err := svc.CancelPendingClosureSettings(ctx, id, actx); err != nil || len(closureEntries(auditRepo)) != before+1 {
		t.Fatalf("second cancel: %v", err)
	}

	// A tightening choice also drops the waiting loosening.
	if _, err := svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeReview}, actx); err != nil {
		t.Fatal(err)
	}
	if cs, err = svc.UpdateClosureSettings(ctx, id, tenant.ClosureSettings{Mode: tenant.ClosingModeOff}, actx); err != nil || cs.PendingAt != nil {
		t.Fatalf("tighten after loosen: %+v, %v", cs, err)
	}
}
