package unit

import (
	"context"
	"errors"
	"testing"

	auditsvc "github.com/openctemio/openctem/server/internal/app/audit"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/pkg/domain/audit"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stepup"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// The organization's re-verification policy (docs/architecture/step-up-reauth.md):
// existing organizations keep what they had, new ones get the defaults,
// the critical floor cannot be lowered, and every change is audited.

func TestStepUpPolicy_ExistingAndNewOrganizations(t *testing.T) {
	_, repo := newTestTenantServiceWithOptions()
	existing := seedTenant(repo, "Old", "old-org")
	if got := existing.TypedSettings().Security.EffectiveStepUp(); got != stepup.LegacyPolicy() {
		t.Fatalf("an organization without a stored policy keeps the fixed 10-minute window: %+v", got)
	}
	fresh, err := tenant.NewTenant("New", "new-org", shared.NewID().String())
	if err != nil {
		t.Fatal(err)
	}
	if got := fresh.TypedSettings().Security.EffectiveStepUp(); got != stepup.DefaultPolicy() {
		t.Fatalf("a new organization gets the default policy: %+v", got)
	}
}

func TestStepUpPolicy_FloorCannotBeLowered(t *testing.T) {
	ctx := context.Background()
	svc, repo := newTestTenantServiceWithOptions()
	tn := seedTenant(repo, "Team", "team-floor")
	actx := auditsvc.AuditContext{ActorID: shared.NewID().String()}
	for _, critical := range []stepup.Rule{
		{Mode: stepup.ModeOff},
		{Mode: stepup.ModeWindow, Window: stepup.Window1h},
		{Mode: stepup.ModeWindow, Window: stepup.WindowSession},
	} {
		p := stepup.DefaultPolicy()
		p.Critical = critical
		_, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{StepUp: &p}, actx)
		if !errors.Is(err, stepup.ErrBelowFloor) {
			t.Fatalf("critical %+v: got %v, want ErrBelowFloor", critical, err)
		}
	}
	if got := repo.tenants[tn.ID().String()].TypedSettings().Security.EffectiveStepUp(); got != stepup.LegacyPolicy() {
		t.Fatalf("a refused change must store nothing: %+v", got)
	}
}

func TestStepUpPolicy_ChangeIsSavedAndAudited(t *testing.T) {
	ctx := context.Background()
	auditRepo := newMockAuditRepo()
	svc, repo := newTestTenantServiceWithOptions(tenantapp.WithTenantAuditService(auditsvc.NewAuditService(auditRepo, logger.NewNop())))
	tn := seedTenant(repo, "Team", "team-audit")
	other := seedTenant(repo, "Other", "team-other")
	actx := auditsvc.AuditContext{ActorID: shared.NewID().String()}

	loose := stepup.Policy{
		Critical:  stepup.Rule{Mode: stepup.ModeEveryTime},
		Sensitive: stepup.Rule{Mode: stepup.ModeOff},
		Routine:   stepup.Rule{Mode: stepup.ModeOff},
	}
	if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{StepUp: &loose}, actx); err != nil {
		t.Fatal(err)
	}
	if got := repo.tenants[tn.ID().String()].TypedSettings().Security.EffectiveStepUp(); got != loose {
		t.Fatalf("saved %+v", got)
	}
	// Tenant isolation: another organization's policy is untouched.
	if got := repo.tenants[other.ID().String()].TypedSettings().Security.EffectiveStepUp(); got != stepup.LegacyPolicy() {
		t.Fatalf("another organization changed: %+v", got)
	}
	var changed []*audit.AuditLog
	for _, l := range auditRepo.logs {
		if l.Action() == audit.ActionTenantStepUpPolicyChanged {
			changed = append(changed, l)
		}
	}
	if len(changed) != 1 || changed[0].Severity() != audit.SeverityHigh {
		t.Fatalf("want one high audit entry for a looser policy, got %d", len(changed))
	}
	if changed[0].Metadata()["before"] == nil || changed[0].Metadata()["after"] == nil {
		t.Fatalf("the entry names the rules before and after: %+v", changed[0].Metadata())
	}

	// Saving the same policy again records nothing new.
	if _, err := svc.UpdateSecuritySettings(ctx, tn.ID().String(), tenantapp.UpdateSecuritySettingsInput{StepUp: &loose}, actx); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, l := range auditRepo.logs {
		if l.Action() == audit.ActionTenantStepUpPolicyChanged {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("an unchanged policy must not be audited again, got %d entries", n)
	}
}
